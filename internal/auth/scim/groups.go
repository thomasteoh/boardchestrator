package scim

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// /Groups (RFC 7644 §3). A group's display name is its group value for the
// org's group -> role mappings (SPEC §7.5).

const maxGroupMembers = 10000

// member is one group member: the SCIM user id and its userName.
type member struct {
	ScimID, UserName string
}

func (h *Handler) groupResource(g sqlc.ScimGroup, members []member) map[string]any {
	ms := make([]any, 0, len(members))
	for _, m := range members {
		ms = append(ms, map[string]any{"value": m.ScimID, "display": m.UserName, "$ref": h.base + "/Users/" + m.ScimID})
	}
	res := map[string]any{
		"schemas":     []any{SchemaGroup},
		"id":          g.ID,
		"displayName": g.DisplayName,
		"members":     ms,
		"meta":        meta("Group", g.CreatedAt, g.UpdatedAt, h.base+"/Groups/"+g.ID),
	}
	if g.ExternalID != "" {
		res["externalId"] = g.ExternalID
	}
	return res
}

// orgMembers returns every group's members in the org.
func orgMembers(ctx context.Context, q *sqlc.Queries, org string) (map[string][]member, error) {
	rows, err := q.ListSCIMGroupMembers(ctx, org)
	if err != nil {
		return nil, fmt.Errorf("scim: group members: %w", err)
	}
	out := map[string][]member{}
	for _, r := range rows {
		out[r.GroupID] = append(out[r.GroupID], member{ScimID: r.ScimUserID, UserName: r.UserName})
	}
	return out, nil
}

func (h *Handler) listGroups(w http.ResponseWriter, r *http.Request) {
	c := callerFrom(r.Context())
	p, err := parseList(r)
	if err != nil {
		fail(w, r, err)
		return
	}
	q := sqlc.New(h.db)
	rows, err := q.ListSCIMGroups(r.Context(), c.OrgID)
	if err == nil {
		var members map[string][]member
		if members, err = orgMembers(r.Context(), q, c.OrgID); err == nil {
			all := make([]map[string]any, 0, len(rows))
			for _, g := range rows {
				all = append(all, h.groupResource(g, members[g.ID]))
			}
			page(w, p, all)
			return
		}
	}
	fail(w, r, err)
}

func loadGroup(ctx context.Context, q *sqlc.Queries, org, id string) (sqlc.ScimGroup, error) {
	g, err := q.GetSCIMGroup(ctx, sqlc.GetSCIMGroupParams{ID: id, OrgID: org})
	if errors.Is(err, sql.ErrNoRows) {
		return g, notFound(id)
	}
	if err != nil {
		return g, fmt.Errorf("scim: get group: %w", err)
	}
	return g, nil
}

// groupView reads a group with its members.
func (h *Handler) groupView(ctx context.Context, q *sqlc.Queries, org, id string) (map[string]any, error) {
	g, err := loadGroup(ctx, q, org, id)
	if err != nil {
		return nil, err
	}
	members, err := orgMembers(ctx, q, org)
	if err != nil {
		return nil, err
	}
	return h.groupResource(g, members[g.ID]), nil
}

func (h *Handler) getGroup(w http.ResponseWriter, r *http.Request) {
	c := callerFrom(r.Context())
	res, err := h.groupView(r.Context(), sqlc.New(h.db), c.OrgID, r.PathValue("id"))
	if err != nil {
		fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, projectOne(r, res))
}

// groupState is a group being changed: members keyed by platform user id.
type groupState struct {
	DisplayName string
	ExternalID  string
	Members     map[string]bool
}

// resolveMembers maps SCIM member values (SCIM user ids) to platform user
// ids in this org. Unknown ids are invalidValue, except when lenient
// (removal: a member that no longer exists is already gone).
func (o *op) resolveMembers(ctx context.Context, v any, lenient bool) ([]string, error) {
	var list []any
	switch x := v.(type) {
	case nil:
		return nil, nil
	case []any:
		list = x
	case map[string]any:
		list = []any{x}
	default:
		return nil, badRequest("invalidValue", "members must be a list.")
	}
	out := make([]string, 0, len(list))
	for _, e := range list {
		m, ok := e.(map[string]any)
		if !ok {
			return nil, badRequest("invalidValue", "Each member must be an object with a value.")
		}
		val, _ := getKey(m, "value")
		id, _ := val.(string)
		id = strings.TrimSpace(id)
		if id == "" {
			return nil, badRequest("invalidValue", "Each member needs a value (the user id).")
		}
		su, err := o.q.GetSCIMUser(ctx, sqlc.GetSCIMUserParams{ID: id, OrgID: o.c.OrgID})
		if errors.Is(err, sql.ErrNoRows) {
			if lenient {
				continue
			}
			return nil, badRequest("invalidValue", "Member %s is not a user in this organisation.", id)
		}
		if err != nil {
			return nil, fmt.Errorf("scim: member lookup: %w", err)
		}
		out = append(out, su.UserID)
	}
	return out, nil
}

func (o *op) setMembers(ctx context.Context, st *groupState, v any, replace bool) error {
	ids, err := o.resolveMembers(ctx, v, false)
	if err != nil {
		return err
	}
	if replace {
		st.Members = map[string]bool{}
	}
	for _, id := range ids {
		st.Members[id] = true
	}
	return nil
}

// readGroup reads displayName, externalId and members from a full Group
// resource (POST, PUT).
func (o *op) readGroup(ctx context.Context, body map[string]any) (groupState, error) {
	st := groupState{Members: map[string]bool{}}
	var err error
	v, _ := getKey(body, "displayName")
	if st.DisplayName, err = str(v, "displayName"); err != nil {
		return st, err
	}
	v, _ = getKey(body, "externalId")
	if st.ExternalID, err = str(v, "externalId"); err != nil {
		return st, err
	}
	v, _ = getKey(body, "members")
	return st, o.setMembers(ctx, &st, v, true)
}

// applyGroupPatch applies one PATCH operation to st.
func (o *op) applyGroupPatch(ctx context.Context, st *groupState, p patchOp) error {
	if p.Path == "" {
		m, ok := p.Value.(map[string]any)
		if !ok {
			return badRequest("invalidValue", "A PATCH without a path needs an object value.")
		}
		for k, v := range m {
			if err := o.applyGroupPath(ctx, st, p.Op, k, v); err != nil {
				return err
			}
		}
		return nil
	}
	return o.applyGroupPath(ctx, st, p.Op, p.Path, p.Value)
}

func (o *op) applyGroupPath(ctx context.Context, st *groupState, opName, path string, v any) error {
	if isExtensionPath(path) {
		return nil
	}
	c, err := ParsePath(path)
	if err != nil {
		return &apiError{Status: http.StatusBadRequest, SCIMType: "invalidPath", Detail: "The path is not valid."}
	}
	key := strings.Join(c.Path, ".")
	remove := opName == "remove"
	switch {
	case key == "members" && c.Sub != nil:
		// members[value eq "id"]: remove the matching members.
		if !remove {
			return nil
		}
		for uid := range st.Members {
			su, err := o.q.GetSCIMUserByUser(ctx, sqlc.GetSCIMUserByUserParams{OrgID: o.c.OrgID, UserID: uid})
			if err != nil {
				return fmt.Errorf("scim: member lookup: %w", err)
			}
			if c.Sub.Match(map[string]any{"value": su.ID, "display": su.UserName}) {
				delete(st.Members, uid)
			}
		}
		return nil
	case key == "members":
		switch {
		case remove && v == nil:
			st.Members = map[string]bool{}
		case remove:
			ids, err := o.resolveMembers(ctx, v, true)
			if err != nil {
				return err
			}
			for _, id := range ids {
				delete(st.Members, id)
			}
		default:
			return o.setMembers(ctx, st, v, opName == "replace")
		}
		return nil
	case key == "displayname":
		if remove {
			return badRequest("mutability", "displayName can't be removed.")
		}
		s, err := str(v, "displayName")
		if err != nil {
			return err
		}
		st.DisplayName = s
	case key == "externalid":
		if remove {
			st.ExternalID = ""
			return nil
		}
		s, err := str(v, "externalId")
		if err != nil {
			return err
		}
		st.ExternalID = s
	}
	return nil
}

// saveGroup writes st over group g (created when g.ID is "") and
// reconciles every user whose group values changed.
func (o *op) saveGroup(ctx context.Context, g sqlc.ScimGroup, st groupState) (string, error) {
	if st.DisplayName == "" {
		return "", badRequest("invalidValue", "displayName is required.")
	}
	if len(st.Members) > maxGroupMembers {
		return "", badRequest("invalidValue", "A group can have up to %d members.", maxGroupMembers)
	}
	org := o.c.OrgID
	created := g.ID == ""
	before := map[string]bool{}
	if created {
		g = sqlc.ScimGroup{ID: newID(), OrgID: org}
		if err := o.q.CreateSCIMGroup(ctx, sqlc.CreateSCIMGroupParams{
			ID: g.ID, OrgID: org, ExternalID: st.ExternalID, DisplayName: st.DisplayName, CreatedAt: o.now, UpdatedAt: o.now,
		}); err != nil {
			return "", fmt.Errorf("scim: create group: %w", err)
		}
	} else {
		ids, err := o.q.ListSCIMGroupMemberUsers(ctx, sqlc.ListSCIMGroupMemberUsersParams{GroupID: g.ID, OrgID: org})
		if err != nil {
			return "", fmt.Errorf("scim: group members: %w", err)
		}
		for _, id := range ids {
			before[id] = true
		}
		if err := o.q.UpdateSCIMGroup(ctx, sqlc.UpdateSCIMGroupParams{
			ExternalID: st.ExternalID, DisplayName: st.DisplayName, UpdatedAt: o.now, ID: g.ID, OrgID: org,
		}); err != nil {
			return "", fmt.Errorf("scim: update group: %w", err)
		}
	}
	renamed := !created && g.DisplayName != st.DisplayName
	affected := map[string]bool{}
	var added, removed int
	for id := range st.Members {
		if before[id] {
			if renamed {
				affected[id] = true
			}
			continue
		}
		if err := o.q.AddSCIMGroupMember(ctx, sqlc.AddSCIMGroupMemberParams{GroupID: g.ID, UserID: id, OrgID: org}); err != nil {
			return "", fmt.Errorf("scim: add member: %w", err)
		}
		affected[id], added = true, added+1
	}
	for id := range before {
		if st.Members[id] {
			continue
		}
		if _, err := o.q.RemoveSCIMGroupMember(ctx, sqlc.RemoveSCIMGroupMemberParams{GroupID: g.ID, UserID: id, OrgID: org}); err != nil {
			return "", fmt.Errorf("scim: remove member: %w", err)
		}
		affected[id], removed = true, removed+1
	}
	act := "scim.group.updated"
	if created {
		act = "scim.group.created"
	}
	if created || renamed || added+removed > 0 || g.ExternalID != st.ExternalID {
		if err := o.audit(ctx, act, g.ID, map[string]any{
			"group_id": g.ID, "members_added": added, "members_removed": removed, "renamed": renamed,
		}); err != nil {
			return "", err
		}
	}
	return g.ID, o.syncUsers(ctx, affected)
}

func (h *Handler) createGroup(w http.ResponseWriter, r *http.Request) {
	c := callerFrom(r.Context())
	body, err := readBody(r)
	if err != nil {
		fail(w, r, err)
		return
	}
	var res map[string]any
	var o *op
	err = h.tx(r.Context(), func(q *sqlc.Queries) error {
		o = h.newOp(q, c)
		st, err := o.readGroup(r.Context(), body)
		if err != nil {
			return err
		}
		id, err := o.saveGroup(r.Context(), sqlc.ScimGroup{}, st)
		if err != nil {
			return err
		}
		res, err = h.groupView(r.Context(), q, c.OrgID, id)
		return err
	})
	if err != nil {
		fail(w, r, err)
		return
	}
	h.emit(r.Context(), o)
	w.Header().Set("Location", res["meta"].(map[string]any)["location"].(string))
	writeJSON(w, http.StatusCreated, res)
}

// mutateGroup loads the group's state, lets change modify it and saves it.
func (h *Handler) mutateGroup(w http.ResponseWriter, r *http.Request, change func(ctx context.Context, o *op, st *groupState, body map[string]any) error) {
	c := callerFrom(r.Context())
	body, err := readBody(r)
	if err != nil {
		fail(w, r, err)
		return
	}
	var res map[string]any
	var o *op
	err = h.tx(r.Context(), func(q *sqlc.Queries) error {
		ctx := r.Context()
		g, err := loadGroup(ctx, q, c.OrgID, r.PathValue("id"))
		if err != nil {
			return err
		}
		o = h.newOp(q, c)
		ids, err := q.ListSCIMGroupMemberUsers(ctx, sqlc.ListSCIMGroupMemberUsersParams{GroupID: g.ID, OrgID: c.OrgID})
		if err != nil {
			return fmt.Errorf("scim: group members: %w", err)
		}
		st := groupState{DisplayName: g.DisplayName, ExternalID: g.ExternalID, Members: map[string]bool{}}
		for _, id := range ids {
			st.Members[id] = true
		}
		if err := change(ctx, o, &st, body); err != nil {
			return err
		}
		if _, err := o.saveGroup(ctx, g, st); err != nil {
			return err
		}
		res, err = h.groupView(ctx, q, c.OrgID, g.ID)
		return err
	})
	if err != nil {
		fail(w, r, err)
		return
	}
	h.emit(r.Context(), o)
	writeJSON(w, http.StatusOK, projectOne(r, res))
}

func (h *Handler) putGroup(w http.ResponseWriter, r *http.Request) {
	h.mutateGroup(w, r, func(ctx context.Context, o *op, st *groupState, body map[string]any) error {
		next, err := o.readGroup(ctx, body)
		if err != nil {
			return err
		}
		*st = next
		return nil
	})
}

func (h *Handler) patchGroup(w http.ResponseWriter, r *http.Request) {
	h.mutateGroup(w, r, func(ctx context.Context, o *op, st *groupState, body map[string]any) error {
		ops, err := patchOps(body)
		if err != nil {
			return err
		}
		for _, p := range ops {
			if err := o.applyGroupPatch(ctx, st, p); err != nil {
				return err
			}
		}
		return nil
	})
}

func (h *Handler) deleteGroup(w http.ResponseWriter, r *http.Request) {
	c := callerFrom(r.Context())
	var o *op
	err := h.tx(r.Context(), func(q *sqlc.Queries) error {
		ctx := r.Context()
		g, err := loadGroup(ctx, q, c.OrgID, r.PathValue("id"))
		if err != nil {
			return err
		}
		o = h.newOp(q, c)
		ids, err := q.ListSCIMGroupMemberUsers(ctx, sqlc.ListSCIMGroupMemberUsersParams{GroupID: g.ID, OrgID: c.OrgID})
		if err != nil {
			return fmt.Errorf("scim: group members: %w", err)
		}
		if err := q.ClearSCIMGroupMembers(ctx, sqlc.ClearSCIMGroupMembersParams{GroupID: g.ID, OrgID: c.OrgID}); err != nil {
			return fmt.Errorf("scim: clear group: %w", err)
		}
		if _, err := q.DeleteSCIMGroup(ctx, sqlc.DeleteSCIMGroupParams{ID: g.ID, OrgID: c.OrgID}); err != nil {
			return fmt.Errorf("scim: delete group: %w", err)
		}
		if err := o.audit(ctx, "scim.group.deleted", g.ID, map[string]any{"group_id": g.ID, "members": len(ids)}); err != nil {
			return err
		}
		affected := map[string]bool{}
		for _, id := range ids {
			affected[id] = true
		}
		return o.syncUsers(ctx, affected)
	})
	if err != nil {
		fail(w, r, err)
		return
	}
	h.emit(r.Context(), o)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}
