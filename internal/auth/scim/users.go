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

// /Users (RFC 7644 §3).

func (h *Handler) userResource(u sqlc.ScimUser) map[string]any {
	res := map[string]any{
		"schemas":  []any{SchemaUser},
		"id":       u.ID,
		"userName": u.UserName,
		"active":   u.Active == 1,
		"meta":     meta("User", u.CreatedAt, u.UpdatedAt, h.base+"/Users/"+u.ID),
	}
	if u.ExternalID != "" {
		res["externalId"] = u.ExternalID
	}
	if u.DisplayName != "" {
		res["displayName"] = u.DisplayName
	}
	if u.GivenName != "" || u.FamilyName != "" {
		name := map[string]any{"formatted": strings.TrimSpace(u.GivenName + " " + u.FamilyName)}
		if u.GivenName != "" {
			name["givenName"] = u.GivenName
		}
		if u.FamilyName != "" {
			name["familyName"] = u.FamilyName
		}
		res["name"] = name
	}
	if u.Email != "" {
		res["emails"] = []any{map[string]any{"value": u.Email, "type": "work", "primary": true}}
	}
	return res
}

func (h *Handler) listUsers(w http.ResponseWriter, r *http.Request) {
	c := callerFrom(r.Context())
	p, err := parseList(r)
	if err != nil {
		fail(w, r, err)
		return
	}
	rows, err := sqlc.New(h.db).ListSCIMUsers(r.Context(), c.OrgID)
	if err != nil {
		fail(w, r, err)
		return
	}
	all := make([]map[string]any, 0, len(rows))
	for _, u := range rows {
		all = append(all, h.userResource(u))
	}
	page(w, p, all)
}

// loadUser reads the org's SCIM user id (404 otherwise).
func loadUser(ctx context.Context, q *sqlc.Queries, org, id string) (sqlc.ScimUser, error) {
	u, err := q.GetSCIMUser(ctx, sqlc.GetSCIMUserParams{ID: id, OrgID: org})
	if errors.Is(err, sql.ErrNoRows) {
		return u, notFound(id)
	}
	if err != nil {
		return u, fmt.Errorf("scim: get user: %w", err)
	}
	return u, nil
}

func (h *Handler) getUser(w http.ResponseWriter, r *http.Request) {
	c := callerFrom(r.Context())
	u, err := loadUser(r.Context(), sqlc.New(h.db), c.OrgID, r.PathValue("id"))
	if err != nil {
		fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, projectOne(r, h.userResource(u)))
}

func (h *Handler) createUser(w http.ResponseWriter, r *http.Request) {
	c := callerFrom(r.Context())
	body, err := readBody(r)
	if err != nil {
		fail(w, r, err)
		return
	}
	a, err := fromResource(body, userAttrs{Active: true})
	if err == nil {
		err = a.validate()
	}
	if err != nil {
		fail(w, r, err)
		return
	}
	var su sqlc.ScimUser
	var o *op
	err = h.tx(r.Context(), func(q *sqlc.Queries) error {
		o = h.newOp(q, c)
		su, err = o.createUser(r.Context(), a)
		return err
	})
	if err != nil {
		fail(w, r, err)
		return
	}
	h.emit(r.Context(), o)
	w.Header().Set("Location", h.base+"/Users/"+su.ID)
	writeJSON(w, http.StatusCreated, h.userResource(su))
}

// mutateUser loads the user, lets change compute the new attributes and
// stores them in one transaction.
func (h *Handler) mutateUser(w http.ResponseWriter, r *http.Request, change func(su sqlc.ScimUser, body map[string]any) (userAttrs, error)) {
	c := callerFrom(r.Context())
	body, err := readBody(r)
	if err != nil {
		fail(w, r, err)
		return
	}
	var su sqlc.ScimUser
	var o *op
	err = h.tx(r.Context(), func(q *sqlc.Queries) error {
		cur, err := loadUser(r.Context(), q, c.OrgID, r.PathValue("id"))
		if err != nil {
			return err
		}
		a, err := change(cur, body)
		if err != nil {
			return err
		}
		o = h.newOp(q, c)
		su, err = o.updateUser(r.Context(), cur, a)
		return err
	})
	if err != nil {
		fail(w, r, err)
		return
	}
	h.emit(r.Context(), o)
	writeJSON(w, http.StatusOK, h.userResource(su))
}

// putUser replaces the supported attributes (Okta updates users by PUT).
func (h *Handler) putUser(w http.ResponseWriter, r *http.Request) {
	h.mutateUser(w, r, func(su sqlc.ScimUser, body map[string]any) (userAttrs, error) {
		return fromResource(body, attrsOf(su))
	})
}

func (h *Handler) patchUser(w http.ResponseWriter, r *http.Request) {
	h.mutateUser(w, r, func(su sqlc.ScimUser, body map[string]any) (userAttrs, error) {
		ops, err := patchOps(body)
		if err != nil {
			return userAttrs{}, err
		}
		a := attrsOf(su)
		for _, p := range ops {
			if err := a.apply(p); err != nil {
				return userAttrs{}, err
			}
		}
		return a, nil
	})
}

func (h *Handler) deleteUser(w http.ResponseWriter, r *http.Request) {
	c := callerFrom(r.Context())
	err := h.tx(r.Context(), func(q *sqlc.Queries) error {
		su, err := loadUser(r.Context(), q, c.OrgID, r.PathValue("id"))
		if err != nil {
			return err
		}
		return h.newOp(q, c).deleteUser(r.Context(), su)
	})
	if err != nil {
		fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// --- PATCH ----------------------------------------------------------------------

// patchOp is one PATCH operation with its op lower-cased (Entra sends
// "Replace", "Add").
type patchOp struct {
	Op    string
	Path  string
	Value any
}

func patchOps(body map[string]any) ([]patchOp, error) {
	raw, ok := getKey(body, "Operations")
	list, isList := raw.([]any)
	if !ok || !isList || len(list) == 0 {
		return nil, badRequest("invalidSyntax", "A PATCH request needs a non-empty Operations list.")
	}
	out := make([]patchOp, 0, len(list))
	for _, e := range list {
		m, ok := e.(map[string]any)
		if !ok {
			return nil, badRequest("invalidSyntax", "Each operation must be an object.")
		}
		opv, _ := getKey(m, "op")
		ops, _ := opv.(string)
		ops = strings.ToLower(strings.TrimSpace(ops))
		if ops != "add" && ops != "replace" && ops != "remove" {
			return nil, badRequest("invalidSyntax", "op must be add, replace or remove.")
		}
		pv, _ := getKey(m, "path")
		path, _ := pv.(string)
		val, _ := getKey(m, "value")
		if ops != "remove" && val == nil && path == "" {
			return nil, badRequest("invalidSyntax", "add and replace need a value.")
		}
		if ops == "remove" && strings.TrimSpace(path) == "" {
			return nil, &apiError{Status: http.StatusBadRequest, SCIMType: "noTarget", Detail: "remove needs a path."}
		}
		out = append(out, patchOp{Op: ops, Path: strings.TrimSpace(path), Value: val})
	}
	return out, nil
}

// apply applies one PATCH operation. Attributes Boardchestrator does not
// keep (and extension schemas) are accepted and ignored, so an IdP's full
// attribute mapping never fails provisioning.
func (a *userAttrs) apply(p patchOp) error {
	if p.Path == "" {
		m, ok := p.Value.(map[string]any)
		if !ok {
			return badRequest("invalidValue", "A PATCH without a path needs an object value.")
		}
		for k, v := range m {
			if err := a.applyPath(p.Op, k, v); err != nil {
				return err
			}
		}
		return nil
	}
	return a.applyPath(p.Op, p.Path, p.Value)
}

func (a *userAttrs) applyPath(op, path string, v any) error {
	if isExtensionPath(path) {
		return nil
	}
	c, err := ParsePath(path)
	if err != nil {
		return &apiError{Status: http.StatusBadRequest, SCIMType: "invalidPath", Detail: "The path is not valid."}
	}
	remove := op == "remove"
	setStr := func(dst *string, name string) error {
		if remove {
			*dst = ""
			return nil
		}
		s, err := str(v, name)
		if err != nil {
			return err
		}
		*dst = s
		return nil
	}
	key := strings.Join(c.Path, ".")
	if c.Sub != nil || c.SubAttr != "" {
		// Only emails[...] and emails[...].value are kept.
		if key != "emails" || remove || (c.SubAttr != "" && c.SubAttr != "value") {
			return nil
		}
		if c.SubAttr == "value" {
			return setStr(&a.Email, "emails.value")
		}
		e, err := pickEmail(v)
		if err != nil {
			return err
		}
		if e != "" {
			a.Email = e
		}
		return nil
	}
	switch key {
	case "username":
		if remove {
			return badRequest("mutability", "userName can't be removed.")
		}
		return setStr(&a.UserName, "userName")
	case "externalid":
		return setStr(&a.ExternalID, "externalId")
	case "displayname":
		return setStr(&a.DisplayName, "displayName")
	case "name.givenname":
		return setStr(&a.GivenName, "name.givenName")
	case "name.familyname":
		return setStr(&a.FamilyName, "name.familyName")
	case "name":
		if remove {
			return a.setName(nil, true)
		}
		return a.setName(v, op == "replace")
	case "emails", "emails.value":
		if remove {
			return nil
		}
		if key == "emails.value" {
			return setStr(&a.Email, "emails.value")
		}
		e, err := pickEmail(v)
		if err != nil {
			return err
		}
		if e != "" {
			a.Email = e
		}
		return nil
	case "active":
		if remove {
			return nil
		}
		b, err := boolean(v, "active")
		if err != nil {
			return err
		}
		a.Active = b
		return nil
	}
	return nil
}
