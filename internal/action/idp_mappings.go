package action

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// JIT provisioning and IdP group -> role mapping (WU-608, SPEC §7.5).

// Membership sources (memberships.source, migration 0037). Group sync only
// ever touches MembershipSourceIdP rows.
const (
	MembershipSourceManual = "manual"
	MembershipSourceInvite = "invite"
	MembershipSourceJIT    = "jit"
	MembershipSourceIdP    = "idp"
	MembershipSourceSCIM   = "scim"
)

// Action names.
const (
	ActionIdPMappingList   = "org.idp_mapping.list"
	ActionIdPMappingCreate = "org.idp_mapping.create"
	ActionIdPMappingDelete = "org.idp_mapping.delete"
)

// EventMembershipSynced is emitted (org-scoped, ids only) when group sync
// changed a user's memberships.
const EventMembershipSynced = "membership.synced"

// Limits.
const (
	maxGroupValueLen  = 256
	maxGroupClaimLen  = 256
	maxMappingsPerOrg = 500
)

// Refusals (fixed copy; all wrap ErrInvalidInput).
var (
	ErrMappingRole     = fmt.Errorf("%w: that role isn't available in this organisation", ErrInvalidInput)
	ErrMappingResource = fmt.Errorf("%w: that team or project isn't in this organisation", ErrInvalidInput)
	ErrMappingProvider = fmt.Errorf("%w: that identity provider isn't on this organisation", ErrInvalidInput)
	ErrMappingGroup    = fmt.Errorf("%w: enter the group value exactly as your identity provider sends it (up to 256 characters)", ErrInvalidInput)
	ErrMappingExists   = fmt.Errorf("%w: that group is already mapped for this team, project or organisation", ErrInvalidInput)
	ErrMappingLimit    = fmt.Errorf("%w: this organisation has reached its limit of 500 group mappings", ErrInvalidInput)
	ErrMappingNotFound = fmt.Errorf("%w: that group mapping isn't on this organisation", ErrInvalidInput)
	ErrJITOwnerRole    = fmt.Errorf("%w: the default role for new people can't be an owner role", ErrInvalidInput)
	ErrJITNoRole       = fmt.Errorf("%w: choose a default role before turning on just-in-time provisioning", ErrInvalidInput)
	ErrGroupClaim      = fmt.Errorf("%w: the group claim must be a claim name or dotted path (up to 256 characters)", ErrInvalidInput)
	ErrPlatformOrgSSO  = fmt.Errorf("%w: the platform organisation can't use provisioning", ErrInvalidInput)
)

// RoleForOrg returns roleID if it is usable in orgID: owned by the org or a
// seeded system role. Anything else (another org's role, a platform-only
// role) is ErrMappingRole.
func RoleForOrg(ctx context.Context, q *sqlc.Queries, orgID, roleID string) (sqlc.Role, error) {
	if roleID == "" || orgID == "" || orgID == PlatformOrgID {
		return sqlc.Role{}, ErrMappingRole
	}
	r, err := q.FindRoleForOrg(ctx, sqlc.FindRoleForOrgParams{ID: roleID, OrgID: orgID})
	if errors.Is(err, sql.ErrNoRows) {
		return sqlc.Role{}, ErrMappingRole
	}
	if err != nil {
		return sqlc.Role{}, fmt.Errorf("role lookup: %w", err)
	}
	return r, nil
}

// OwnerEquivalent reports whether r is the Owner system role or any role
// granting "*". Such roles can never be the JIT default: anyone on a
// verified domain would become an owner on first sign-in.
func OwnerEquivalent(r sqlc.Role) bool {
	if r.ID == PlatformOwnerRoleID {
		return true
	}
	var grants []string
	if err := json.Unmarshal([]byte(r.GrantsJson), &grants); err != nil {
		return true // unreadable grants: refuse rather than guess
	}
	for _, g := range grants {
		if strings.TrimSpace(g) == "*" {
			return true
		}
	}
	return false
}

// JITDefaultRole returns the org's JIT default role when JIT is on and the
// role is still usable for it ("" otherwise: JIT off, no row, or the role was
// deleted, moved out of reach or edited into an owner role since).
func JITDefaultRole(ctx context.Context, q *sqlc.Queries, orgID string) (string, error) {
	if orgID == "" || orgID == PlatformOrgID {
		return "", nil
	}
	st, err := q.GetOrgSSOSettings(ctx, orgID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("org sso settings: %w", err)
	}
	if st.JitEnabled == 0 || !st.JitDefaultRoleID.Valid {
		return "", nil
	}
	r, err := RoleForOrg(ctx, q, orgID, st.JitDefaultRoleID.String)
	if errors.Is(err, ErrMappingRole) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if OwnerEquivalent(r) {
		return "", nil
	}
	return r.ID, nil
}

// validGroupClaim accepts a claim name or path: printable, no spaces.
func validGroupClaim(s string) bool {
	if len(s) > maxGroupClaimLen {
		return false
	}
	for _, r := range s {
		if unicode.IsSpace(r) || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

func validGroupValue(s string) bool {
	if s == "" || len(s) > maxGroupValueLen {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// --- org.idp_mapping.* ------------------------------------------------------

// IdPMappingView is one group mapping as the actions return it.
type IdPMappingView struct {
	ID           string `json:"id"`
	ProviderID   string `json:"provider_id,omitempty"`
	GroupValue   string `json:"group_value"`
	RoleID       string `json:"role_id"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	CreatedAt    string `json:"created_at"`
}

func mappingView(m sqlc.IdpGroupMapping) IdPMappingView {
	return IdPMappingView{
		ID: m.ID, ProviderID: m.ProviderID.String, GroupValue: m.GroupValue, RoleID: m.RoleID,
		ResourceType: m.ResourceType, ResourceID: m.ResourceID, CreatedAt: m.CreatedAt,
	}
}

type idpMappingCreateInput struct {
	OrgID        string `json:"org_id,omitempty"`
	ProviderID   string `json:"provider_id,omitempty"`
	GroupValue   string `json:"group_value"`
	RoleID       string `json:"role_id"`
	ResourceType string `json:"resource_type,omitempty"`
	ResourceID   string `json:"resource_id,omitempty"`
}

type idpMappingIDInput struct {
	OrgID string `json:"org_id,omitempty"`
	ID    string `json:"id"`
}

func strictDecode(raw json.RawMessage, v any) error {
	if len(bytes.TrimSpace(raw)) == 0 {
		raw = json.RawMessage("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	return nil
}

func strictSchema[T any]() Schema {
	return FuncSchema(func(raw json.RawMessage) error {
		var v T
		return strictDecode(raw, &v)
	})
}

func init() {
	for _, def := range []Definition{
		{Name: ActionIdPMappingList, Impact: ImpactRead, Handle: handleIdPMappingList,
			Input: strictSchema[struct {
				OrgID string `json:"org_id,omitempty"`
			}]()},
		{Name: ActionIdPMappingCreate, Impact: ImpactHigh, Handle: handleIdPMappingCreate,
			Input: strictSchema[idpMappingCreateInput]()},
		{Name: ActionIdPMappingDelete, Impact: ImpactHigh, Handle: handleIdPMappingDelete,
			Input: strictSchema[idpMappingIDInput]()},
	} {
		def.Permission = PermissionOrgSSO
		def.Scope = ScopeOrg
		Register(def)
	}
}

func handleIdPMappingList(ctx context.Context, ac ActionCtx, _ json.RawMessage) (any, error) {
	rows, err := ac.Tx.ListIdPGroupMappings(ctx, ac.Org)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ActionIdPMappingList, err)
	}
	out := make([]IdPMappingView, 0, len(rows))
	for _, m := range rows {
		out = append(out, mappingView(m))
	}
	return out, nil
}

func handleIdPMappingCreate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input idpMappingCreateInput
	if err := strictDecode(in, &input); err != nil {
		return nil, err
	}
	if ac.Org == PlatformOrgID {
		return nil, ErrPlatformOrgSSO
	}
	q := ac.Tx.Queries
	group := strings.TrimSpace(input.GroupValue)
	if !validGroupValue(group) {
		return nil, ErrMappingGroup
	}
	if _, err := RoleForOrg(ctx, q, ac.Org, strings.TrimSpace(input.RoleID)); err != nil {
		return nil, err
	}
	rt, rid := strings.TrimSpace(input.ResourceType), strings.TrimSpace(input.ResourceID)
	if rt == "" {
		rt = "org"
	}
	if err := checkMappingResource(ctx, q, ac.Org, rt, &rid); err != nil {
		return nil, err
	}
	prov := sql.NullString{}
	if p := strings.TrimSpace(input.ProviderID); p != "" {
		if _, err := q.GetOrgAuthProvider(ctx, sqlc.GetOrgAuthProviderParams{ID: p, OrgID: sql.NullString{String: ac.Org, Valid: true}}); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, ErrMappingProvider
			}
			return nil, fmt.Errorf("%s: provider: %w", ActionIdPMappingCreate, err)
		}
		prov = sql.NullString{String: p, Valid: true}
	}
	existing, err := q.ListIdPGroupMappings(ctx, ac.Org)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ActionIdPMappingCreate, err)
	}
	if len(existing) >= maxMappingsPerOrg {
		return nil, ErrMappingLimit
	}
	for _, m := range existing {
		if m.ProviderID == prov && m.GroupValue == group && m.ResourceType == rt && m.ResourceID == rid {
			return nil, ErrMappingExists
		}
	}
	id := newID()
	if err := q.CreateIdPGroupMapping(ctx, sqlc.CreateIdPGroupMappingParams{
		ID: id, OrgID: ac.Org, ProviderID: prov, GroupValue: group, RoleID: strings.TrimSpace(input.RoleID),
		ResourceType: rt, ResourceID: rid,
	}); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, ErrMappingExists
		}
		return nil, fmt.Errorf("%s: %w", ActionIdPMappingCreate, err)
	}
	return IdPMappingView{
		ID: id, ProviderID: prov.String, GroupValue: group, RoleID: strings.TrimSpace(input.RoleID),
		ResourceType: rt, ResourceID: rid,
	}, nil
}

// checkMappingResource verifies a mapping target belongs to orgID; an org
// target's id defaults to orgID.
func checkMappingResource(ctx context.Context, q *sqlc.Queries, orgID, rt string, rid *string) error {
	switch rt {
	case "org":
		if *rid == "" {
			*rid = orgID
		}
		if *rid != orgID {
			return ErrMappingResource
		}
		return nil
	case "team":
		_, err := q.FindTeamByID(ctx, sqlc.FindTeamByIDParams{ID: *rid, OrgID: orgID})
		return resourceErr(err)
	case "project":
		_, err := q.FindProjectByID(ctx, sqlc.FindProjectByIDParams{ID: *rid, OrgID: orgID})
		return resourceErr(err)
	}
	return ErrMappingResource
}

func resourceErr(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrMappingResource
	}
	if err != nil {
		return fmt.Errorf("mapping resource: %w", err)
	}
	return nil
}

func handleIdPMappingDelete(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input idpMappingIDInput
	if err := strictDecode(in, &input); err != nil {
		return nil, err
	}
	n, err := ac.Tx.DeleteIdPGroupMapping(ctx, sqlc.DeleteIdPGroupMappingParams{ID: input.ID, OrgID: ac.Org})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ActionIdPMappingDelete, err)
	}
	if n == 0 {
		return nil, ErrMappingNotFound
	}
	return map[string]string{"id": input.ID}, nil
}

// --- Reconciliation (SPEC §7.5) ----------------------------------------------

// SyncedMembership is one membership group sync added, updated or removed.
type SyncedMembership struct {
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	RoleID       string `json:"role_id"`
}

// SyncResult is what ReconcileIdPMemberships changed. Kept lists desired
// memberships left alone because a manual, invite, JIT or SCIM membership
// already holds that resource.
type SyncResult struct {
	OrgID   string             `json:"org_id"`
	UserID  string             `json:"user_id"`
	Added   []SyncedMembership `json:"added"`
	Updated []SyncedMembership `json:"updated"`
	Removed []SyncedMembership `json:"removed"`
	Kept    []SyncedMembership `json:"kept"`
}

// Changed reports whether any membership was written.
func (r SyncResult) Changed() bool {
	return len(r.Added)+len(r.Updated)+len(r.Removed) > 0
}

// Event is the membership.synced event for r (org-scoped; ids only).
func (r SyncResult) Event(actor Actor) Event {
	b, _ := json.Marshal(r)
	return Event{Name: EventMembershipSynced, Org: r.OrgID, Actor: actor, Subject: r.UserID, Payload: b}
}

// SyncInput is one reconciliation request.
type SyncInput struct {
	OrgID  string
	UserID string
	// ProviderID is the org provider the user signed in through: its own
	// mappings and the org-wide (provider-less) ones apply. "" applies only
	// the org-wide mappings (SCIM, WU-611).
	ProviderID string
	// Groups are the user's group values (exact, case-sensitive match).
	Groups []string
	// Actor and IP are recorded on the audit row (the user at sign-in; the
	// SCIM service actor for WU-611).
	Actor Actor
	IP    string
	Now   time.Time
}

type memberKey struct{ rt, rid string }

// keepLastOwner reports whether sync must leave m alone because it is the
// org's last owner membership and the change (a new role, or "" for removal)
// would leave the org without an owner (WU-613). It audits the decision.
func keepLastOwner(ctx context.Context, q *sqlc.Queries, in SyncInput, m sqlc.Membership, newRole string) (bool, error) {
	if m.ResourceType != "org" || m.ResourceID != in.OrgID {
		return false, nil
	}
	if newRole != "" {
		r, err := RoleForOrg(ctx, q, in.OrgID, newRole)
		if err != nil {
			return false, err
		}
		if OwnerEquivalent(r) {
			return false, nil
		}
	}
	last, err := IsLastOwnerMembership(ctx, q, in.OrgID, m.ID)
	if err != nil || !last {
		return false, err
	}
	if err := AuditOwnerPreserved(ctx, q, in.OrgID, in.UserID, m.ID, "group_sync", in.Actor, in.Now); err != nil {
		return false, fmt.Errorf("group sync: audit: %w", err)
	}
	return true, nil
}

// ReconcileIdPMemberships makes the user's source='idp' memberships in
// in.OrgID match the org's group mappings for in.Groups (SPEC §7.5): it
// inserts missing ones, updates the role where the resource matches, and
// deletes stale ones. Memberships with any other source are never changed;
// where one already holds a desired resource (the memberships table allows
// one membership per user per resource), the desired one is skipped and
// listed in Kept. Several mappings onto one resource: the oldest mapping
// wins. Mappings whose role or resource has gone are ignored. Callers run
// it inside their transaction and emit res.Event after commit; it writes
// a membership.synced audit row when anything changed.
func ReconcileIdPMemberships(ctx context.Context, q *sqlc.Queries, in SyncInput) (SyncResult, error) {
	res := SyncResult{OrgID: in.OrgID, UserID: in.UserID,
		Added: []SyncedMembership{}, Updated: []SyncedMembership{}, Removed: []SyncedMembership{}, Kept: []SyncedMembership{}}
	if in.OrgID == "" || in.OrgID == PlatformOrgID || in.UserID == "" {
		return res, nil
	}
	groups := make(map[string]struct{}, len(in.Groups))
	for _, g := range in.Groups {
		if g = strings.TrimSpace(g); g != "" {
			groups[g] = struct{}{}
		}
	}
	mappings, err := q.ListIdPGroupMappingsForProvider(ctx, sqlc.ListIdPGroupMappingsForProviderParams{
		OrgID: in.OrgID, ProviderID: sql.NullString{String: in.ProviderID, Valid: true},
	})
	if err != nil {
		return res, fmt.Errorf("group sync: mappings: %w", err)
	}
	desired := map[memberKey]string{}
	var order []memberKey
	for _, m := range mappings {
		if _, ok := groups[m.GroupValue]; !ok {
			continue
		}
		k := memberKey{m.ResourceType, m.ResourceID}
		if _, dup := desired[k]; dup {
			continue
		}
		if _, err := RoleForOrg(ctx, q, in.OrgID, m.RoleID); err != nil {
			if errors.Is(err, ErrMappingRole) {
				continue
			}
			return res, err
		}
		rid := m.ResourceID
		if err := checkMappingResource(ctx, q, in.OrgID, m.ResourceType, &rid); err != nil {
			if errors.Is(err, ErrMappingResource) {
				continue
			}
			return res, err
		}
		desired[k] = m.RoleID
		order = append(order, k)
	}

	rows, err := q.FindMembershipsForActor(ctx, sqlc.FindMembershipsForActorParams{
		OrgID: in.OrgID, ActorType: string(ActorUser), ActorID: in.UserID,
	})
	if err != nil {
		return res, fmt.Errorf("group sync: memberships: %w", err)
	}
	existing := make(map[memberKey]sqlc.Membership, len(rows))
	for _, m := range rows {
		existing[memberKey{m.ResourceType, m.ResourceID}] = m
	}

	for _, k := range order {
		role := desired[k]
		sm := SyncedMembership{ResourceType: k.rt, ResourceID: k.rid, RoleID: role}
		cur, ok := existing[k]
		switch {
		case !ok:
			if err := q.CreateSourcedMembership(ctx, sqlc.CreateSourcedMembershipParams{
				ID: newID(), OrgID: in.OrgID, ActorID: in.UserID, ResourceType: k.rt, ResourceID: k.rid,
				RoleID: sql.NullString{String: role, Valid: true}, Source: MembershipSourceIdP,
			}); err != nil {
				return res, fmt.Errorf("group sync: add: %w", err)
			}
			res.Added = append(res.Added, sm)
		case cur.Source != MembershipSourceIdP:
			res.Kept = append(res.Kept, sm)
		case !cur.RoleID.Valid || cur.RoleID.String != role:
			keep, err := keepLastOwner(ctx, q, in, cur, role)
			if err != nil {
				return res, err
			}
			if keep {
				res.Kept = append(res.Kept, sm)
				continue
			}
			if _, err := q.UpdateIdPMembershipRole(ctx, sqlc.UpdateIdPMembershipRoleParams{
				RoleID: sql.NullString{String: role, Valid: true}, ID: cur.ID, OrgID: in.OrgID,
			}); err != nil {
				return res, fmt.Errorf("group sync: update: %w", err)
			}
			res.Updated = append(res.Updated, sm)
		}
	}
	stale := make([]sqlc.Membership, 0)
	for k, m := range existing {
		if _, want := desired[k]; !want && m.Source == MembershipSourceIdP {
			stale = append(stale, m)
		}
	}
	sort.Slice(stale, func(i, j int) bool { return stale[i].ID < stale[j].ID })
	for _, m := range stale {
		keep, err := keepLastOwner(ctx, q, in, m, "")
		if err != nil {
			return res, err
		}
		if keep {
			res.Kept = append(res.Kept, SyncedMembership{ResourceType: m.ResourceType, ResourceID: m.ResourceID, RoleID: m.RoleID.String})
			continue
		}
		if _, err := q.DeleteIdPMembership(ctx, sqlc.DeleteIdPMembershipParams{ID: m.ID, OrgID: in.OrgID}); err != nil {
			return res, fmt.Errorf("group sync: remove: %w", err)
		}
		res.Removed = append(res.Removed, SyncedMembership{ResourceType: m.ResourceType, ResourceID: m.ResourceID, RoleID: m.RoleID.String})
	}

	if !res.Changed() {
		return res, nil
	}
	detail, err := json.Marshal(map[string]any{
		"provider": in.ProviderID, "added": res.Added, "updated": res.Updated, "removed": res.Removed,
	})
	if err != nil {
		return res, fmt.Errorf("group sync: audit detail: %w", err)
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	if err := q.CreateAuditLog(ctx, sqlc.CreateAuditLogParams{
		ID: newID(), OrgID: sql.NullString{String: in.OrgID, Valid: true},
		ActorType: string(in.Actor.Type), ActorID: in.Actor.ID, Action: EventMembershipSynced,
		Subject: in.UserID, DetailJson: string(detail), Ip: in.IP, CreatedAt: now.UTC().Format(timeFormat),
	}); err != nil {
		return res, fmt.Errorf("group sync: audit: %w", err)
	}
	return res, nil
}
