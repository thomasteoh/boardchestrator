package scim

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// Provisioning (SPEC §7.8): SCIM users and groups to platform users, org
// memberships (source='scim') and, through the org's group mappings, idp
// memberships (SPEC §7.5).

// memberRoleID is the seeded Member system role, the default role for a
// SCIM membership when the org has no usable JIT default role.
const memberRoleID = "22222222222222222222222222222222"

// formerMemberUserID is the data-export sentinel user (migration 0017); it
// can never be provisioned.
const formerMemberUserID = "ffffffffffffffffffffffffffffffff"

const maxAttrLen = 256

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("scim: crypto/rand: %v", err))
	}
	return hex.EncodeToString(b[:])
}

// tx runs fn in a BEGIN IMMEDIATE transaction on a dedicated connection, so
// concurrent provisioning requests queue on busy_timeout instead of failing
// a read-then-write upgrade with SQLITE_BUSY.
func (h *Handler) tx(ctx context.Context, fn func(q *sqlc.Queries) error) (err error) {
	conn, err := h.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("scim: db conn: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("scim: begin: %w", err)
	}
	done := false
	defer func() {
		if !done {
			_, _ = conn.ExecContext(context.WithoutCancel(ctx), "ROLLBACK")
		}
	}()
	if err := fn(sqlc.New(conn)); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("scim: commit: %w", err)
	}
	done = true
	return nil
}

// op carries one request's context through the provisioning functions.
type op struct {
	q      *sqlc.Queries
	c      caller
	now    string
	synced []action.SyncResult
}

func (h *Handler) newOp(q *sqlc.Queries, c caller) *op {
	return &op{q: q, c: c, now: h.now().UTC().Format(timeFormat)}
}

// emit publishes the membership.synced events after commit.
func (h *Handler) emit(ctx context.Context, o *op) {
	if h.events == nil {
		return
	}
	for _, res := range o.synced {
		if res.Changed() {
			h.events.Emit(ctx, res.Event(o.c.Actor))
		}
	}
}

// audit writes an org-scoped audit row as the SCIM service actor. Details
// carry ids and counts only.
func (o *op) audit(ctx context.Context, act, subject string, detail map[string]any) error {
	b, err := json.Marshal(detail)
	if err != nil {
		return fmt.Errorf("scim: audit detail: %w", err)
	}
	if err := o.q.CreateAuditLog(ctx, sqlc.CreateAuditLogParams{
		ID: newID(), OrgID: sql.NullString{String: o.c.OrgID, Valid: true},
		ActorType: string(o.c.Actor.Type), ActorID: o.c.Actor.ID, Action: act, Subject: subject,
		DetailJson: string(b), Ip: o.c.Actor.IP, CreatedAt: o.now,
	}); err != nil {
		return fmt.Errorf("scim: audit %s: %w", act, err)
	}
	return nil
}

// --- User attributes ------------------------------------------------------------

// userAttrs are the SCIM User attributes Boardchestrator keeps.
type userAttrs struct {
	UserName    string
	ExternalID  string
	Email       string
	GivenName   string
	FamilyName  string
	DisplayName string
	Active      bool
}

func attrsOf(u sqlc.ScimUser) userAttrs {
	return userAttrs{
		UserName: u.UserName, ExternalID: u.ExternalID, Email: u.Email, GivenName: u.GivenName,
		FamilyName: u.FamilyName, DisplayName: u.DisplayName, Active: u.Active == 1,
	}
}

// getKey returns m's value for key, compared case-insensitively.
func getKey(m map[string]any, key string) (any, bool) {
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return nil, false
}

// str converts a SCIM string value; nil is "".
func str(v any, name string) (string, error) {
	switch x := v.(type) {
	case nil:
		return "", nil
	case string:
		x = strings.TrimSpace(x)
		if len(x) > maxAttrLen {
			return "", badRequest("invalidValue", "%s is too long (up to %d characters).", name, maxAttrLen)
		}
		for _, r := range x {
			if !unicode.IsPrint(r) {
				return "", badRequest("invalidValue", "%s contains control characters.", name)
			}
		}
		return x, nil
	}
	return "", badRequest("invalidValue", "%s must be a string.", name)
}

// boolean accepts JSON booleans and the strings "true"/"false" in any case
// (Entra sends "False").
func boolean(v any, name string) (bool, error) {
	switch x := v.(type) {
	case bool:
		return x, nil
	case string:
		if b, err := strconv.ParseBool(strings.ToLower(strings.TrimSpace(x))); err == nil {
			return b, nil
		}
	}
	return false, badRequest("invalidValue", "%s must be true or false.", name)
}

// pickEmail chooses the address from a SCIM emails value: the primary one,
// else the work one, else the first.
func pickEmail(v any) (string, error) {
	var list []any
	switch x := v.(type) {
	case nil:
		return "", nil
	case []any:
		list = x
	case map[string]any:
		list = []any{x}
	default:
		return "", badRequest("invalidValue", "emails must be a list.")
	}
	var primary, work, first string
	for _, e := range list {
		m, ok := e.(map[string]any)
		if !ok {
			return "", badRequest("invalidValue", "emails must be a list of objects.")
		}
		val, _ := getKey(m, "value")
		s, err := str(val, "emails.value")
		if err != nil || s == "" {
			if err != nil {
				return "", err
			}
			continue
		}
		if first == "" {
			first = s
		}
		if p, ok := getKey(m, "primary"); ok {
			if b, err := boolean(p, "emails.primary"); err == nil && b && primary == "" {
				primary = s
			}
		}
		if t, ok := getKey(m, "type"); ok {
			if ts, _ := t.(string); strings.EqualFold(ts, "work") && work == "" {
				work = s
			}
		}
	}
	switch {
	case primary != "":
		return primary, nil
	case work != "":
		return work, nil
	}
	return first, nil
}

// setName applies a SCIM name object.
func (a *userAttrs) setName(v any, replace bool) error {
	if v == nil {
		a.GivenName, a.FamilyName = "", ""
		return nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return badRequest("invalidValue", "name must be an object.")
	}
	if replace {
		a.GivenName, a.FamilyName = "", ""
	}
	if g, ok := getKey(m, "givenName"); ok {
		s, err := str(g, "name.givenName")
		if err != nil {
			return err
		}
		a.GivenName = s
	}
	if f, ok := getKey(m, "familyName"); ok {
		s, err := str(f, "name.familyName")
		if err != nil {
			return err
		}
		a.FamilyName = s
	}
	return nil
}

// fromResource reads a full User resource (POST, PUT) over base: every
// supported attribute is replaced; active keeps base's value when absent.
func fromResource(m map[string]any, base userAttrs) (userAttrs, error) {
	a := userAttrs{Active: base.Active}
	var err error
	v, _ := getKey(m, "userName")
	if a.UserName, err = str(v, "userName"); err != nil {
		return a, err
	}
	v, _ = getKey(m, "externalId")
	if a.ExternalID, err = str(v, "externalId"); err != nil {
		return a, err
	}
	v, _ = getKey(m, "displayName")
	if a.DisplayName, err = str(v, "displayName"); err != nil {
		return a, err
	}
	if v, ok := getKey(m, "name"); ok {
		if err := a.setName(v, true); err != nil {
			return a, err
		}
	}
	v, _ = getKey(m, "emails")
	if a.Email, err = pickEmail(v); err != nil {
		return a, err
	}
	if v, ok := getKey(m, "active"); ok && v != nil {
		if a.Active, err = boolean(v, "active"); err != nil {
			return a, err
		}
	}
	return a, nil
}

// validate checks the attributes a stored user needs and fills the email
// from an address-shaped userName.
func (a *userAttrs) validate() error {
	if a.UserName == "" {
		return badRequest("invalidValue", "userName is required.")
	}
	if a.Email == "" && strings.Contains(a.UserName, "@") {
		a.Email = a.UserName
	}
	if a.Email == "" {
		return badRequest("invalidValue", "An email address (emails, or an address as userName) is required.")
	}
	if _, err := action.EmailDomain(a.Email); err != nil || strings.ContainsAny(a.Email, " <>,;") {
		return badRequest("invalidValue", "The email address is not valid.")
	}
	return nil
}

// fullName is the platform user's name for a new account.
func (a userAttrs) fullName() string {
	if a.DisplayName != "" {
		return a.DisplayName
	}
	if n := strings.TrimSpace(a.GivenName + " " + a.FamilyName); n != "" {
		return n
	}
	return a.UserName
}

// --- Users ------------------------------------------------------------------------

// createUser provisions a SCIM user (SPEC §7.8): link an existing platform
// user only when the email's domain is verified for this org, refuse an
// existing address on any other domain (users.email is unique, and linking
// it would hand another account to this org), else create the user.
func (o *op) createUser(ctx context.Context, a userAttrs) (sqlc.ScimUser, error) {
	org := o.c.OrgID
	if _, err := o.q.FindSCIMUserByUserName(ctx, sqlc.FindSCIMUserByUserNameParams{OrgID: org, UserName: a.UserName}); err == nil {
		return sqlc.ScimUser{}, conflict("A user with this userName already exists.")
	} else if !errors.Is(err, sql.ErrNoRows) {
		return sqlc.ScimUser{}, fmt.Errorf("scim: user name lookup: %w", err)
	}
	userID, linked := "", false
	existing, err := o.q.FindUserByEmailFold(ctx, a.Email)
	switch {
	case err == nil:
		if existing.DeletedAt.Valid || existing.ID == formerMemberUserID {
			return sqlc.ScimUser{}, conflict("This email address belongs to a deleted account and can't be provisioned.")
		}
		verifiedOrg, err := action.VerifiedOrgForEmail(ctx, o.q, a.Email)
		if err != nil {
			return sqlc.ScimUser{}, err
		}
		if verifiedOrg != org {
			slog.Warn("scim: refused to link an existing account outside the org's verified domains",
				"org", org, "token", o.c.TokenID)
			return sqlc.ScimUser{}, conflict("An account with this email address already exists, and its domain isn't verified for this organisation. Verify the domain under Single sign-on so SCIM can link the account.")
		}
		if _, err := o.q.GetSCIMUserByUser(ctx, sqlc.GetSCIMUserByUserParams{OrgID: org, UserID: existing.ID}); err == nil {
			return sqlc.ScimUser{}, conflict("This account is already provisioned as another SCIM user in this organisation.")
		} else if !errors.Is(err, sql.ErrNoRows) {
			return sqlc.ScimUser{}, fmt.Errorf("scim: scim user lookup: %w", err)
		}
		userID, linked = existing.ID, true
	case errors.Is(err, sql.ErrNoRows):
		userID = newID()
		if err := o.q.CreateUser(ctx, sqlc.CreateUserParams{ID: userID, Email: a.Email, Name: a.fullName()}); err != nil {
			return sqlc.ScimUser{}, fmt.Errorf("scim: create user: %w", err)
		}
	default:
		return sqlc.ScimUser{}, fmt.Errorf("scim: user lookup: %w", err)
	}
	su := sqlc.ScimUser{
		ID: newID(), OrgID: org, UserID: userID, ExternalID: a.ExternalID, UserName: a.UserName, Email: a.Email,
		GivenName: a.GivenName, FamilyName: a.FamilyName, DisplayName: a.DisplayName, Active: b2i(a.Active),
		CreatedAt: o.now, UpdatedAt: o.now,
	}
	if err := o.q.CreateSCIMUser(ctx, sqlc.CreateSCIMUserParams{
		ID: su.ID, OrgID: org, UserID: userID, ExternalID: su.ExternalID, UserName: su.UserName, Email: su.Email,
		GivenName: su.GivenName, FamilyName: su.FamilyName, DisplayName: su.DisplayName, Active: su.Active,
		CreatedAt: o.now, UpdatedAt: o.now,
	}); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return sqlc.ScimUser{}, conflict("A user with this userName already exists.")
		}
		return sqlc.ScimUser{}, fmt.Errorf("scim: create scim user: %w", err)
	}
	if err := o.audit(ctx, "scim.user.created", userID, map[string]any{
		"scim_user_id": su.ID, "user_id": userID, "linked": linked, "active": a.Active,
	}); err != nil {
		return sqlc.ScimUser{}, err
	}
	if a.Active {
		if err := o.grantMembership(ctx, userID); err != nil {
			return sqlc.ScimUser{}, err
		}
	}
	return su, nil
}

func b2i(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// updateUser stores a's attributes for su and applies an active change.
func (o *op) updateUser(ctx context.Context, su sqlc.ScimUser, a userAttrs) (sqlc.ScimUser, error) {
	if err := a.validate(); err != nil {
		return su, err
	}
	if !strings.EqualFold(a.UserName, su.UserName) {
		if other, err := o.q.FindSCIMUserByUserName(ctx, sqlc.FindSCIMUserByUserNameParams{OrgID: o.c.OrgID, UserName: a.UserName}); err == nil && other.ID != su.ID {
			return su, conflict("A user with this userName already exists.")
		} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return su, fmt.Errorf("scim: user name lookup: %w", err)
		}
	}
	old := attrsOf(su)
	var changed []string
	for _, f := range []struct {
		name     string
		was, now string
	}{
		{"userName", old.UserName, a.UserName}, {"externalId", old.ExternalID, a.ExternalID},
		{"emails", old.Email, a.Email}, {"name.givenName", old.GivenName, a.GivenName},
		{"name.familyName", old.FamilyName, a.FamilyName}, {"displayName", old.DisplayName, a.DisplayName},
	} {
		if f.was != f.now {
			changed = append(changed, f.name)
		}
	}
	if old.Active != a.Active {
		changed = append(changed, "active")
	}
	if err := o.q.UpdateSCIMUser(ctx, sqlc.UpdateSCIMUserParams{
		ExternalID: a.ExternalID, UserName: a.UserName, Email: a.Email, GivenName: a.GivenName,
		FamilyName: a.FamilyName, DisplayName: a.DisplayName, Active: b2i(a.Active), UpdatedAt: o.now,
		ID: su.ID, OrgID: o.c.OrgID,
	}); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return su, conflict("A user with this userName already exists.")
		}
		return su, fmt.Errorf("scim: update scim user: %w", err)
	}
	su.UserName, su.ExternalID, su.Email = a.UserName, a.ExternalID, a.Email
	su.GivenName, su.FamilyName, su.DisplayName = a.GivenName, a.FamilyName, a.DisplayName
	su.Active, su.UpdatedAt = b2i(a.Active), o.now
	if len(changed) > 0 {
		if err := o.audit(ctx, "scim.user.updated", su.UserID, map[string]any{
			"scim_user_id": su.ID, "user_id": su.UserID, "changed": changed,
		}); err != nil {
			return su, err
		}
	}
	switch {
	case old.Active && !a.Active:
		if err := o.deprovision(ctx, su, "scim.user.deactivated"); err != nil {
			return su, err
		}
	case !old.Active && a.Active:
		if err := o.grantMembership(ctx, su.UserID); err != nil {
			return su, err
		}
		if err := o.syncUser(ctx, su.UserID); err != nil {
			return su, err
		}
		if err := o.audit(ctx, "scim.user.reactivated", su.UserID, map[string]any{
			"scim_user_id": su.ID, "user_id": su.UserID,
		}); err != nil {
			return su, err
		}
	}
	return su, nil
}

// deleteUser deprovisions su and removes the SCIM user and its group
// memberships. The platform user is never deleted.
func (o *op) deleteUser(ctx context.Context, su sqlc.ScimUser) error {
	if err := o.deprovision(ctx, su, "scim.user.deleted"); err != nil {
		return err
	}
	if err := o.q.RemoveSCIMUserFromGroups(ctx, sqlc.RemoveSCIMUserFromGroupsParams{OrgID: o.c.OrgID, UserID: su.UserID}); err != nil {
		return fmt.Errorf("scim: remove from groups: %w", err)
	}
	if _, err := o.q.DeleteSCIMUser(ctx, sqlc.DeleteSCIMUserParams{ID: su.ID, OrgID: o.c.OrgID}); err != nil {
		return fmt.Errorf("scim: delete scim user: %w", err)
	}
	return nil
}

// deprovision removes every membership the user holds in the org (any
// source), revokes their API keys bound to the org and, when they no longer
// belong to any organisation, their sessions. Sessions stay when the user
// still belongs elsewhere: revoking them would sign the person out of every
// other organisation, and with no membership here the permission check
// already refuses them this one.
func (o *op) deprovision(ctx context.Context, su sqlc.ScimUser, act string) error {
	org := o.c.OrgID
	// Last-owner protection (WU-613): the org's only owner keeps that one
	// membership; everything else is still deprovisioned.
	owners, err := action.OrgOwnerMemberships(ctx, o.q, org)
	if err != nil {
		return fmt.Errorf("scim: owners: %w", err)
	}
	keep := ""
	if len(owners) == 1 && owners[0].ActorID == su.UserID {
		keep = owners[0].ID
	}
	var mems int64
	if keep != "" {
		mems, err = o.q.DeleteUserOrgMembershipsExcept(ctx, sqlc.DeleteUserOrgMembershipsExceptParams{OrgID: org, ActorID: su.UserID, ID: keep})
	} else {
		mems, err = o.q.DeleteUserOrgMemberships(ctx, sqlc.DeleteUserOrgMembershipsParams{OrgID: org, ActorID: su.UserID})
	}
	if err != nil {
		return fmt.Errorf("scim: remove memberships: %w", err)
	}
	if keep != "" {
		now, _ := time.Parse(timeFormat, o.now)
		if err := action.AuditOwnerPreserved(ctx, o.q, org, su.UserID, keep, "scim", o.c.Actor, now); err != nil {
			return fmt.Errorf("scim: audit: %w", err)
		}
	}
	keys, err := o.q.RevokeUserOrgAPIKeys(ctx, sqlc.RevokeUserOrgAPIKeysParams{
		Now: sql.NullString{String: o.now, Valid: true}, OrgID: org, UserID: su.UserID,
	})
	if err != nil {
		return fmt.Errorf("scim: revoke api keys: %w", err)
	}
	// The preserved owner membership does not keep the person signed in:
	// sessions go when nothing but it is left.
	var left int64
	if keep != "" {
		left, err = o.q.CountUserMembershipOrgsExcept(ctx, sqlc.CountUserMembershipOrgsExceptParams{ActorID: su.UserID, OrgID: org})
	} else {
		left, err = o.q.CountUserMembershipOrgs(ctx, su.UserID)
	}
	if err != nil {
		return fmt.Errorf("scim: count memberships: %w", err)
	}
	sessions := false
	if left == 0 {
		if err := o.q.DeleteUserSessions(ctx, su.UserID); err != nil {
			return fmt.Errorf("scim: revoke sessions: %w", err)
		}
		sessions = true
	}
	if err := o.audit(ctx, act, su.UserID, map[string]any{
		"scim_user_id": su.ID, "user_id": su.UserID,
	}); err != nil {
		return err
	}
	if mems > 0 {
		if err := o.audit(ctx, "membership.scim_removed", su.UserID, map[string]any{"user_id": su.UserID, "removed": mems}); err != nil {
			return err
		}
	}
	if keys > 0 {
		if err := o.audit(ctx, "apikey.scim_revoked", su.UserID, map[string]any{"user_id": su.UserID, "revoked": keys}); err != nil {
			return err
		}
	}
	if sessions {
		if err := o.audit(ctx, "session.scim_revoked", su.UserID, map[string]any{"user_id": su.UserID}); err != nil {
			return err
		}
	}
	return nil
}

// grantMembership gives the user an org-level membership (source='scim')
// with the org's JIT default role, or Member when that is unset or no
// longer usable. An existing org-level membership of any source is kept.
func (o *op) grantMembership(ctx context.Context, userID string) error {
	org := o.c.OrgID
	if _, err := o.q.FindOrgMembershipForUser(ctx, sqlc.FindOrgMembershipForUserParams{OrgID: org, ActorID: userID}); err == nil {
		return nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("scim: membership lookup: %w", err)
	}
	role, err := o.defaultRole(ctx)
	if err != nil {
		return err
	}
	memID := newID()
	if err := o.q.CreateSourcedMembership(ctx, sqlc.CreateSourcedMembershipParams{
		ID: memID, OrgID: org, ActorID: userID, ResourceType: "org", ResourceID: org,
		RoleID: sql.NullString{String: role, Valid: true}, Source: action.MembershipSourceSCIM,
	}); err != nil {
		return fmt.Errorf("scim: create membership: %w", err)
	}
	return o.audit(ctx, "membership.scim", userID, map[string]any{"membership_id": memID, "user_id": userID, "role_id": role})
}

// defaultRole is the JIT default role when set and usable (never an
// owner-equivalent role), else the Member system role.
func (o *op) defaultRole(ctx context.Context) (string, error) {
	st, err := o.q.GetOrgSSOSettingsForSCIM(ctx, o.c.OrgID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("scim: org sso settings: %w", err)
	}
	if err == nil && st.JitDefaultRoleID.Valid {
		r, err := action.RoleForOrg(ctx, o.q, o.c.OrgID, st.JitDefaultRoleID.String)
		switch {
		case err == nil && !action.OwnerEquivalent(r):
			return r.ID, nil
		case err != nil && !errors.Is(err, action.ErrMappingRole):
			return "", err
		}
	}
	r, err := action.RoleForOrg(ctx, o.q, o.c.OrgID, memberRoleID)
	if err != nil {
		return "", fmt.Errorf("scim: member role: %w", err)
	}
	return r.ID, nil
}

// syncUser reconciles the user's idp memberships from the display names of
// the SCIM groups they are in (SPEC §7.5, org-wide mappings only). Inactive
// or unknown SCIM users are skipped: their memberships are gone.
func (o *op) syncUser(ctx context.Context, userID string) error {
	su, err := o.q.GetSCIMUserByUser(ctx, sqlc.GetSCIMUserByUserParams{OrgID: o.c.OrgID, UserID: userID})
	if errors.Is(err, sql.ErrNoRows) || (err == nil && su.Active == 0) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("scim: scim user lookup: %w", err)
	}
	groups, err := o.q.ListSCIMUserGroupNames(ctx, sqlc.ListSCIMUserGroupNamesParams{OrgID: o.c.OrgID, UserID: userID})
	if err != nil {
		return fmt.Errorf("scim: user groups: %w", err)
	}
	now, _ := time.Parse(timeFormat, o.now)
	res, err := action.ReconcileIdPMemberships(ctx, o.q, action.SyncInput{
		OrgID: o.c.OrgID, UserID: userID, ProviderID: "", Groups: groups,
		Actor: o.c.Actor, IP: o.c.Actor.IP, Now: now,
	})
	if err != nil {
		return err
	}
	o.synced = append(o.synced, res)
	return nil
}

// syncUsers reconciles each user once, in a stable order.
func (o *op) syncUsers(ctx context.Context, users map[string]bool) error {
	ids := make([]string, 0, len(users))
	for id := range users {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if err := o.syncUser(ctx, id); err != nil {
			return err
		}
	}
	return nil
}
