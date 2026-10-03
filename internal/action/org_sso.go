package action

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// Organisation SSO enforcement (WU-607, SPEC §7.4).

// PlatformOrgID is the sentinel org holding platform-level memberships, and
// PlatformOwnerRoleID the platform Owner role (migration 0005). perm.PlatformOrg
// and perm.PlatformOwnerRole are these values.
const (
	PlatformOrgID       = "00000000000000000000000000000000"
	PlatformOwnerRoleID = "00000000000000000000000000000000"
)

// PermissionOrgSSO gates org.domain.*, org.idp.* and org.sso.* (Owner roles
// hold it through "*").
const PermissionOrgSSO = "org.sso"

// ErrSSORequired refuses a user actor acting in an organisation that
// enforces single sign-on from a session that was not signed in through one
// of the organisation's enabled providers. Providers lists those providers
// in display order (empty when the org has none enabled). It matches
// errors.Is(err, ErrForbidden).
type ErrSSORequired struct {
	OrgID     string
	Providers []string
}

func (e ErrSSORequired) Error() string {
	return fmt.Sprintf("action: organisation %s requires single sign-on", e.OrgID)
}

// Unwrap makes ErrSSORequired a refusal for callers that only check
// ErrForbidden.
func (e ErrSSORequired) Unwrap() error { return ErrForbidden }

// IsPlatformOwner reports whether userID holds the platform Owner role.
func IsPlatformOwner(ctx context.Context, q *sqlc.Queries, userID string) (bool, error) {
	rows, err := q.FindMembershipsForActor(ctx, sqlc.FindMembershipsForActorParams{
		OrgID: PlatformOrgID, ActorType: string(ActorUser), ActorID: userID,
	})
	if err != nil {
		return false, fmt.Errorf("platform owner check: %w", err)
	}
	for _, m := range rows {
		if m.ResourceType == "org" && m.ResourceID == PlatformOrgID &&
			m.RoleID.Valid && m.RoleID.String == PlatformOwnerRoleID {
			return true, nil
		}
	}
	return false, nil
}

// CheckOrgSSO returns ErrSSORequired when orgID enforces SSO and userID, a
// member of orgID, is acting through a session signed in with providerID
// that is not one of the org's enabled providers. Non-members get nil (the
// permission check refuses them without revealing the org's SSO policy), and
// platform owners are exempt (break-glass). Only user actors are subject to
// it; callers must not call it for API keys, agents or services.
func CheckOrgSSO(ctx context.Context, q *sqlc.Queries, orgID, userID, providerID string) error {
	if orgID == "" || userID == "" {
		return nil
	}
	st, err := q.GetOrgSSOSettings(ctx, orgID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("org sso settings: %w", err)
	}
	if st.EnforceSso == 0 {
		return nil
	}
	ids, err := q.ListEnabledOrgAuthProviderIDs(ctx, sql.NullString{String: orgID, Valid: true})
	if err != nil {
		return fmt.Errorf("org sso providers: %w", err)
	}
	for _, id := range ids {
		if providerID != "" && id == providerID {
			return nil
		}
	}
	member, err := q.FindMembershipsForActor(ctx, sqlc.FindMembershipsForActorParams{
		OrgID: orgID, ActorType: string(ActorUser), ActorID: userID,
	})
	if err != nil {
		return fmt.Errorf("org sso membership: %w", err)
	}
	if len(member) == 0 {
		return nil
	}
	if owner, err := IsPlatformOwner(ctx, q, userID); err != nil || owner {
		return err
	}
	return ErrSSORequired{OrgID: orgID, Providers: ids}
}

// checkSSO applies CheckOrgSSO to user actors on org/team/project actions.
func (r *DBScopeResolver) checkSSO(ctx context.Context, ac ActionCtx) error {
	if ac.Actor.Type != ActorUser {
		return nil
	}
	return CheckOrgSSO(ctx, r.q, ac.Org, ac.Actor.ID, ac.Actor.AuthProviderID)
}

// ErrSSOLockout refuses turning enforcement on from a session that would be
// locked out by it.
var ErrSSOLockout = fmt.Errorf("%w: to require single sign-on, first sign in through one of this organisation's enabled identity providers, so you can't lock yourself out", ErrInvalidInput)

// ErrSSONoProvider refuses turning enforcement on with no enabled provider.
var ErrSSONoProvider = fmt.Errorf("%w: add and enable an identity provider for this organisation before requiring single sign-on", ErrInvalidInput)

// OrgSSOView is what org.sso.get and org.sso.update return.
type OrgSSOView struct {
	OrgID      string `json:"org_id"`
	EnforceSSO bool   `json:"enforce_sso"`
}

type orgSSOInput struct {
	OrgID      string `json:"org_id,omitempty"`
	EnforceSSO *bool  `json:"enforce_sso"`
}

func init() {
	for _, def := range []Definition{
		{Name: "org.sso.get", Impact: ImpactRead, Handle: handleOrgSSOGet},
		{Name: "org.sso.update", Impact: ImpactHigh, Handle: handleOrgSSOUpdate},
	} {
		def.Permission = PermissionOrgSSO
		def.Scope = ScopeOrg
		def.Input = FuncSchema(func(raw json.RawMessage) error { return nil })
		Register(def)
	}
}

func handleOrgSSOGet(ctx context.Context, ac ActionCtx, _ json.RawMessage) (any, error) {
	st, err := ac.Tx.GetOrgSSOSettings(ctx, ac.Org)
	if errors.Is(err, sql.ErrNoRows) {
		return OrgSSOView{OrgID: ac.Org}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("org.sso.get: %w", err)
	}
	return OrgSSOView{OrgID: ac.Org, EnforceSSO: st.EnforceSso == 1}, nil
}

// handleOrgSSOUpdate turns enforcement on or off. Turning it on needs an
// enabled org provider and the caller's own session to be signed in through
// one, so nobody can lock themselves (and everyone else) out by mistake.
func handleOrgSSOUpdate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input orgSSOInput
	dec := json.NewDecoder(strings.NewReader(string(in)))
	dec.DisallowUnknownFields()
	if len(in) > 0 {
		if err := dec.Decode(&input); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
		}
	}
	if input.EnforceSSO == nil {
		return nil, fmt.Errorf("%w: enforce_sso is required", ErrInvalidInput)
	}
	on := *input.EnforceSSO
	if on {
		ids, err := ac.Tx.ListEnabledOrgAuthProviderIDs(ctx, sql.NullString{String: ac.Org, Valid: true})
		if err != nil {
			return nil, fmt.Errorf("org.sso.update: providers: %w", err)
		}
		if len(ids) == 0 {
			return nil, ErrSSONoProvider
		}
		ok := false
		for _, id := range ids {
			if ac.Actor.Type == ActorUser && ac.Actor.AuthProviderID != "" && id == ac.Actor.AuthProviderID {
				ok = true
			}
		}
		if !ok {
			return nil, ErrSSOLockout
		}
	}
	v := int64(0)
	if on {
		v = 1
	}
	if err := ac.Tx.SetOrgSSOEnforce(ctx, sqlc.SetOrgSSOEnforceParams{OrgID: ac.Org, EnforceSso: v}); err != nil {
		return nil, fmt.Errorf("org.sso.update: %w", err)
	}
	return OrgSSOView{OrgID: ac.Org, EnforceSSO: on}, nil
}
