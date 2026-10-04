package action

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// Last-owner protection (WU-613). No path may leave an organisation without
// an owner: an org-level membership of a live user whose role is
// owner-equivalent (OwnerEquivalent: the Owner system role or any role
// granting "*"). Manual paths (membership.delete, member.remove, role.update)
// refuse with ErrLastOwner; automated paths (SCIM deprovisioning, IdP group
// sync) keep the membership and audit membership.last_owner_preserved.

// ErrLastOwner refuses a change that would leave the org without an owner.
var ErrLastOwner = fmt.Errorf("%w: this would leave the organisation without an owner; make someone else an owner first", ErrInvalidInput)

// AuditLastOwnerPreserved is the audit action for a kept owner membership.
const AuditLastOwnerPreserved = "membership.last_owner_preserved"

// OrgOwnerMemberships returns the org's owner-equivalent org-level
// memberships of live users.
func OrgOwnerMemberships(ctx context.Context, q *sqlc.Queries, orgID string) ([]sqlc.ListOrgOwnerCandidatesRow, error) {
	rows, err := q.ListOrgOwnerCandidates(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("org owners: %w", err)
	}
	out := rows[:0]
	for _, m := range rows {
		if OwnerEquivalent(sqlc.Role{ID: m.RoleID, GrantsJson: m.GrantsJson}) {
			out = append(out, m)
		}
	}
	return out, nil
}

// IsLastOwnerMembership reports whether membershipID is the org's only
// owner membership, so removing or demoting it would leave none.
func IsLastOwnerMembership(ctx context.Context, q *sqlc.Queries, orgID, membershipID string) (bool, error) {
	owners, err := OrgOwnerMemberships(ctx, q, orgID)
	if err != nil {
		return false, err
	}
	return len(owners) == 1 && owners[0].ID == membershipID, nil
}

// OwnerGuard checks a manual change against last-owner protection: take it
// before the change and Check after it, inside the same transaction. An org
// that had no owner to begin with is not blocked.
type OwnerGuard struct {
	q   *sqlc.Queries
	org string
	had bool
}

// NewOwnerGuard snapshots whether orgID has an owner.
func NewOwnerGuard(ctx context.Context, q *sqlc.Queries, orgID string) (OwnerGuard, error) {
	owners, err := OrgOwnerMemberships(ctx, q, orgID)
	if err != nil {
		return OwnerGuard{}, err
	}
	return OwnerGuard{q: q, org: orgID, had: len(owners) > 0}, nil
}

// Check returns ErrLastOwner when the org had an owner and now has none.
func (g OwnerGuard) Check(ctx context.Context) error {
	if !g.had {
		return nil
	}
	owners, err := OrgOwnerMemberships(ctx, g.q, g.org)
	if err != nil {
		return err
	}
	if len(owners) == 0 {
		return ErrLastOwner
	}
	return nil
}

// AuditOwnerPreserved writes the membership.last_owner_preserved audit row
// for an automated path that kept an org's last owner membership.
func AuditOwnerPreserved(ctx context.Context, q *sqlc.Queries, orgID, userID, membershipID, via string, actor Actor, now time.Time) error {
	detail, err := json.Marshal(map[string]string{"membership_id": membershipID, "user_id": userID, "via": via})
	if err != nil {
		return err
	}
	if now.IsZero() {
		now = time.Now()
	}
	return q.CreateAuditLog(ctx, sqlc.CreateAuditLogParams{
		ID: newID(), OrgID: sql.NullString{String: orgID, Valid: orgID != ""}, ActorType: string(actor.Type), ActorID: actor.ID,
		Action: AuditLastOwnerPreserved, Subject: userID, DetailJson: string(detail), Ip: actor.IP,
		CreatedAt: now.UTC().Format(timeFormat),
	})
}
