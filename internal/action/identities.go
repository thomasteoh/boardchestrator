package action

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// Sign-in method actions (WU-604, SPEC §7.3, PRD §4 "Account linking").
// Linking happens in the login flow (auth.Resolve); these list and unlink the
// caller's own identities. Both are ScopeSelf: they only ever touch rows of
// ac.Actor.ID.

// ErrLastSignInMethod refuses removing a user's only way to sign in.
var ErrLastSignInMethod = fmt.Errorf("%w: you can't remove your only sign-in method", ErrInvalidInput)

// SignInMethodCount is the number of ways userID can sign in. It is the one
// place that knows what counts as a sign-in method: linked identities, plus
// passkeys while the platform has them turned on (a passkey nobody can use
// must not keep a user's last identity from counting as the last).
func SignInMethodCount(ctx context.Context, q *sqlc.Queries, userID string) (int64, error) {
	n, err := q.CountUserIdentities(ctx, userID)
	if err != nil {
		return 0, fmt.Errorf("count identities: %w", err)
	}
	on, err := PasskeysEnabled(ctx, q)
	if err != nil {
		return 0, err
	}
	if on {
		p, err := q.CountUserWebAuthnCredentials(ctx, userID)
		if err != nil {
			return 0, fmt.Errorf("count passkeys: %w", err)
		}
		n += p
	}
	return n, nil
}

// IdentityView is one linked identity as identity.list returns it. It never
// carries the subject or any token.
type IdentityView struct {
	ID          string `json:"id"`
	Provider    string `json:"provider"`
	DisplayName string `json:"display_name"`
	Email       string `json:"email"`
	LastLoginAt string `json:"last_login_at,omitempty"`
	CreatedAt   string `json:"created_at,omitempty"`
}

type identityListInput struct {
	UserID string `json:"user_id"`
}

type identityUnlinkInput struct {
	ID     string `json:"id"`
	UserID string `json:"user_id"`
}

func init() {
	Register(Definition{
		Name:       "identity.list",
		Impact:     ImpactRead,
		Permission: "identity.list",
		Scope:      ScopeSelf,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleIdentityList,
	})
	Register(Definition{
		Name:       "identity.unlink",
		Impact:     ImpactHigh,
		Permission: "identity.unlink",
		Scope:      ScopeSelf,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleIdentityUnlink,
	})
}

func handleIdentityList(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input identityListInput
	if len(in) > 0 {
		if err := json.Unmarshal(in, &input); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
		}
	}
	uid, err := SelfUserID(ac, input.UserID)
	if err != nil {
		return nil, err
	}
	rows, err := ac.Tx.ListSignInIdentities(ctx, uid)
	if err != nil {
		return nil, fmt.Errorf("identity.list: %w", err)
	}
	out := make([]IdentityView, 0, len(rows))
	for _, r := range rows {
		name := r.DisplayName
		if name == "" {
			name = r.Provider // provider row deleted or never existed
		}
		out = append(out, IdentityView{
			ID: r.ID, Provider: r.Provider, DisplayName: name, Email: r.Email,
			LastLoginAt: r.LastLoginAt.String, CreatedAt: r.CreatedAt.String,
		})
	}
	return map[string]any{"identities": out}, nil
}

func handleIdentityUnlink(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input identityUnlinkInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	uid, err := SelfUserID(ac, input.UserID)
	if err != nil {
		return nil, err
	}
	if input.ID == "" {
		return nil, fmt.Errorf("%w: id required", ErrInvalidInput)
	}
	ident, err := ac.Tx.FindUserIdentity(ctx, sqlc.FindUserIdentityParams{ID: input.ID, UserID: uid})
	if errors.Is(err, sql.ErrNoRows) {
		// Another user's identity (or none): indistinguishable to the caller.
		return nil, fmt.Errorf("identity.unlink: %w", sql.ErrNoRows)
	}
	if err != nil {
		return nil, fmt.Errorf("identity.unlink: %w", err)
	}
	if _, err := ac.Tx.DeleteUserIdentity(ctx, sqlc.DeleteUserIdentityParams{ID: ident.ID, UserID: uid}); err != nil {
		return nil, fmt.Errorf("identity.unlink: %w", err)
	}
	// Counted after the delete, inside the transaction, so two concurrent
	// unlinks cannot both pass a "more than one left" check.
	left, err := SignInMethodCount(ctx, ac.Tx.Queries, uid)
	if err != nil {
		return nil, fmt.Errorf("identity.unlink: %w", err)
	}
	if left < 1 {
		return nil, ErrLastSignInMethod
	}
	detail, err := json.Marshal(map[string]string{"provider": ident.Provider, "identity_id": ident.ID})
	if err != nil {
		return nil, fmt.Errorf("identity.unlink: %w", err)
	}
	if err := ac.Tx.CreateAuditLog(ctx, sqlc.CreateAuditLogParams{
		ID:         newID(),
		ActorType:  string(ac.Actor.Type),
		ActorID:    uid,
		Action:     "identity.unlinked",
		Subject:    ident.Provider,
		DetailJson: string(detail),
		Ip:         ac.Actor.IP,
		CreatedAt:  time.Now().UTC().Format(timeFormat),
	}); err != nil {
		return nil, fmt.Errorf("identity.unlink: audit: %w", err)
	}
	return map[string]string{"id": ident.ID, "provider": ident.Provider}, nil
}
