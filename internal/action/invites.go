package action

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// --- Invite action definitions (WU-106) ---

type memberInviteInput struct {
	OrgID        string `json:"org_id"`
	Email        string `json:"email"`
	RoleID       string `json:"role_id"`
	ResourceType string `json:"resource_type"` // org | team | project
	ResourceID   string `json:"resource_id"`
}

type memberRemoveInput struct {
	OrgID        string `json:"org_id"`
	ActorID      string `json:"actor_id"`
	ActorType    string `json:"actor_type"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
}

type inviteAcceptInput struct {
	Token string `json:"token"`
}

type inviteListInput struct {
	OrgID string `json:"org_id"`
}

// tokenHash generates a SHA-256 hex digest for the invite secret.
func tokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// RegisterInviteActions is exported so cmd/bc/serve.go can ensure the invite action package's init() runs.
func RegisterInviteActions() {}

func init() {
	Register(Definition{
		Name:       "member.invite",
		Impact:     ImpactHigh,
		Permission: "org.permissions",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleMemberInvite,
	})
	Register(Definition{
		Name:       "member.remove",
		Impact:     ImpactHigh,
		Permission: "org.permissions",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleMemberRemove,
	})
	Register(Definition{
		Name:       "invite.accept",
		Impact:     ImpactLow,
		Permission: "",
		Scope:      ScopePlatform,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleInviteAccept,
	})
	Register(Definition{
		Name:       "invite.list",
		Impact:     ImpactRead,
		Permission: "org.read",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleInviteList,
	})
}

func handleMemberInvite(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input memberInviteInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("member.invite: %w", err)
	}
	if input.Email == "" {
		return nil, fmt.Errorf("member.invite: email required")
	}
	if input.ResourceType == "" {
		input.ResourceType = "org"
	}
	if input.ResourceID == "" {
		input.ResourceID = input.OrgID
	}
	if input.RoleID == "" {
		return nil, fmt.Errorf("member.invite: role_id required")
	}

	id := newID()
	token := newID() // random hex token
	hash := tokenHash(token)
	expiresAt := time.Now().UTC().Add(7 * 24 * time.Hour).Format(timeFormat)

	_, err := ac.Tx.CreateInvite(ctx, sqlc.CreateInviteParams{
		ID:           id,
		OrgID:        input.OrgID,
		InviterID:    ac.Actor.ID,
		Email:        input.Email,
		TokenHash:    hash,
		RoleID:       sql.NullString{String: input.RoleID, Valid: input.RoleID != ""},
		ResourceType: input.ResourceType,
		ResourceID:   input.ResourceID,
		ExpiresAt:    expiresAt,
	})
	if err != nil {
		return nil, fmt.Errorf("member.invite: %w", err)
	}
	return map[string]any{
		"id":     id,
		"token":  token,
		"expiry": expiresAt,
	}, nil
}

func handleMemberRemove(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input memberRemoveInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("member.remove: %w", err)
	}
	if err := ac.Tx.DeleteMembership(ctx, sqlc.DeleteMembershipParams{
		OrgID:        input.OrgID,
		ActorID:      input.ActorID,
		ActorType:    input.ActorType,
		ResourceType: input.ResourceType,
		ResourceID:   input.ResourceID,
	}); err != nil {
		return nil, fmt.Errorf("member.remove: %w", err)
	}
	return nil, nil
}

func handleInviteAccept(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input inviteAcceptInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("invite.accept: %w", err)
	}
	hash := tokenHash(input.Token)

	invite, err := ac.Tx.FindInviteByTokenHash(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf("invite.accept: invalid or expired token: %w", err)
	}
	if invite.AcceptedAt.Valid {
		return nil, fmt.Errorf("invite.accept: already accepted")
	}
	expiry, err := time.Parse(timeFormat, invite.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("invite.accept: parse expiry: %w", err)
	}
	if time.Now().UTC().After(expiry) {
		return nil, fmt.Errorf("invite.accept: token expired")
	}

	now := time.Now().UTC().Format(timeFormat)
	_, err = ac.Tx.AcceptInvite(ctx, sqlc.AcceptInviteParams{
		ID:         invite.ID,
		AcceptedAt: sql.NullString{String: now, Valid: true},
	})
	if err != nil {
		return nil, fmt.Errorf("invite.accept: %w", err)
	}

	// Auto-create membership for the accepted invite.
	memID := newID()
	_, err = ac.Tx.CreateMembership(ctx, sqlc.CreateMembershipParams{
		ID:           memID,
		OrgID:        invite.OrgID,
		ActorID:      ac.Actor.ID,
		ActorType:    "user",
		ResourceType: invite.ResourceType,
		ResourceID:   invite.ResourceID,
		RoleID:       invite.RoleID,
	})
	if err != nil {
		return nil, fmt.Errorf("invite.accept: create membership: %w", err)
	}
	return map[string]any{
		"membership_id": memID,
		"org_id":        invite.OrgID,
	}, nil
}

func handleInviteList(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input inviteListInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("invite.list: %w", err)
	}
	now := time.Now().UTC().Format(timeFormat)
	invites, err := ac.Tx.FindPendingInvitesByOrg(ctx, sqlc.FindPendingInvitesByOrgParams{
		OrgID:     input.OrgID,
		ExpiresAt: now,
	})
	if err != nil {
		return nil, fmt.Errorf("invite.list: %w", err)
	}
	return invites, nil
}
