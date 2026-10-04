package action

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// Session lifecycle (WU-613, SPEC §7.10). A user lists and revokes their own
// sessions (ScopeSelf); a platform admin revokes all of one user's sessions.
// Sessions are named by an opaque id derived from the stored token hash, so
// neither the hash nor the token ever reaches a page.

// Action names.
const (
	ActionSessionList         = "session.list"
	ActionSessionRevoke       = "session.revoke"
	ActionSessionRevokeAll    = "session.revoke_all"
	ActionUserSessionsRevoke  = "user.sessions.revoke"
	sessionPublicIDHexLetters = 16
)

// Refusals.
var (
	ErrNoCurrentSession = fmt.Errorf("%w: there is no current session to keep", ErrInvalidInput)
)

// SessionPublicID is a session's opaque id: the first 16 hex digits of
// SHA-256(token_hash). It identifies a session in pages and forms without
// exposing the stored hash.
func SessionPublicID(tokenHash string) string {
	sum := sha256.Sum256([]byte(tokenHash))
	return hex.EncodeToString(sum[:])[:sessionPublicIDHexLetters]
}

// SessionView is one session as session.list returns it.
type SessionView struct {
	ID         string `json:"id"`
	IP         string `json:"ip"`
	UserAgent  string `json:"user_agent"`
	Method     string `json:"method"`
	ProviderID string `json:"provider_id,omitempty"`
	Provider   string `json:"provider,omitempty"`
	CreatedAt  string `json:"created_at"`
	LastSeenAt string `json:"last_seen_at"`
	ExpiresAt  string `json:"expires_at"`
	Current    bool   `json:"current"`
}

type sessionRevokeInput struct {
	ID string `json:"id"`
	// TokenHash is accepted from older clients (the API, never a page).
	TokenHash string `json:"token_hash"`
}

type sessionRevokeAllInput struct {
	// KeepCurrent signs out everywhere else; false signs out everywhere.
	KeepCurrent bool `json:"keep_current"`
}

type userSessionsRevokeInput struct {
	UserID string `json:"user_id"`
}

func init() {
	Register(Definition{
		Name:       ActionSessionList,
		Impact:     ImpactRead,
		Permission: ActionSessionList,
		Scope:      ScopeSelf,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleSessionList,
	})
	Register(Definition{
		Name:       ActionSessionRevoke,
		Impact:     ImpactLow,
		Permission: ActionSessionRevoke,
		Scope:      ScopeSelf,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleSessionRevoke,
	})
	Register(Definition{
		Name:       ActionSessionRevokeAll,
		Impact:     ImpactHigh,
		Permission: ActionSessionRevokeAll,
		Scope:      ScopeSelf,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleSessionRevokeAll,
	})
	Register(Definition{
		Name:          ActionUserSessionsRevoke,
		Impact:        ImpactHigh,
		Permission:    ActionUserSessionsRevoke,
		Scope:         ScopePlatform,
		Input:         strictSchema[userSessionsRevokeInput](),
		Handle:        handleUserSessionsRevoke,
		PrivateResult: true,
	})
}

// sessionMethodLabel names how a session was signed in.
func sessionMethodLabel(method string) string {
	switch method {
	case "oidc":
		return "OpenID Connect"
	case "github":
		return "GitHub"
	case "saml":
		return "SAML"
	case "passkey":
		return "Passkey"
	case "":
		return "Unknown"
	}
	return method
}

// userSessions lists the user's live sessions.
func userSessions(ctx context.Context, q *sqlc.Queries, userID string) ([]sqlc.ListSessionsByUserRow, error) {
	return q.ListSessionsByUser(ctx, sqlc.ListSessionsByUserParams{
		UserID: userID, ExpiresAt: time.Now().UTC().Format(timeFormat),
	})
}

// findSessionHash returns the stored hash of the user's session with the
// given public id ("" when none).
func findSessionHash(ctx context.Context, q *sqlc.Queries, userID, publicID string) (string, error) {
	if len(publicID) != sessionPublicIDHexLetters {
		return "", nil
	}
	rows, err := userSessions(ctx, q, userID)
	if err != nil {
		return "", err
	}
	for _, s := range rows {
		if subtle.ConstantTimeCompare([]byte(SessionPublicID(s.TokenHash)), []byte(publicID)) == 1 {
			return s.TokenHash, nil
		}
	}
	return "", nil
}

func handleSessionList(ctx context.Context, ac ActionCtx, _ json.RawMessage) (any, error) {
	rows, err := userSessions(ctx, ac.Tx.Queries, ac.Actor.ID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ActionSessionList, err)
	}
	out := make([]SessionView, 0, len(rows))
	for _, s := range rows {
		id := SessionPublicID(s.TokenHash)
		provider := s.ProviderName
		if provider == "" && s.ProviderID == "passkey" {
			provider = "Passkey"
		}
		if provider == "" {
			provider = s.ProviderID
		}
		out = append(out, SessionView{
			ID: id, IP: s.Ip, UserAgent: s.Ua, Method: sessionMethodLabel(s.AuthMethod),
			ProviderID: s.ProviderID, Provider: provider,
			CreatedAt: s.CreatedAt, LastSeenAt: s.LastSeenAt, ExpiresAt: s.ExpiresAt,
			Current: ac.Actor.SessionID != "" && id == ac.Actor.SessionID,
		})
	}
	// The current session first, then most recently seen.
	for i := range out {
		if out[i].Current && i > 0 {
			cur := out[i]
			copy(out[1:i+1], out[:i])
			out[0] = cur
			break
		}
	}
	return map[string]any{"sessions": out}, nil
}

func handleSessionRevoke(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input sessionRevokeInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	hash := strings.TrimSpace(input.TokenHash)
	id := strings.TrimSpace(input.ID)
	if hash == "" && id == "" {
		return nil, fmt.Errorf("%w: id required", ErrInvalidInput)
	}
	if hash == "" {
		var err error
		if hash, err = findSessionHash(ctx, ac.Tx.Queries, ac.Actor.ID, id); err != nil {
			return nil, fmt.Errorf("%s: %w", ActionSessionRevoke, err)
		}
		if hash == "" {
			return nil, fmt.Errorf("%s: %w", ActionSessionRevoke, sql.ErrNoRows)
		}
	}
	n, err := ac.Tx.DeleteUserSession(ctx, sqlc.DeleteUserSessionParams{TokenHash: hash, UserID: ac.Actor.ID})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ActionSessionRevoke, err)
	}
	if n == 0 {
		// Another user's session (or none): indistinguishable to the caller.
		return nil, fmt.Errorf("%s: %w", ActionSessionRevoke, sql.ErrNoRows)
	}
	return map[string]any{"id": SessionPublicID(hash), "current": SessionPublicID(hash) == ac.Actor.SessionID}, nil
}

func handleSessionRevokeAll(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input sessionRevokeAllInput
	if len(in) > 0 {
		if err := json.Unmarshal(in, &input); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
		}
	}
	var n int64
	var err error
	if input.KeepCurrent {
		keep, ferr := findSessionHash(ctx, ac.Tx.Queries, ac.Actor.ID, ac.Actor.SessionID)
		if ferr != nil {
			return nil, fmt.Errorf("%s: %w", ActionSessionRevokeAll, ferr)
		}
		if keep == "" {
			return nil, ErrNoCurrentSession
		}
		n, err = ac.Tx.RevokeUserSessionsExcept(ctx, sqlc.RevokeUserSessionsExceptParams{UserID: ac.Actor.ID, TokenHash: keep})
	} else {
		n, err = ac.Tx.RevokeUserSessions(ctx, ac.Actor.ID)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ActionSessionRevokeAll, err)
	}
	return map[string]any{"revoked": n, "kept_current": input.KeepCurrent}, nil
}

func handleUserSessionsRevoke(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input userSessionsRevokeInput
	if err := strictDecode(in, &input); err != nil {
		return nil, err
	}
	uid := strings.TrimSpace(input.UserID)
	if uid == "" {
		return nil, fmt.Errorf("%w: user_id required", ErrInvalidInput)
	}
	if _, err := ac.Tx.GetUser(ctx, uid); err != nil {
		return nil, fmt.Errorf("%s: %w", ActionUserSessionsRevoke, err)
	}
	n, err := ac.Tx.RevokeUserSessions(ctx, uid)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ActionUserSessionsRevoke, err)
	}
	return map[string]any{"id": uid, "user_id": uid, "revoked": n}, nil
}

// RevokeUserProviderSessions ends userID's sessions signed in through
// providerID (identity.unlink, WU-613). One identity per provider per user
// (WU-604), so these are exactly the sessions that identity established.
func RevokeUserProviderSessions(ctx context.Context, q *sqlc.Queries, userID, providerID string) (int64, error) {
	if userID == "" || providerID == "" {
		return 0, nil
	}
	return q.RevokeUserProviderSessions(ctx, sqlc.RevokeUserProviderSessionsParams{UserID: userID, ProviderID: providerID})
}
