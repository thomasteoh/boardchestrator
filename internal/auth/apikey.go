package auth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// context key for API key resolution.
type ctxKeyAPIKey struct{}

// APIKeyActorFrom returns the resolved API-key actor from the request context,
// or false if the request is not authenticated via API key.
func APIKeyActorFrom(ctx context.Context) (action.Actor, bool) {
	v, ok := ctx.Value(ctxKeyAPIKey{}).(action.Actor)
	return v, ok
}

// APIKeyAuthMiddleware returns middleware that checks for a Bearer token and
// resolves it to an API-key actor. It does NOT fail requests without a Bearer
// token — that is the session middleware's domain. When a Bearer token is
// present but invalid, it returns 401.
func APIKeyAuthMiddleware(d *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				next.ServeHTTP(w, r)
				return
			}

			token := strings.TrimPrefix(authHeader, "Bearer ")
			if len(token) < 8 {
				http.Error(w, "invalid API key format", http.StatusUnauthorized)
				return
			}

			prefix := token[:8]
			secretHex := token[8:]

			q := sqlc.New(d)
			key, err := q.FindAPIKeyByPrefix(r.Context(), prefix)
			if err != nil {
				http.Error(w, "invalid or revoked API key", http.StatusUnauthorized)
				return
			}

			// Verify secret.
			secret, err := hex.DecodeString(secretHex)
			if err != nil || len(secret) != 32 {
				http.Error(w, "invalid API key format", http.StatusUnauthorized)
				return
			}
			hash := sha256.Sum256(secret)
			if hex.EncodeToString(hash[:]) != key.Hash {
				http.Error(w, "invalid API key", http.StatusUnauthorized)
				return
			}

			// Build actor with scope intersection.
			actor := action.Actor{
				Type:        action.ActorAPIKey,
				ID:          key.ID,
				OwnerUserID: key.UserID,
				IP:          extractIP(r),
			}

			r = r.WithContext(context.WithValue(r.Context(), ctxKeyAPIKey{}, actor))

			// Touch last_used_at best-effort.
			_ = q.TouchAPIKey(r.Context(), key.ID)

			next.ServeHTTP(w, r)
		})
	}
}

// extractIP extracts the client IP from the request.
func extractIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		if idx := strings.Index(fwd, ","); idx > 0 {
			return strings.TrimSpace(fwd[:idx])
		}
		return strings.TrimSpace(fwd)
	}
	return r.RemoteAddr
}
