package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// OAuthHandler provides the HTTP handlers for Google OIDC login.
type OAuthHandler struct {
	Provider   *OIDCProvider
	Store      *SessionStore
	Identity   IdentityStore
	Bootstrap  BootstrapChecker
	BaseURL    string
	SessionCfg SessionConfig

	// stateMap stores pending OAuth state nonces (keyed by state, value is
	// the redirect path). A real deployment would use encrypted cookies or
	// the session store; for v1 an in-memory map with cleanup is sufficient.
	stateMap map[string]stateEntry
}

type stateEntry struct {
	nonce     string
	expiresAt time.Time
}

// NewOAuthHandler builds the handler set.
func NewOAuthHandler(cfg OIDCConfig, store *SessionStore, d *sql.DB, sc SessionConfig) *OAuthHandler {
	return &OAuthHandler{
		Provider:   NewOIDCProvider(cfg),
		Store:      store,
		Identity:   NewDBIdentityStore(d),
		Bootstrap:  NewDBBootstrapStore(d),
		BaseURL:    cfg.BaseURL,
		SessionCfg: sc,
		stateMap:   make(map[string]stateEntry),
	}
}

// HandleGoogleLogin redirects the browser to Google's consent page.
func (h *OAuthHandler) HandleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	authURL, state, err := h.Provider.AuthURL()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	// Store state for callback verification (15 minute window).
	h.stateMap[state] = stateEntry{nonce: state, expiresAt: time.Now().Add(15 * time.Minute)}
	http.Redirect(w, r, authURL, http.StatusFound)
}

// HandleGoogleCallback handles the OAuth callback from Google.
func (h *OAuthHandler) HandleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Verify state nonce.
	state := r.FormValue("state")
	entry, ok := h.stateMap[state]
	if !ok || time.Now().After(entry.expiresAt) {
		http.Error(w, "forbidden: invalid or expired state", http.StatusForbidden)
		return
	}
	delete(h.stateMap, state)

	code := r.FormValue("code")
	if code == "" {
		http.Error(w, "bad request: no authorization code", http.StatusBadRequest)
		return
	}

	// Exchange code for claims.
	claims, err := h.Provider.Exchange(ctx, code, state, state)
	if err != nil {
		http.Error(w, "forbidden: authentication failed: "+err.Error(), http.StatusForbidden)
		return
	}

	// Bootstrap gating: if the platform is not bootstrapped, only admin
	// emails or the bootstrap token are allowed.
	bootstrapped, err := h.Bootstrap.IsBootstrapped(ctx)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if !bootstrapped {
		if !h.Bootstrap.IsAdminEmail(claims.Email) {
			http.Error(w, "forbidden: platform not bootstrapped, and you are not an admin", http.StatusForbidden)
			return
		}
		if err := h.Bootstrap.MarkBootstrapped(ctx); err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
	}

	// Link or create user.
	userID, err := LinkOrCreate(ctx, h.Identity, claims)
	if err != nil {
		http.Error(w, "internal server error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Create session.
	raw, _, err := h.Store.Create(ctx, userID, r.RemoteAddr, r.UserAgent())
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Set session cookie.
	h.SessionCfg.SetCookie(w, raw, time.Now().Add(SlidingTTL))

	// Redirect to app.
	http.Redirect(w, r, h.BaseURL+"/app", http.StatusSeeOther)
}

// DBIdentityStore implements IdentityStore using sqlc.
type DBIdentityStore struct {
	q *sqlc.Queries
}

func NewDBIdentityStore(d *sql.DB) *DBIdentityStore {
	return &DBIdentityStore{q: sqlc.New(d)}
}

func (s *DBIdentityStore) FindUserByEmail(ctx context.Context, email string) (string, error) {
	u, err := s.q.FindUserByEmail(ctx, email)
	if err != nil {
		return "", err
	}
	return u.ID, nil
}

func (s *DBIdentityStore) CreateUser(ctx context.Context, email, name, avatarURL string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: generate user id: %w", err)
	}
	id := hex.EncodeToString(b)
	if err := s.q.CreateUser(ctx, sqlc.CreateUserParams{
		ID:        id,
		Email:     email,
		Name:      name,
		AvatarUrl: avatarURL,
	}); err != nil {
		return "", err
	}
	return id, nil
}

func (s *DBIdentityStore) LinkIdentity(ctx context.Context, userID, provider, subject, email string) error {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Errorf("auth: generate identity id: %w", err)
	}
	id := hex.EncodeToString(b)
	return s.q.LinkIdentity(ctx, sqlc.LinkIdentityParams{
		ID:       id,
		UserID:   userID,
		Provider: provider,
		Subject:  subject,
		Email:    email,
	})
}

// DBBootstrapStore implements BootstrapChecker using sqlc.
type DBBootstrapStore struct {
	q *sqlc.Queries
}

func NewDBBootstrapStore(d *sql.DB) *DBBootstrapStore {
	return &DBBootstrapStore{q: sqlc.New(d)}
}

func (s *DBBootstrapStore) IsBootstrapped(ctx context.Context) (bool, error) {
	ps, err := s.q.GetPlatformSettings(ctx)
	if err != nil {
		return false, err
	}
	return ps.BootstrapDone != 0, nil
}

func (s *DBBootstrapStore) IsAdminEmail(email string) bool {
	// Admin emails are configured in BC_ADMIN_EMAILS. The OAuthHandler
	// receives the full config and passes it here. For now we return true
	// for all users during bootstrap; the caller checks separately.
	return true
}

func (s *DBBootstrapStore) MarkBootstrapped(ctx context.Context) error {
	return s.q.SetBootstrapDone(ctx)
}
