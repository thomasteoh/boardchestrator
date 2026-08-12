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
	"github.com/thomasteoh/boardchestrator/internal/tenant"
)

// OAuthHandler provides the HTTP handlers for Google OIDC login.
type OAuthHandler struct {
	Provider       *OIDCProvider
	GitHub         *GitHubProvider
	Store          *SessionStore
	Identity       IdentityStore
	Bootstrap      BootstrapChecker
	BaseURL        string
	SessionCfg     SessionConfig
	AdminEmails    []string
	BootstrapToken string
	// SecretKey is the AES-256 key used to encrypt OAuth tokens at rest
	// (WU-406: GitHub token reuse for wiki edits). Pad via tenant.PadKey.
	SecretKey []byte

	// stateMap stores pending OAuth state nonces (keyed by state, value is
	// the redirect path). A real deployment would use encrypted cookies or
	// the session store; for v1 an in-memory map with cleanup is sufficient.
	stateMap map[string]stateEntry
}

type stateEntry struct {
	nonce     string
	expiresAt time.Time
}

// NewOAuthHandler builds the handler set with Google and GitHub providers.
func NewOAuthHandler(cfg OIDCConfig, ghCfg GitHubConfig, store *SessionStore, d *sql.DB, sc SessionConfig) *OAuthHandler {
	return &OAuthHandler{
		Provider:   NewOIDCProvider(cfg),
		GitHub:     NewGitHubProvider(ghCfg),
		Store:      store,
		Identity:   NewDBIdentityStore(d),
		Bootstrap:  NewDBBootstrapStore(d),
		BaseURL:    cfg.BaseURL,
		SessionCfg: sc,
		stateMap:   make(map[string]stateEntry),
	}
}

// SetBootstrapConfig sets the admin email list and bootstrap token after construction.
func (h *OAuthHandler) SetBootstrapConfig(adminEmails []string, token string) {
	h.AdminEmails = adminEmails
	h.BootstrapToken = token
}

// bootstrapGate checks whether the caller's email is allowed during pre-bootstrap.
// Returns an error response if gated.
func (h *OAuthHandler) bootstrapGate(ctx context.Context, w http.ResponseWriter, email string) bool {
	bootstrapped, err := h.Bootstrap.IsBootstrapped(ctx)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return false
	}
	if bootstrapped {
		return true
	}

	// Token-based bootstrap is handled by WU-103's dedicated token claim page.
	// Here we just check admin email membership.

	for _, ae := range h.AdminEmails {
		if ae == email {
			if err := h.Bootstrap.MarkBootstrapped(ctx); err != nil {
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return false
			}
			return true
		}
	}

	http.Error(w, "forbidden: platform not bootstrapped, and you are not an admin", http.StatusForbidden)
	return false
}

// HandleGoogleLogin redirects the browser to Google's consent page.
func (h *OAuthHandler) HandleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	authURL, state, err := h.Provider.AuthURL()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	h.stateMap[state] = stateEntry{nonce: state, expiresAt: time.Now().Add(15 * time.Minute)}
	http.Redirect(w, r, authURL, http.StatusFound)
}

// HandleGoogleCallback handles the OAuth callback from Google.
func (h *OAuthHandler) HandleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

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

	claims, err := h.Provider.Exchange(ctx, code, state, state)
	if err != nil {
		http.Error(w, "forbidden: authentication failed: "+err.Error(), http.StatusForbidden)
		return
	}

	if !h.bootstrapGate(ctx, w, claims.Email) {
		return
	}

	userID, err := LinkOrCreate(ctx, h.Identity, claims)
	if err != nil {
		http.Error(w, "internal server error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	raw, _, err := h.Store.Create(ctx, userID, r.RemoteAddr, r.UserAgent())
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	h.SessionCfg.SetCookie(w, raw, time.Now().Add(SlidingTTL))
	http.Redirect(w, r, h.BaseURL+"/app", http.StatusSeeOther)
}

// HandleGitHubLogin redirects the browser to GitHub's consent page.
func (h *OAuthHandler) HandleGitHubLogin(w http.ResponseWriter, r *http.Request) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	state := hex.EncodeToString(b)
	h.stateMap[state] = stateEntry{nonce: state, expiresAt: time.Now().Add(15 * time.Minute)}
	http.Redirect(w, r, h.GitHub.AuthURL(state), http.StatusFound)
}

// HandleGitHubCallback handles the OAuth callback from GitHub.
func (h *OAuthHandler) HandleGitHubCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

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

	user, err := h.GitHub.Exchange(ctx, code, state)
	if err != nil {
		http.Error(w, "forbidden: authentication failed: "+err.Error(), http.StatusForbidden)
		return
	}

	if !h.bootstrapGate(ctx, w, user.Email) {
		return
	}

	userID, err := LinkOrCreate(ctx, h.Identity, &GoogleClaims{
		Sub:           fmt.Sprintf("gh-%d", user.ID),
		Email:         user.Email,
		EmailVerified: true,
		Name:          user.Name,
		Picture:       user.Avatar,
	})
	if err != nil {
		http.Error(w, "internal server error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// WU-406: encrypt the OAuth access token at rest so the github.connect
	// action can reuse it (and Phase-5 wiki edits can commit as this user).
	if len(h.SecretKey) == 32 && user.Token != "" {
		enc, err := tenant.Encrypt(h.SecretKey, user.Token)
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		if err := h.Identity.SetIdentityToken(ctx, userID, "github", enc); err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
	}

	raw, _, err := h.Store.Create(ctx, userID, r.RemoteAddr, r.UserAgent())
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	h.SessionCfg.SetCookie(w, raw, time.Now().Add(SlidingTTL))
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

// SetIdentityToken stores an encrypted OAuth token against the user's identity.
func (s *DBIdentityStore) SetIdentityToken(ctx context.Context, userID, provider, tokenEnc string) error {
	return s.q.SetIdentityToken(ctx, sqlc.SetIdentityTokenParams{
		TokenEnc: []byte(tokenEnc),
		UserID:   userID,
		Provider: provider,
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
	// Admin email check is now handled at the OAuthHandler level via the
	// AdminEmails field. This stub satisfies the interface; the real gating
	// logic is in bootstrapGate.
	return false
}

func (s *DBBootstrapStore) MarkBootstrapped(ctx context.Context) error {
	return s.q.SetBootstrapDone(ctx)
}
