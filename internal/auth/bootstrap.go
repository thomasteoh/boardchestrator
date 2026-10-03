package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// SetupURL is the bootstrap claim page (SPEC §7.3 step 5).
const SetupURL = "/setup"

// SetupCookieName carries proof, between GET /setup and GET /auth/{id}, that
// this browser presented the bootstrap token. Sealed like the flow cookie.
const SetupCookieName = "__Host-bc_setup"

// setupTTL bounds how long the claim page's buttons stay usable.
const setupTTL = 30 * time.Minute

// maxBootstrapTokenLen bounds a presented token.
const maxBootstrapTokenLen = 256

// Bootstrap is the platform-claim token (SPEC §7.3 step 5). While the
// platform is unclaimed, whoever presents it at /setup?token= may sign in
// through any platform provider and becomes the platform owner.
//
// The token is BC_BOOTSTRAP_TOKEN when set. Otherwise, if BC_ADMIN_EMAILS
// is empty too, Prepare generates one at startup and stores only its
// SHA-256 in platform_settings.settings_json, so a fresh install is never
// claimable by the first random visitor yet always claimable by whoever can
// read the server log.
type Bootstrap struct {
	DB          *sql.DB
	EnvToken    string
	AdminEmails []string
}

// TokenHash is the hex SHA-256 of a bootstrap token, the form it is compared
// (and, when generated, stored) in.
func TokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Prepare runs at startup. On an unclaimed platform it returns the claim URL
// to announce: the env token's, or a freshly generated token's (replacing
// any earlier generated hash, so only the latest logged URL works). It
// returns "" when the platform is claimed or only BC_ADMIN_EMAILS can claim
// it.
func (b *Bootstrap) Prepare(ctx context.Context, baseURL string) (string, error) {
	q := sqlc.New(b.DB)
	ps, err := q.GetPlatformSettings(ctx)
	if err != nil {
		return "", fmt.Errorf("auth: platform settings: %w", err)
	}
	if ps.BootstrapDone != 0 {
		return "", nil
	}
	token := b.EnvToken
	if token == "" {
		if hasAdminEmail(b.AdminEmails) {
			return "", nil
		}
		if token, err = randomHex(32); err != nil {
			return "", err
		}
		n, err := q.SetBootstrapTokenHash(ctx, TokenHash(token))
		if err != nil {
			return "", fmt.Errorf("auth: store bootstrap token hash: %w", err)
		}
		if n == 0 {
			return "", nil // claimed in the meantime
		}
	}
	return strings.TrimRight(baseURL, "/") + SetupURL + "?token=" + url.QueryEscape(token), nil
}

func hasAdminEmail(list []string) bool {
	for _, e := range list {
		if strings.TrimSpace(e) != "" {
			return true
		}
	}
	return false
}

// expectedHash is the hash a presented token must match: the env token's
// when set (a generated hash left from an earlier start no longer counts),
// else the stored generated one ("" = no token can claim).
func (b *Bootstrap) expectedHash(ps sqlc.PlatformSetting) string {
	if b.EnvToken != "" {
		return TokenHash(b.EnvToken)
	}
	var s struct {
		Hash string `json:"bootstrap_token_hash"`
	}
	if err := json.Unmarshal([]byte(ps.SettingsJson), &s); err != nil {
		return ""
	}
	return s.Hash
}

// claims reports, in constant time, whether tokenHash claims the platform
// described by ps. Always false once bootstrapped.
func (b *Bootstrap) claims(ps sqlc.PlatformSetting, tokenHash string) bool {
	if b == nil || ps.BootstrapDone != 0 || tokenHash == "" {
		return false
	}
	want := b.expectedHash(ps)
	if want == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(want), []byte(tokenHash)) == 1
}

// Valid reports whether tokenHash currently claims the platform.
func (b *Bootstrap) Valid(ctx context.Context, tokenHash string) (bool, error) {
	if b == nil || b.DB == nil {
		return false, nil
	}
	ps, err := sqlc.New(b.DB).GetPlatformSettings(ctx)
	if err != nil {
		return false, fmt.Errorf("auth: platform settings: %w", err)
	}
	return b.claims(ps, tokenHash), nil
}

// setupProof is the sealed payload of the setup cookie.
type setupProof struct {
	Hash string `json:"h"`
	Exp  int64  `json:"exp"`
}

// setSetupCookie records that this browser presented tokenHash.
func (s *FlowSealer) setSetupCookie(w http.ResponseWriter, tokenHash string) error {
	v, err := s.sealAs(SetupCookieName, setupProof{Hash: tokenHash, Exp: s.now().Add(setupTTL).Unix()})
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name: SetupCookieName, Value: v, Path: "/", MaxAge: int(setupTTL / time.Second),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	return nil
}

// setupHash is the token hash proven by r's setup cookie ("" = none).
func (s *FlowSealer) setupHash(r *http.Request) string {
	ck, err := r.Cookie(SetupCookieName)
	if err != nil || ck.Value == "" {
		return ""
	}
	var p setupProof
	if err := s.openAs(SetupCookieName, ck.Value, &p); err != nil || s.now().Unix() >= p.Exp {
		return ""
	}
	return p.Hash
}

func clearSetupCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: SetupCookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
}

// SetupPageHandler renders the "Claim this instance" page after a valid
// token. The server overrides it with the templ page, which lists the
// platform providers linking to /auth/{id}?bootstrap=1.
var SetupPageHandler = func(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = fmt.Fprintln(w, "Claim this instance: sign in with a provider via /auth/{id}?bootstrap=1")
}

// NotFoundHandler answers /setup for a wrong token or a claimed platform,
// exactly as for any unknown page. The server overrides it with its 404.
var NotFoundHandler = http.NotFound

// Setup is GET /setup?token= (SPEC §7.3 step 5). A token that claims the
// unclaimed platform gets the claim page and a setup cookie; anything else
// (wrong, missing, already bootstrapped, lookup failure) gets the same 404
// as an unknown page, so the route is no oracle.
func (h *Handler) Setup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	// The token is in this URL; never let it leave in a Referer.
	w.Header().Set("Referrer-Policy", "no-referrer")
	tok := r.URL.Query().Get("token")
	if tok == "" || len(tok) > maxBootstrapTokenLen {
		NotFoundHandler(w, r)
		return
	}
	hash := TokenHash(tok)
	ok, err := h.Resolver.Bootstrap.Valid(r.Context(), hash)
	if err != nil {
		reqID := ""
		if h.RequestID != nil {
			reqID = h.RequestID(r.Context())
		}
		slog.Warn("auth: setup token check", "req_id", reqID, "err", err)
	}
	if !ok {
		NotFoundHandler(w, r)
		return
	}
	if err := h.Flows.setSetupCookie(w, hash); err != nil {
		h.fail(w, r, http.StatusInternalServerError, "", "setup_seal", err)
		return
	}
	SetupPageHandler(w, r)
}
