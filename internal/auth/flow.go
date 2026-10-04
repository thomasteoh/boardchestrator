package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

// FlowCookieName is the sealed login-flow cookie (SPEC §7.2).
const FlowCookieName = "__Host-bc_flow"

// FlowTTL bounds how long a login flow may take, cookie and payload alike.
const FlowTTL = 10 * time.Minute

// flowKeyInfo is the HKDF info label separating the flow-cookie key from every
// other use of BC_SECRET_KEY.
const flowKeyInfo = "bc-auth-flow"

// Flow intents (SPEC §7.2). IntentLink is issued by the Sign-in methods page
// (WU-604); IntentBootstrap by the /setup claim page (WU-605); the passkey
// intents by the passkey endpoints (WU-612).
const (
	IntentLogin     = "login"
	IntentLink      = "link"
	IntentBootstrap = "bootstrap"
	// Passkey ceremonies (WU-612): usernameless sign-in, adding a passkey
	// while signed in (bound to the session like IntentLink), and creating
	// an account with a passkey from an invite or the bootstrap token.
	IntentPasskeyLogin    = "passkey_login"
	IntentPasskeyRegister = "passkey_register"
	IntentPasskeySignup   = "passkey_signup"
)

// Flow is the per-login state carried in the sealed flow cookie between
// GET /auth/{provider} and its callback. Nothing about a pending login is kept
// server-side.
type Flow struct {
	State           string `json:"st"`
	Nonce           string `json:"no"`
	PKCEVerifier    string `json:"pv"`
	ProviderID      string `json:"p"`
	ReturnTo        string `json:"rt,omitempty"`
	Intent          string `json:"in"`
	LinkSessionHash string `json:"ls,omitempty"`
	// Bootstrap marks a platform claim started from /setup (WU-605);
	// BootstrapHash is the token hash it proved, re-checked against the
	// platform inside the resolution transaction.
	Bootstrap     bool   `json:"bs,omitempty"`
	BootstrapHash string `json:"bh,omitempty"`
	LoginHint     string `json:"lh,omitempty"`
	// InviteToken is the raw invite token when the person arrived through an
	// invite link (WU-604). Possession of it may permit sign-up (SPEC §7.3
	// step 4); resolution re-validates it.
	InviteToken string `json:"iv,omitempty"`
	// SAMLRequestID is the ID of the AuthnRequest a SAML flow sent (WU-610).
	// The ACS accepts only a response InResponseTo it, and a flow carrying it
	// is sealed into a SameSite=None cookie, because the ACS is a cross-site
	// POST from the identity provider (SPEC §7.2).
	SAMLRequestID string `json:"sr,omitempty"`
	// WebAuthn is a passkey ceremony's session data (challenge, RP id, user
	// handle, ...) between its begin and finish endpoints (WU-612).
	WebAuthn json.RawMessage `json:"wa,omitempty"`
	// SignupName and SignupEmail are what a person typed to create an
	// account with a passkey (the email only for a bootstrap claim; an
	// invite supplies its own).
	SignupName  string `json:"sn,omitempty"`
	SignupEmail string `json:"se,omitempty"`
	Exp         int64  `json:"exp"`
}

// sameSite is the flow cookie's SameSite mode: Lax for OIDC/GitHub, whose
// callbacks are top-level GETs, and None only for SAML flows.
func (f *Flow) sameSite() http.SameSite {
	if f.SAMLRequestID != "" {
		return http.SameSiteNoneMode
	}
	return http.SameSiteLaxMode
}

// Flow errors. Callers map all of them to a generic failure response.
var (
	ErrFlowMissing  = errors.New("auth: flow cookie missing")
	ErrFlowInvalid  = errors.New("auth: flow cookie invalid")
	ErrFlowExpired  = errors.New("auth: flow expired")
	ErrFlowMismatch = errors.New("auth: flow does not match callback")
)

// FlowSealer seals and opens Flow payloads with AES-256-GCM under a key
// derived from BC_SECRET_KEY via HKDF-SHA256 (info "bc-auth-flow").
type FlowSealer struct {
	aead cipher.AEAD
	now  func() time.Time
}

// NewFlowSealer derives the flow key from the raw BC_SECRET_KEY value.
func NewFlowSealer(secretKey string) (*FlowSealer, error) {
	if secretKey == "" {
		return nil, errors.New("auth: flow sealer needs BC_SECRET_KEY")
	}
	key, err := hkdf.Key(sha256.New, []byte(secretKey), nil, flowKeyInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("auth: derive flow key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("auth: flow cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("auth: flow gcm: %w", err)
	}
	return &FlowSealer{aead: aead, now: time.Now}, nil
}

// WithClock overrides the sealer's clock; test-only.
func (s *FlowSealer) WithClock(now func() time.Time) *FlowSealer {
	s.now = now
	return s
}

// NewFlow mints a flow for providerID with fresh state, nonce and PKCE
// verifier.
func (s *FlowSealer) NewFlow(providerID, intent string) (*Flow, error) {
	state, err := randomHex(32)
	if err != nil {
		return nil, err
	}
	nonce, err := randomHex(32)
	if err != nil {
		return nil, err
	}
	return &Flow{
		State:        state,
		Nonce:        nonce,
		PKCEVerifier: oauth2.GenerateVerifier(),
		ProviderID:   providerID,
		Intent:       intent,
		Exp:          s.now().Add(FlowTTL).Unix(),
	}, nil
}

// Seal encrypts f into a cookie-safe string. The cookie name is bound as
// associated data so the ciphertext cannot be replayed under another name.
func (s *FlowSealer) Seal(f *Flow) (string, error) {
	return s.sealAs(FlowCookieName, f)
}

// sealAs seals v as JSON with the cookie name as associated data.
func (s *FlowSealer) sealAs(name string, v any) (string, error) {
	pt, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("auth: marshal %s: %w", name, err)
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("auth: seal nonce: %w", err)
	}
	ct := s.aead.Seal(nonce, nonce, pt, []byte(name))
	return base64.RawURLEncoding.EncodeToString(ct), nil
}

// openAs reverses sealAs for the same cookie name.
func (s *FlowSealer) openAs(name, v string, out any) error {
	raw, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil || len(raw) < s.aead.NonceSize() {
		return ErrFlowInvalid
	}
	ns := s.aead.NonceSize()
	pt, err := s.aead.Open(nil, raw[:ns], raw[ns:], []byte(name))
	if err != nil {
		return ErrFlowInvalid
	}
	if err := json.Unmarshal(pt, out); err != nil {
		return ErrFlowInvalid
	}
	return nil
}

// Open decrypts and validates a sealed flow, rejecting expired payloads.
func (s *FlowSealer) Open(v string) (*Flow, error) {
	var f Flow
	if err := s.openAs(FlowCookieName, v, &f); err != nil {
		return nil, err
	}
	if s.now().Unix() >= f.Exp {
		return nil, ErrFlowExpired
	}
	return &f, nil
}

// SetCookie seals f into the __Host-bc_flow cookie. SameSite=Lax suits
// OIDC/GitHub, whose callbacks are top-level GETs; a SAML flow's cookie is
// SameSite=None so the identity provider's cross-site POST to the ACS
// carries it (Secure is always set, which None requires).
func (s *FlowSealer) SetCookie(w http.ResponseWriter, f *Flow) error {
	v, err := s.Seal(f)
	if err != nil {
		return err
	}
	// gosec G124: SameSite is None only for SAML flows, which SPEC §7.2
	// requires (the ACS is a cross-site POST); Secure and HttpOnly are fixed.
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: SameSite=None for SAML flows by design, see above
		Name:     FlowCookieName,
		Value:    v,
		Path:     "/",
		MaxAge:   int(FlowTTL / time.Second),
		HttpOnly: true,
		Secure:   true,
		SameSite: f.sameSite(),
	})
	return nil
}

// ClearFlowCookie expires the flow cookie. Called on every callback outcome.
func ClearFlowCookie(w http.ResponseWriter) {
	clearFlowCookie(w, http.SameSiteLaxMode)
}

// clearFlowCookie expires the flow cookie with the given SameSite mode (the
// SAML ACS answers a cross-site POST, so it clears with None).
func clearFlowCookie(w http.ResponseWriter, mode http.SameSite) {
	// An expiring cookie; mode is Lax or (at the SAML ACS) None.
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: deletion cookie, SameSite=None only at the SAML ACS

		Name:     FlowCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: mode,
	})
}

// FromRequest opens the flow cookie on r.
func (s *FlowSealer) FromRequest(r *http.Request) (*Flow, error) {
	ck, err := r.Cookie(FlowCookieName)
	if err != nil || ck.Value == "" {
		return nil, ErrFlowMissing
	}
	return s.Open(ck.Value)
}

// Matches checks the callback's provider id and state against the flow, with
// a constant-time state comparison.
func (f *Flow) Matches(providerID, state string) error {
	if f.ProviderID != providerID {
		return ErrFlowMismatch
	}
	if state == "" || subtle.ConstantTimeCompare([]byte(f.State), []byte(state)) != 1 {
		return ErrFlowMismatch
	}
	return nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: random: %w", err)
	}
	return hex.EncodeToString(b), nil
}
