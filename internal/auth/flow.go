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
// (WU-604); IntentBootstrap arrives with WU-605.
const (
	IntentLogin     = "login"
	IntentLink      = "link"
	IntentBootstrap = "bootstrap"
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
	Bootstrap       bool   `json:"bs,omitempty"`
	LoginHint       string `json:"lh,omitempty"`
	// InviteToken is the raw invite token when the person arrived through an
	// invite link (WU-604). Possession of it may permit sign-up (SPEC §7.3
	// step 4); resolution re-validates it.
	InviteToken string `json:"iv,omitempty"`
	Exp         int64  `json:"exp"`
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
	pt, err := json.Marshal(f)
	if err != nil {
		return "", fmt.Errorf("auth: marshal flow: %w", err)
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("auth: flow nonce: %w", err)
	}
	ct := s.aead.Seal(nonce, nonce, pt, []byte(FlowCookieName))
	return base64.RawURLEncoding.EncodeToString(ct), nil
}

// Open decrypts and validates a sealed flow, rejecting expired payloads.
func (s *FlowSealer) Open(v string) (*Flow, error) {
	raw, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil || len(raw) < s.aead.NonceSize() {
		return nil, ErrFlowInvalid
	}
	ns := s.aead.NonceSize()
	pt, err := s.aead.Open(nil, raw[:ns], raw[ns:], []byte(FlowCookieName))
	if err != nil {
		return nil, ErrFlowInvalid
	}
	var f Flow
	if err := json.Unmarshal(pt, &f); err != nil {
		return nil, ErrFlowInvalid
	}
	if s.now().Unix() >= f.Exp {
		return nil, ErrFlowExpired
	}
	return &f, nil
}

// SetCookie seals f into the __Host-bc_flow cookie. SameSite=Lax suits
// OIDC/GitHub, whose callbacks are top-level GETs.
func (s *FlowSealer) SetCookie(w http.ResponseWriter, f *Flow) error {
	v, err := s.Seal(f)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     FlowCookieName,
		Value:    v,
		Path:     "/",
		MaxAge:   int(FlowTTL / time.Second),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

// ClearFlowCookie expires the flow cookie. Called on every callback outcome.
func ClearFlowCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     FlowCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
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
