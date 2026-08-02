package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// CSRFHeader is the header HTMX sends the token in (wired via hx-headers on
// <body> — SPEC §3, §15).
const CSRFHeader = "X-CSRF-Token"

// CSRFFormField is the fallback field name for non-HTMX form posts.
const CSRFFormField = "csrf_token"

// CSRFToken derives a per-session synchronizer token from the session's stored
// token hash and the server's session secret: token = HMAC-SHA256(secret,
// tokenHash). This binds the CSRF token to the session (a token from one
// session is invalid for another) while remaining stateless — we recompute and
// compare rather than storing a second secret per session. The session token
// itself is never exposed; only its already-hashed form feeds the HMAC.
func CSRFToken(secret, sessionTokenHash string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(sessionTokenHash))
	return hex.EncodeToString(mac.Sum(nil))
}

// ValidCSRF reports whether presented matches the token derived for the
// session, using a constant-time comparison to avoid timing leaks.
func ValidCSRF(secret, sessionTokenHash, presented string) bool {
	if presented == "" {
		return false
	}
	want := CSRFToken(secret, sessionTokenHash)
	return hmac.Equal([]byte(want), []byte(presented))
}
