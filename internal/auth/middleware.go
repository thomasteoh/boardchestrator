package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"time"
)

// context keys for values the middleware stashes per request.
type (
	ctxKeyNonce   struct{}
	ctxKeySession struct{}
	ctxKeyCSRF    struct{}
)

// Nonce returns the per-request CSP nonce, or "" if the CSP middleware did not
// run for this request.
func Nonce(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyNonce{}).(string); ok {
		return v
	}
	return ""
}

// SessionFrom returns the resolved session for the request, or false if the
// request is unauthenticated.
func SessionFrom(ctx context.Context) (Session, bool) {
	v, ok := ctx.Value(ctxKeySession{}).(Session)
	return v, ok
}

// CSRFFrom returns the CSRF token minted for the request (empty for
// unauthenticated requests, which cannot mutate anyway).
func CSRFFrom(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyCSRF{}).(string); ok {
		return v
	}
	return ""
}

// nonceBytes is the CSP nonce size (128 bits, per WU-004's placeholder shape).
const nonceBytes = 16

func newNonce() string {
	b := make([]byte, nonceBytes)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand.Read is documented never to fail on supported platforms;
		// the branch exists only to satisfy errcheck honestly.
		panic("auth: crypto/rand unavailable: " + err.Error())
	}
	return base64.RawStdEncoding.EncodeToString(b)
}

// CSP returns middleware that mints a fresh nonce per request, stashes it in
// the context (read by the web handler into Shell.Nonce), and sets a strict
// nonce-based Content-Security-Policy plus the companion security headers
// mandated by SPEC §15.
//
// The policy is nonce-based with default-src 'self' and no unsafe-eval /
// unsafe-inline for scripts: the sole inline script (the theme bootstrap in
// layout.templ) is nonced and thus allowed by 'nonce-<v>'. Styles: we allow
// 'self' plus a per-request nonce; the layout carries no inline <style>, so
// this is headroom, not a relaxation (any future inline style must be nonced).
func CSP() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nonce := newNonce()
			h := w.Header()
			h.Set("Content-Security-Policy", cspPolicy(nonce))
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("Referrer-Policy", "no-referrer")
			// frame-ancestors 'none' is in the CSP; X-Frame-Options covers
			// legacy browsers that ignore it.
			h.Set("X-Frame-Options", "DENY")
			ctx := context.WithValue(r.Context(), ctxKeyNonce{}, nonce)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func cspPolicy(nonce string) string {
	// connect-src includes 'self' so HTMX and the SSE EventSource (WU-007) work
	// without widening default-src. img-src allows data: for inline SVG/theme
	// glyphs. No unsafe-inline / unsafe-eval anywhere for scripts.
	return "default-src 'self'; " +
		"base-uri 'self'; " +
		"frame-ancestors 'none'; " +
		"object-src 'none'; " +
		"script-src 'self' 'nonce-" + nonce + "'; " +
		"style-src 'self' 'nonce-" + nonce + "'; " +
		"img-src 'self' data:; " +
		"font-src 'self'; " +
		"connect-src 'self'; " +
		"form-action 'self'"
}

// SessionConfig configures the session and CSRF middleware.
type SessionConfig struct {
	Store  *SessionStore
	Secret string // BC_SESSION_SECRET, used to derive CSRF tokens

	// Insecure drops the Secure cookie attribute. Production MUST leave this
	// false so the __Host- prefix requirement holds. It exists only so tests
	// can exercise the middleware over plain HTTP (httptest.NewServer is not
	// TLS); it is never set from config in serve paths.
	Insecure bool
}

// Session returns middleware that resolves the session cookie into the request
// context, slides its expiry, re-sets the sliding cookie, and mints the CSRF
// token for the session. Unauthenticated requests pass through with no session.
func (c SessionConfig) Session() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			if ck, err := r.Cookie(CookieName); err == nil {
				sess, lookErr := c.Store.Lookup(ctx, ck.Value)
				if lookErr == nil {
					ctx = context.WithValue(ctx, ctxKeySession{}, sess)
					ctx = context.WithValue(ctx, ctxKeyCSRF{}, CSRFToken(c.Secret, sess.TokenHash))
					// Re-set the cookie so the sliding expiry reaches the client.
					c.SetCookie(w, ck.Value, sess.ExpiresAt)
				} else {
					// Invalid/expired token: clear the stale cookie.
					c.ClearCookie(w)
				}
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// safeMethod reports whether m is a read-only method exempt from CSRF checks.
func safeMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}

// CSRF returns middleware that rejects state-changing requests
// (POST/PUT/PATCH/DELETE) lacking a valid per-session CSRF token. The token is
// accepted from the X-CSRF-Token header (HTMX) or the csrf_token form field.
// Must run after Session so the session is resolved.
func (c SessionConfig) CSRF() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if safeMethod(r.Method) {
				next.ServeHTTP(w, r)
				return
			}
			sess, ok := SessionFrom(r.Context())
			if !ok {
				// No session ⇒ nothing to protect against, but a mutating call
				// without a session has no authority anyway; reject uniformly.
				http.Error(w, "forbidden: no session", http.StatusForbidden)
				return
			}
			presented := r.Header.Get(CSRFHeader)
			if presented == "" {
				presented = r.PostFormValue(CSRFFormField)
			}
			if !ValidCSRF(c.Secret, sess.TokenHash, presented) {
				http.Error(w, "forbidden: invalid CSRF token", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// SetCookie writes the session cookie with the production-grade attributes
// (SPEC §7, §15): __Host- prefix, Secure, HttpOnly, SameSite=Lax, Path=/, no
// Domain. Secure is dropped only when Insecure is set (test seam).
func (c SessionConfig) SetCookie(w http.ResponseWriter, raw string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    raw,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   !c.Insecure,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearCookie expires the session cookie on the client.
func (c SessionConfig) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   !c.Insecure,
		SameSite: http.SameSiteLaxMode,
	})
}
