package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
)

func timeIn(secs int) time.Time { return time.Now().Add(time.Duration(secs) * time.Second) }

func TestCSPFreshNoncePerRequest(t *testing.T) {
	var nonces []string
	h := auth.CSP()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonces = append(nonces, auth.Nonce(r.Context()))
		w.WriteHeader(http.StatusOK)
	}))

	nonceRE := regexp.MustCompile(`'nonce-([A-Za-z0-9+/]+)'`)
	get := func() (headerNonce, ctxNonce string) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		csp := rec.Header().Get("Content-Security-Policy")
		if csp == "" {
			t.Fatal("no CSP header set")
		}
		m := nonceRE.FindStringSubmatch(csp)
		if m == nil {
			t.Fatalf("CSP header has no nonce: %q", csp)
		}
		return m[1], nonces[len(nonces)-1]
	}

	h1, c1 := get()
	h2, c2 := get()

	if h1 == h2 {
		t.Error("CSP header nonce identical across requests, want fresh per request")
	}
	// The nonce in the header must equal the nonce placed in the context (the
	// value the layout stamps onto its <script> tags).
	if h1 != c1 || h2 != c2 {
		t.Errorf("header nonce != context nonce: %q/%q, %q/%q", h1, c1, h2, c2)
	}
}

func TestCSPStrictPolicy(t *testing.T) {
	var csp string
	h := auth.CSP()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	csp = rec.Header().Get("Content-Security-Policy")

	for _, want := range []string{"default-src 'self'", "frame-ancestors 'none'", "object-src 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP missing %q; got %q", want, csp)
		}
	}
	// No script-relaxing directives.
	if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
		// unsafe-inline is only forbidden for script-src; assert it's absent
		// entirely since we use nonces for both script and style.
		t.Errorf("CSP must not use unsafe-inline/unsafe-eval; got %q", csp)
	}
	// Companion security headers.
	rh := rec.Header()
	if rh.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing X-Content-Type-Options: nosniff")
	}
	if rh.Get("Referrer-Policy") == "" {
		t.Error("missing Referrer-Policy")
	}
	if rh.Get("X-Frame-Options") != "DENY" {
		t.Error("missing X-Frame-Options: DENY")
	}
}

// mwStack builds the CSP → Session → CSRF chain over a test DB with one user,
// returning the handler, the session store, and the session config used.
func mwStack(t *testing.T, ok http.HandlerFunc) (http.Handler, *auth.SessionStore, auth.SessionConfig) {
	t.Helper()
	d := dbtest.New(t)
	if _, err := d.ExecContext(context.Background(), `INSERT INTO users (id, email) VALUES (?, ?)`, "u1", "u1@example.com"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	store := auth.NewSessionStore(d)
	// Insecure so httptest (plain HTTP) sees the cookie; production keeps Secure.
	sc := auth.SessionConfig{Store: store, Secret: "test-secret", Insecure: true}
	h := auth.CSP()(sc.Session()(sc.CSRF()(ok)))
	return h, store, sc
}

func TestCSRFBlocksMutationWithoutToken(t *testing.T) {
	h, store, _ := mwStack(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	raw, _, err := store.Create(context.Background(), "u1", "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/mutate", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: raw})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("POST without CSRF token: status %d, want 403", rec.Code)
	}
}

func TestCSRFAllowsMutationWithValidToken(t *testing.T) {
	h, store, _ := mwStack(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	raw, sess, err := store.Create(context.Background(), "u1", "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	token := auth.CSRFToken("test-secret", sess.TokenHash)

	req := httptest.NewRequest(http.MethodPost, "/mutate", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: raw})
	req.Header.Set(auth.CSRFHeader, token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("POST with valid CSRF token: status %d, want 200", rec.Code)
	}
}

func TestCSRFRejectsCrossSessionToken(t *testing.T) {
	h, store, _ := mwStack(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	ctx := context.Background()
	rawA, _, err := store.Create(ctx, "u1", "", "")
	if err != nil {
		t.Fatalf("Create A: %v", err)
	}
	_, sessB, err := store.Create(ctx, "u1", "", "")
	if err != nil {
		t.Fatalf("Create B: %v", err)
	}
	// Present session A's cookie but session B's CSRF token.
	req := httptest.NewRequest(http.MethodPost, "/mutate", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: rawA})
	req.Header.Set(auth.CSRFHeader, auth.CSRFToken("test-secret", sessB.TokenHash))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("cross-session CSRF token: status %d, want 403", rec.Code)
	}
}

func TestCSRFExemptsSafeMethods(t *testing.T) {
	h, _, _ := mwStack(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	// GET with no session and no token must pass (reads are exempt).
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("GET status %d, want 200", rec.Code)
	}
}

func TestCSRFMutationWithoutSessionRejected(t *testing.T) {
	h, _, _ := mwStack(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mutate", nil))
	if rec.Code != http.StatusForbidden {
		t.Errorf("POST without session: status %d, want 403", rec.Code)
	}
}

func TestSessionCookieAttributes(t *testing.T) {
	// Production config (Insecure=false) must emit __Host--compatible cookies.
	sc := auth.SessionConfig{Secret: "s"}
	rec := httptest.NewRecorder()
	sc.SetCookie(rec, "rawtoken", timeIn(3600))

	setCookie := rec.Header().Get("Set-Cookie")
	for _, want := range []string{
		auth.CookieName + "=rawtoken",
		"Path=/",
		"HttpOnly",
		"Secure",
		"SameSite=Lax",
	} {
		if !strings.Contains(setCookie, want) {
			t.Errorf("Set-Cookie missing %q; got %q", want, setCookie)
		}
	}
	if strings.Contains(setCookie, "Domain=") {
		t.Errorf("__Host- cookie must not set Domain; got %q", setCookie)
	}
}

func TestSessionMiddlewarePopulatesContext(t *testing.T) {
	var gotSession bool
	var gotCSRF string
	d := dbtest.New(t)
	if _, err := d.ExecContext(context.Background(), `INSERT INTO users (id, email) VALUES (?, ?)`, "u1", "u1@example.com"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	store := auth.NewSessionStore(d)
	sc := auth.SessionConfig{Store: store, Secret: "test-secret", Insecure: true}
	h := sc.Session()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, gotSession = auth.SessionFrom(r.Context())
		gotCSRF = auth.CSRFFrom(r.Context())
	}))

	raw, _, err := store.Create(context.Background(), "u1", "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: raw})
	h.ServeHTTP(httptest.NewRecorder(), req)

	if !gotSession {
		t.Error("session not populated in context")
	}
	if gotCSRF == "" {
		t.Error("CSRF token not populated in context")
	}
}
