package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/thomasteoh/boardchestrator/internal/auth"
)

// newTestRouter mounts the web routes behind the CSP middleware, which is the
// per-request source of Shell.Nonce (WU-005). Without it the app shell renders
// with an empty nonce, so the shell tests must exercise the real middleware.
func newTestRouter() http.Handler {
	r := chi.NewRouter()
	r.Use(auth.CSP())
	Routes(r)
	return r
}

func TestAppShellServed(t *testing.T) {
	rec := httptest.NewRecorder()
	newTestRouter().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/app", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /app: status %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	body, _ := io.ReadAll(rec.Body)
	html := string(body)

	if !strings.Contains(html, `aria-label="Primary"`) {
		t.Error("shell missing primary nav")
	}
	if !regexp.MustCompile(`nonce="[A-Za-z0-9+/]{20,}"`).MatchString(html) {
		t.Error("shell missing per-request nonce attribute")
	}
	// Every asset the shell references must be a hashed URL that the static
	// handler actually resolves.
	for _, m := range regexp.MustCompile(`(?:href|src)="(/static/[^"]+)"`).FindAllStringSubmatch(html, -1) {
		rec := httptest.NewRecorder()
		newTestRouter().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, m[1], nil))
		if rec.Code != http.StatusOK {
			t.Errorf("referenced asset %s: status %d, want 200", m[1], rec.Code)
		}
		if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "immutable") {
			t.Errorf("referenced asset %s served without immutable caching (%q) — layout must use hashed URLs", m[1], cc)
		}
	}
}

func TestAppShellFreshNoncePerRequest(t *testing.T) {
	fetch := func() string {
		rec := httptest.NewRecorder()
		newTestRouter().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/app", nil))
		m := regexp.MustCompile(`nonce="([^"]+)"`).FindStringSubmatch(rec.Body.String())
		if m == nil {
			t.Fatal("no nonce in response")
		}
		return m[1]
	}
	first, second := fetch(), fetch()
	if first == second {
		t.Error("nonce identical across requests, want fresh per request")
	}
}
