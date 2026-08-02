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

func TestManifestServed(t *testing.T) {
	rec := httptest.NewRecorder()
	newTestRouter().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/manifest.json", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /manifest.json: status %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/manifest+json" {
		t.Errorf("Content-Type = %q, want application/manifest+json", ct)
	}
	body, _ := io.ReadAll(rec.Body)
	json := string(body)

	if !strings.Contains(json, `"name": "Boardchestrator"`) {
		t.Error("manifest missing name")
	}
	if !strings.Contains(json, `"short_name": "Boards"`) {
		t.Error("manifest missing short_name")
	}
	if !strings.Contains(json, `"display": "standalone"`) {
		t.Error("manifest missing display")
	}
	if !strings.Contains(json, `"theme_color": "#6366f1"`) {
		t.Error("manifest missing theme_color")
	}
	if !strings.Contains(json, `"background_color": "#1a1a1a"`) {
		t.Error("manifest missing background_color")
	}
	if !strings.Contains(json, `"start_url": "/"`) {
		t.Error("manifest missing start_url")
	}
}

func TestServiceWorkerServed(t *testing.T) {
	// The worker is served at the stable root path /sw.js (not a hashed
	// /static/ URL) so its scope is the whole origin.
	rec := httptest.NewRecorder()
	newTestRouter().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sw.js", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /sw.js: status %d, want 200", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if ct != "text/javascript; charset=utf-8" && ct != "application/javascript" {
		t.Errorf("Content-Type = %q, want a javascript type", ct)
	}
	if got := rec.Header().Get("Service-Worker-Allowed"); got != "/" {
		t.Errorf("Service-Worker-Allowed = %q, want /", got)
	}
	body, _ := io.ReadAll(rec.Body)
	bodyStr := string(body)

	if !strings.Contains(bodyStr, "CACHE_NAME") {
		t.Error("sw.js missing cache name")
	}
	if !strings.Contains(bodyStr, "NEVER_CACHE_PREFIXES") {
		t.Error("sw.js missing never-cache prefixes")
	}
	if !strings.Contains(bodyStr, "/api/") {
		t.Error("sw.js missing /api/ in exclusion list")
	}
	if !strings.Contains(bodyStr, "/events") {
		t.Error("sw.js missing /events in exclusion list")
	}
	if !strings.Contains(bodyStr, "/mcp") {
		t.Error("sw.js missing /mcp in exclusion list")
	}
}

func TestShellContainsManifestLink(t *testing.T) {
	rec := httptest.NewRecorder()
	newTestRouter().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/app", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /app: status %d, want 200", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	html := string(body)

	if !strings.Contains(html, `rel="manifest"`) {
		t.Error("shell missing manifest link")
	}
	if !strings.Contains(html, `href="/manifest.json"`) {
		t.Error("shell manifest link should point to /manifest.json")
	}
}

func TestShellContainsSWRegistration(t *testing.T) {
	rec := httptest.NewRecorder()
	newTestRouter().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/app", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /app: status %d, want 200", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	html := string(body)

	if !strings.Contains(html, `data-sw-url=`) {
		t.Error("shell missing data-sw-url attribute")
	}
	if !strings.Contains(html, `navigator.serviceWorker.register`) {
		t.Error("shell missing service worker registration")
	}
}
