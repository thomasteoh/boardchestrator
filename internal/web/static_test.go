package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestAssetURLHashed(t *testing.T) {
	tests := []struct {
		name    string
		logical string
		want    string // regexp
	}{
		{"app css", "app.css", `^/static/app\.[0-9a-f]{12}\.css$`},
		{"app js", "app.js", `^/static/app\.[0-9a-f]{12}\.js$`},
		{"vendored htmx", "vendor/htmx.min.js", `^/static/vendor/htmx\.min\.[0-9a-f]{12}\.js$`},
		{"vendored alpine", "vendor/alpine-csp.min.js", `^/static/vendor/alpine-csp\.min\.[0-9a-f]{12}\.js$`},
		{"unknown falls back unhashed", "nope.css", `^/static/nope\.css$`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AssetURL(tt.logical)
			if !regexp.MustCompile(tt.want).MatchString(got) {
				t.Errorf("AssetURL(%q) = %q, want match %q", tt.logical, got, tt.want)
			}
		})
	}
}

func get(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	StaticHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestStaticHandlerHashedURLImmutable(t *testing.T) {
	for _, logical := range []string{"app.css", "app.js", "vendor/htmx.min.js", "vendor/alpine-csp.min.js"} {
		t.Run(logical, func(t *testing.T) {
			rec := get(t, AssetURL(logical))
			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s: status %d, want 200", AssetURL(logical), rec.Code)
			}
			if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=31536000, immutable" {
				t.Errorf("Cache-Control = %q, want immutable far-future", cc)
			}
			if xc := rec.Header().Get("X-Content-Type-Options"); xc != "nosniff" {
				t.Errorf("X-Content-Type-Options = %q, want nosniff", xc)
			}
			body, _ := io.ReadAll(rec.Body)
			if len(body) == 0 {
				t.Error("empty body")
			}
		})
	}
}

func TestStaticHandlerContentTypes(t *testing.T) {
	tests := []struct {
		logical  string
		wantType string
	}{
		{"app.css", "text/css"},
		{"app.js", "text/javascript"},
	}
	for _, tt := range tests {
		rec := get(t, AssetURL(tt.logical))
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, tt.wantType) {
			t.Errorf("%s: Content-Type = %q, want prefix %q", tt.logical, ct, tt.wantType)
		}
	}
}

func TestStaticHandlerUnhashedNoCache(t *testing.T) {
	rec := get(t, "/static/app.css")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("Cache-Control = %q, want no-cache", cc)
	}
}

func TestStaticHandlerRejects(t *testing.T) {
	tests := []struct {
		name string
		path string
		want int
	}{
		{"missing file", "/static/missing.css", http.StatusNotFound},
		{"stale hash", "/static/app.000000000000.css", http.StatusNotFound},
		{"directory", "/static/vendor", http.StatusNotFound},
		{"traversal", "/static/../go.mod", http.StatusNotFound},
		{"dotted traversal to real asset", "/static/vendor/../app.css", http.StatusNotFound},
		{"empty", "/static/", http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := get(t, tt.path)
			if rec.Code != tt.want {
				t.Errorf("GET %s: status %d, want %d", tt.path, rec.Code, tt.want)
			}
		})
	}
}

func TestStaticHandlerMethodNotAllowed(t *testing.T) {
	rec := httptest.NewRecorder()
	StaticHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, AssetURL("app.css"), nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: status %d, want 405", rec.Code)
	}
}

// TestAppCSSResponsiveRules pins the responsive contract: SPEC §3 breakpoints
// (640/1024), --bc-* design tokens, and dark/light via data-theme plus
// prefers-color-scheme must all be present in the served stylesheet.
func TestAppCSSResponsiveRules(t *testing.T) {
	css, err := staticFS.ReadFile("static/app.css")
	if err != nil {
		t.Fatalf("read embedded app.css: %v", err)
	}
	for _, want := range []string{
		"@media (min-width: 640px)",
		"@media (min-width: 1024px)",
		"--bc-bg:",
		"--bc-accent:",
		`[data-theme="dark"]`,
		"@media (prefers-color-scheme: dark)",
		":root:not([data-theme=\"light\"])",
		"@media (prefers-reduced-motion: reduce)",
		".bc-bottom-nav",
		".bc-sidebar",
	} {
		if !strings.Contains(string(css), want) {
			t.Errorf("app.css missing %q", want)
		}
	}
}
