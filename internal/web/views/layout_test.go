package views

import (
	"context"
	"strings"
	"testing"

	"github.com/a-h/templ"
)

func renderBase(t *testing.T, s Shell, children string) string {
	t.Helper()
	var b strings.Builder
	ctx := templ.WithChildren(context.Background(), templ.Raw(children))
	if err := Base(s).Render(ctx, &b); err != nil {
		t.Fatalf("render: %v", err)
	}
	return b.String()
}

func testShell() Shell {
	return Shell{
		Title: "Test Page",
		Nonce: "test-nonce-123",
		Assets: ShellAssets{
			AppCSS: "/static/app.abc123def456.css",
			HTMX:   "/static/vendor/htmx.min.abc123def456.js",
			Alpine: "/static/vendor/alpine-csp.min.abc123def456.js",
			AppJS:  "/static/app.abc123def456.js",
			SW:     "/static/sw.abc123def456.js",
		},
	}
}

func TestBaseLayoutRenders(t *testing.T) {
	html := renderBase(t, testShell(), "<p id=\"slot-content\">hello slot</p>")

	tests := []struct {
		name string
		want string
	}{
		{"doctype", "<!doctype html>"},
		{"australian english locale", `lang="en-AU"`},
		{"title with product suffix", "<title>Test Page · Boardchestrator</title>"},
		{"nav landmark present", `<nav class="bc-sidebar" aria-label="Primary">`},
		{"bottom nav present", `<nav class="bc-bottom-nav" aria-label="Primary">`},
		{"drawer present", `class="bc-drawer"`},
		{"main slot content", `<p id="slot-content">hello slot</p>`},
		{"nonce attr on scripts", `nonce="test-nonce-123"`},
		{"stylesheet link", `href="/static/app.abc123def456.css"`},
		{"htmx script", `src="/static/vendor/htmx.min.abc123def456.js"`},
		{"alpine script", `src="/static/vendor/alpine-csp.min.abc123def456.js"`},
		{"app script", `src="/static/app.abc123def456.js"`},
		{"hx-boost nav", `hx-boost="true"`},
		{"alpine shell component", `x-data="shell"`},
		{"skip link", `class="bc-skip-link"`},
		{"boards nav item", `href="/boards"`},
		{"theme bootstrap reads storage", `localStorage.getItem("bc-theme")`},
		{"manifest link", `rel="manifest"`},
		{"manifest href", `href="/manifest.json"`},
		{"sw data attribute on body", `data-sw-url="`},
		{"sw registration", `navigator.serviceWorker.register`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(html, tt.want) {
				t.Errorf("rendered layout missing %q", tt.want)
			}
		})
	}
}

func TestBaseLayoutNoncePerRequest(t *testing.T) {
	s := testShell()
	s.Nonce = "other-nonce-456"
	html := renderBase(t, s, "")
	if !strings.Contains(html, `nonce="other-nonce-456"`) {
		t.Error("nonce param not plumbed through to script tags")
	}
	if strings.Contains(html, "test-nonce-123") {
		t.Error("stale nonce value present — nonce must come from the param")
	}
}

func TestBaseLayoutCSRFHeader(t *testing.T) {
	s := testShell()
	s.CSRF = "csrf-token-xyz"
	html := renderBase(t, s, "")
	// The CSRF token rides in the body's hx-headers so every HTMX mutating
	// request carries it. templ HTML-escapes the JSON quotes in the attribute.
	if !strings.Contains(html, "hx-headers=") {
		t.Fatal("body missing hx-headers attribute")
	}
	if !strings.Contains(html, "X-CSRF-Token") || !strings.Contains(html, "csrf-token-xyz") {
		t.Errorf("hx-headers missing CSRF token; got %q", html)
	}

	// Unauthenticated shell: empty token yields an empty header object.
	s.CSRF = ""
	html = renderBase(t, s, "")
	if strings.Contains(html, "X-CSRF-Token") {
		t.Error("empty CSRF token must not emit an X-CSRF-Token header")
	}
}

func TestBaseLayoutEscapesTitle(t *testing.T) {
	s := testShell()
	s.Title = `<script>alert(1)</script>`
	html := renderBase(t, s, "")
	if strings.Contains(html, "<script>alert(1)</script>") {
		t.Error("title not escaped")
	}
}

func TestNavLinksActiveState(t *testing.T) {
	s := testShell()
	s.Active = "/boards"
	html := renderBase(t, s, "")
	if !strings.Contains(html, `aria-current="page"`) {
		t.Error("active nav item missing aria-current")
	}

	s.Active = ""
	html = renderBase(t, s, "")
	if strings.Contains(html, `aria-current="page"`) {
		t.Error("aria-current rendered with no active item")
	}
}

func TestBottomNavIsMobileSubset(t *testing.T) {
	html := renderBase(t, testShell(), "")
	bottom := html[strings.Index(html, `class="bc-bottom-nav"`):]
	bottom = bottom[:strings.Index(bottom, "</nav>")]
	for _, want := range []string{"Boards", "Backlog", "Chat", "Search", "Notifications"} {
		if !strings.Contains(bottom, want) {
			t.Errorf("bottom nav missing %q", want)
		}
	}
	if strings.Contains(bottom, "Settings") {
		t.Error("Settings must not appear in the mobile bottom nav")
	}
}
