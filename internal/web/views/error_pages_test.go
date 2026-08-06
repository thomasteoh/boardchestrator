package views

import (
	"context"
	"strings"
	"testing"

	"github.com/a-h/templ"
)

func renderComponent(t *testing.T, c templ.Component) string {
	t.Helper()
	var buf strings.Builder
	err := c.Render(context.Background(), &buf)
	if err != nil {
		t.Fatalf("Render failed: %v", err)
	}
	return buf.String()
}

func TestNotFoundPage(t *testing.T) {
	s := Shell{Title: "Test", Active: "", Nonce: "abc", CSRF: "xyz"}
	html := renderComponent(t, NotFoundPage(s))
	tests := []struct{ name, want string }{
		{"status code", "404"},
		{"title", "Page not found"},
		{"message", "doesn"},
		{"back button", "Back to home"},
	}
	for _, tt := range tests {
		if !strings.Contains(html, tt.want) {
			t.Errorf("NotFoundPage missing %q", tt.name)
		}
	}
}

func TestForbiddenPage(t *testing.T) {
	s := Shell{Title: "Test", Active: "", Nonce: "abc", CSRF: "xyz"}
	html := renderComponent(t, ForbiddenPage(s))
	tests := []struct{ name, want string }{
		{"status code", "403"},
		{"title", "Forbidden"},
		{"message", "permission"},
	}
	for _, tt := range tests {
		if !strings.Contains(html, tt.want) {
			t.Errorf("ForbiddenPage missing %q", tt.name)
		}
	}
}

func TestInternalErrorPage(t *testing.T) {
	s := Shell{Title: "Test", Active: "", Nonce: "abc", CSRF: "xyz"}
	html := renderComponent(t, InternalErrorPage(s))
	tests := []struct{ name, want string }{
		{"status code", "500"},
		{"title", "Internal server error"},
		{"message", "try again"},
	}
	for _, tt := range tests {
		if !strings.Contains(html, tt.want) {
			t.Errorf("InternalErrorPage missing %q", tt.name)
		}
	}
}

func TestErrorPageCustom(t *testing.T) {
	s := Shell{Title: "Test", Active: "", Nonce: "abc", CSRF: "xyz"}
	html := renderComponent(t, ErrorPage(s, 418, "I'm a teapot", "Cannot brew coffee"))
	tests := []struct{ name, want string }{
		{"status code", "418"},
		{"title", "teapot"},
		{"message", "brew coffee"},
		{"error code class", "bc-error-code"},
	}
	for _, tt := range tests {
		if !strings.Contains(html, tt.want) {
			t.Errorf("ErrorPage missing %q", tt.name)
		}
	}
}
