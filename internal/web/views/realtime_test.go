package views

import (
	"strings"
	"testing"
)

// TestBoardColumnsPartialAriaLive asserts the partial template includes
// aria-live attributes for screen-reader announcements.
func TestBoardColumnsPartialAriaLive(t *testing.T) {
	// Render with empty data — the aria-live attributes are structural.
	var b strings.Builder
	err := BoardColumnsPartial("proj-1", nil, nil).Render(t.Context(), &b)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	html := b.String()
	if !strings.Contains(html, `aria-live="polite"`) {
		t.Error("board partial missing aria-live=\"polite\"")
	}
	if !strings.Contains(html, `role="region"`) {
		t.Error("board partial missing role=\"region\"")
	}
	if !strings.Contains(html, `aria-relevant="additions removals"`) {
		t.Error("board partial missing aria-relevant")
	}
	if !strings.Contains(html, `aria-label="Board columns"`) {
		t.Error("board partial missing aria-label")
	}
}

// TestCommentsListPartialAriaLive asserts the comments partial includes
// aria-live attributes.
func TestCommentsListPartialAriaLive(t *testing.T) {
	var b strings.Builder
	err := CommentsListPartial(nil).Render(t.Context(), &b)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	html := b.String()
	if !strings.Contains(html, `aria-live="polite"`) {
		t.Error("comments partial missing aria-live=\"polite\"")
	}
	if !strings.Contains(html, `role="region"`) {
		t.Error("comments partial missing role=\"region\"")
	}
	if !strings.Contains(html, `aria-relevant="additions removals"`) {
		t.Error("comments partial missing aria-relevant")
	}
	if !strings.Contains(html, `aria-label="Comments"`) {
		t.Error("comments partial missing aria-label")
	}
}

// TestNotifBadgeInNavLinks asserts the notification badge element exists
// in the nav link for /notifications.
func TestNotifBadgeInNavLinks(t *testing.T) {
	var b strings.Builder
	// Render a full shell page so the nav links are included.
	err := BoardPage(Shell{
		Title: "Test",
		Nonce: "abc123",
		CSRF:  "csrf-token",
		Assets: ShellAssets{
			AppCSS:   "/static/app.abc123.css",
			HTMX:     "/static/vendor/htmx.min.abc123.js",
			Alpine:   "/static/vendor/alpine-csp.min.abc123.js",
			AppJS:    "/static/app.abc123.js",
			Sortable: "/static/vendor/sortable.min.abc123.js",
			SW:       "/sw.js",
		},
		Active: "",
	}, "proj-1", nil, nil).Render(t.Context(), &b)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	html := b.String()
	if !strings.Contains(html, `id="notif-badge"`) {
		t.Error("notification badge not found in rendered shell")
	}
	if !strings.Contains(html, `x-text="unreadCount > 0 ? unreadCount : ''"`) {
		t.Error("notification badge missing x-text binding")
	}
}
