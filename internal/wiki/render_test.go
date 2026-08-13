package wiki

import (
	"strings"
	"testing"
)

// TestRenderMermaid verifies a mermaid fenced block becomes a client-side
// <div class="mermaid"> (rendered by mermaid.js in the browser).
func TestRenderMermaid(t *testing.T) {
	md := "```mermaid\ngraph TD;\n  A-->B;\n```"
	out, err := Render([]byte(md), RenderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, `<div class="mermaid">`) {
		t.Fatalf("expected mermaid div, got: %s", s)
	}
	if !strings.Contains(s, "graph TD;") {
		t.Fatalf("expected mermaid source preserved, got: %s", s)
	}
}

// TestRenderCodeBlock verifies a normal code block is left as-is (not mermaid).
func TestRenderCodeBlock(t *testing.T) {
	out, err := Render([]byte("```go\nx := 1\n```"), RenderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, `<div class="mermaid">`) {
		t.Fatalf("non-mermaid code block became mermaid: %s", s)
	}
	if !strings.Contains(s, "x := 1") {
		t.Fatalf("code content lost: %s", s)
	}
}

// TestRenderSanitizeXSS verifies the sanitizer strips event handlers,
// javascript: URLs, and disallowed tags while keeping safe SVG.
func TestRenderSanitizeXSS(t *testing.T) {
	md := `<img src="x" onerror="alert(1)">\n<a href="javascript:alert(1)">click</a>\n<svg><path d="M0 0"/></svg>`
	_ = md
	// Direct sanitizer check (bypasses markdown escaping of inline HTML).
	in := []byte(`<img src="x" onerror="alert(1)"><a href="javascript:alert(1)">click</a><svg><path d="M0 0" onload="x"/></svg><script>bad()</script>`)
	out := SanitizeHTML(in)
	s := string(out)
	if strings.Contains(s, "onerror") || strings.Contains(s, "onload") {
		t.Fatalf("event handler survived: %s", s)
	}
	if strings.Contains(s, "javascript:") {
		t.Fatalf("javascript URL survived: %s", s)
	}
	if strings.Contains(s, "bad()") {
		t.Fatalf("script content survived (tag removed but text kept): %s", s)
	}
	if !strings.Contains(s, "<svg>") || !strings.Contains(s, `<path d="M0 0"`) {
		t.Fatalf("safe SVG was dropped: %s", s)
	}
}

// TestAutolinkTasks verifies KEY-n autolinks to tasks, skipping code/pre and
// existing anchors.
func TestAutolinkTasks(t *testing.T) {
	in := `<p>See ABC-123 and DEF-456.</p><pre><code>ABC-999</code></pre><a href="/x">ABC-888</a>`
	out := AutolinkTasks([]byte(in), "/tasks")
	s := string(out)
	for _, want := range []string{`<a href="/tasks/ABC-123">ABC-123</a>`, `<a href="/tasks/DEF-456">DEF-456</a>`} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing autolink %s in %s", want, s)
		}
	}
	if strings.Contains(s, "ABC-999") && strings.Contains(s, `<a href`) {
		// The pre block text must remain unlinked.
		if strings.Contains(s, `<a href="/tasks/ABC-999">`) {
			t.Fatalf("autolinked inside code block: %s", s)
		}
	}
	if strings.Contains(s, `ABC-888</a>`) && strings.Contains(s, `<a href="/tasks/ABC-888">`) {
		t.Fatalf("nested/duplicated link: %s", s)
	}
	// Empty base URL → no autolink.
	if out := AutolinkTasks([]byte("ABC-123"), ""); strings.Contains(string(out), "<a ") {
		t.Fatalf("autolinked with empty base: %s", out)
	}
}

// TestRenderAutolinkInPage verifies the full pipeline autolinks KEY-n.
func TestRenderAutolinkInPage(t *testing.T) {
	out, err := Render([]byte("Fix ABC-12"), RenderOptions{TaskBaseURL: "/tasks"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `<a href="/tasks/ABC-12">ABC-12</a>`) {
		t.Fatalf("no autolink: %s", out)
	}
}
