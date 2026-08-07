package md

import (
	"strings"
	"testing"
)

func TestRender(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []string
	}{
		{name: "plain", src: "hello", want: []string{"<p>hello</p>"}},
		{name: "bold", src: "**bold**", want: []string{"<strong>bold</strong>"}},
		{name: "italic", src: "*italic*", want: []string{"<em>italic</em>"}},
		{name: "code fence", src: "```\ncode\n```", want: []string{"<pre><code>", "code"}},
		{name: "mention", src: "hello @user", want: []string{`href="/mention/user"`, `bc-mention`}},
		{name: "key ref", src: "see PROJ-123", want: []string{`href="/task/PROJ-123"`, `bc-keyref`}},
		{name: "link", src: "[text](https://x.com)", want: []string{`href="https://x.com">text</a>`}},
		{name: "table", src: "| a | b |\n|---|---|\n| 1 | 2 |", want: []string{"<table>", "<th>a</th>", "<td>1</td>", "<td>2</td>"}},
		{name: "task list", src: "- [x] done\n- [ ] todo", want: []string{"checked", "disabled"}},
		{name: "strikethrough", src: "~~strike~~", want: []string{"<del>strike</del>"}},
		{name: "html escaped", src: "<script>alert(1)</script>", want: []string{"alert(1)"}},
		{name: "heading", src: "## Title", want: []string{"<h2>Title</h2>"}},
		{name: "hr", src: "---", want: []string{"<hr>"}},
		{name: "empty", src: "", want: []string{""}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Render(tt.src)
			for _, w := range tt.want {
				if !strings.Contains(got, w) {
					t.Errorf("Render(%q) = %q, missing %q", tt.src, got, w)
				}
			}
		})
	}
}

func TestRenderEscapesScript(t *testing.T) {
	got := Render("<script>alert(1)</script>")
	if strings.Contains(got, "<script>") {
		t.Errorf("raw script tag not escaped: %s", got)
	}
	if !strings.Contains(got, "<") {
		t.Errorf("expected HTML-escaped output, got %s", got)
	}
}

func TestRenderPlain(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{name: "plain", src: "hello world", want: "hello world"},
		{name: "bold stripped", src: "**bold** text", want: "bold text"},
		{name: "mention preserved", src: "@user hello", want: "@user hello"},
		{name: "html escaped", src: "<script>x</script>", want: "x"},
		{name: "empty", src: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RenderPlain(tt.src)
			if got != tt.want {
				t.Errorf("RenderPlain(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func TestFuzzCorpusSmoke(t *testing.T) {
	for _, c := range FuzzCorpus() {
		t.Run(c.Label, func(t *testing.T) {
			got := Render(c.Src)
			if strings.Contains(got, "<script>") {
				t.Errorf("raw script tag leaked: %s", c.Label)
			}
		})
	}
}
