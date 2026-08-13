package wiki

import (
	"bytes"
	"fmt"
	"regexp"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/renderer"
	"github.com/yuin/goldmark/renderer/html"
	"github.com/yuin/goldmark/util"
)

// keyRe matches a project key + numeric suffix: KEY-n (e.g. ABC-123).
var keyRe = regexp.MustCompile(`([A-Z][A-Z0-9_]*)-([0-9]+)`)

// mermaidRe matches a fenced code block tagged `mermaid` as rendered by
// goldmark: <pre><code class="language-mermaid">…</code></pre>.
var mermaidRe = regexp.MustCompile(`(?s)<pre><code[^>]*class="language-mermaid">(.*?)</code></pre>`)

// RenderOptions controls rendering.
type RenderOptions struct {
	// TaskBaseURL is the href base for KEY-n autolinks (e.g. "/tasks").
	TaskBaseURL string
}

// Render converts markdown to sanitized HTML: mermaid fenced blocks become
// client-side mermaid <div>s, raw SVG is allowed but sanitized (XSS vectors
// stripped), and KEY-n tokens autolink to tasks. Uses GFM (tables,
// strikethrough, autolinks) + unsafe HTML so inline SVG survives, then
// sanitizes.
func Render(md []byte, opts RenderOptions) ([]byte, error) {
	mdRenderer := goldmark.New(
		goldmark.WithExtensions(extension.GFM),
		goldmark.WithRenderer(renderer.NewRenderer(renderer.WithNodeRenderers(
			util.Prioritized(html.NewRenderer(
				html.WithUnsafe(),
			), 1000),
		))),
	)
	var buf bytes.Buffer
	if err := mdRenderer.Convert(md, &buf); err != nil {
		return nil, fmt.Errorf("render: %w", err)
	}
	out := buf.Bytes()

	out = mermaidBlock(out)     // fenced mermaid → <div class="mermaid">
	out = SanitizeHTML(out)    // strip XSS vectors, keep safe SVG
	out = AutolinkTasks(out, opts.TaskBaseURL) // KEY-n → task links

	return out, nil
}

// mermaidBlock rewrites goldmark's <pre><code class="language-mermaid"> into a
// client-side mermaid <div> (rendered by mermaid.js in the browser).
func mermaidBlock(in []byte) []byte {
	return mermaidRe.ReplaceAll(in, []byte(`<div class="mermaid">$1</div>`))
}
