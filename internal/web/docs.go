package web

import (
	"embed"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/thomasteoh/boardchestrator/internal/web/views"
	"github.com/thomasteoh/boardchestrator/internal/wiki"
)

//go:embed docs/*.md
var docsFS embed.FS

// handleDocsPage serves the in-app help area. /app/docs renders the
// overview (index.md); /app/docs/{slug} renders the matching guide.
// Each guide is embedded markdown rendered through wiki.Render, so the
// output is sanitized (XSS-stripped, safe SVG preserved) like wiki pages.
func handleDocsPage(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if slug == "" {
		slug = "index"
	}

	md, err := readDocs(slug)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	html, err := wiki.Render(md, wiki.RenderOptions{})
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	title := docsTitle(slug)
	s := shellData(r, title, "/docs")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := views.DocsPage(s, slug, title, string(html)).Render(r.Context(), w); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// readDocs reads an embedded guide by slug, defaulting to index.md.
func readDocs(slug string) ([]byte, error) {
	name := "docs/" + slug + ".md"
	b, err := docsFS.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("docs %s: %w", slug, err)
	}
	return b, nil
}

// docsTitle maps a slug to its display title.
func docsTitle(slug string) string {
	// Reuse the views nav list for single-source titles.
	for _, g := range views.DocsNav() {
		if g.Slug == slug {
			return g.Label
		}
	}
	switch slug {
	case "index":
		return "Help"
	default:
		return "Help — " + slug
	}
}

// docsSlugs returns the sorted list of guide slugs (used by tests).
func docsSlugs() []string {
	entries, _ := docsFS.ReadDir("docs")
	slugs := make([]string, 0, len(entries))
	for _, e := range entries {
		slugs = append(slugs, strings.TrimSuffix(e.Name(), ".md"))
	}
	sort.Strings(slugs)
	return slugs
}
