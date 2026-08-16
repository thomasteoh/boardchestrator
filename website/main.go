// Boardchestrator public website generator.
//
// Minimal Go static site generator (awry pattern): markdown-driven pages,
// single base template, inline CSS/JS composed per page. No runtime deps
// beyond goldmark. Output to public/ for GitHub Pages.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/renderer/html"
	"gopkg.in/yaml.v3"
)

// Page is a single markdown page: frontmatter (title, desc, order) + body.
type Page struct {
	Title string `yaml:"title"`
	Desc  string `yaml:"desc"`
	Order int    `yaml:"order"`
	Body  string `yaml:"-"`
	Slug  string `yaml:"-"`
	Path  string `yaml:"-"`
}

type Site struct {
	Title       string `yaml:"title"`
	URL         string `yaml:"url"`
	Description string `yaml:"description"`
	Repo        string `yaml:"repo"`
	Pages       []Page `yaml:"-"`
}

var md = goldmark.New(
	goldmark.WithExtensions(extension.GFM),
	goldmark.WithParserOptions(),
	goldmark.WithRendererOptions(html.WithUnsafe()),
)

func main() {
	root := flag.String("root", ".", "website root")
	flag.Parse()

	cfg := loadSite(filepath.Join(*root, "site.yaml"))
	loaded := loadPages(filepath.Join(*root, "content"))
	// Merge markdown pages into the site config (they carry order/desc/title).
	cfg.Pages = append(cfg.Pages, loaded...)

	tmpl := template.New("base").Funcs(template.FuncMap{
		"safeHTML": func(s string) template.HTML { return template.HTML(s) },
		"lower":    strings.ToLower,
	})
	base := readFile(filepath.Join(*root, "templates", "base.html"))
	template.Must(tmpl.Parse(base))

	out := filepath.Join(*root, "public")
	os.RemoveAll(out)
	os.MkdirAll(out, 0755)

	// Home page is assembled from the markdown body plus the generated
	// features/docs sections.
	home := Page{Title: cfg.Title, Desc: cfg.Description, Slug: "index", Path: "/"}
	for _, p := range cfg.Pages {
		if p.Slug == "index" {
			home = p
		}
	}

	renderPage(tmpl, cfg, home, filepath.Join(out, "index.html"))

	for _, p := range cfg.Pages {
		if p.Slug == "index" {
			continue
		}
		dir := filepath.Join(out, p.Slug)
		os.MkdirAll(dir, 0755)
		renderPage(tmpl, cfg, p, filepath.Join(dir, "index.html"))
	}

	copyStatic(filepath.Join(*root, "static"), out)
	writeRobots(cfg, out)
	writeSitemap(cfg, out)
	writeLlmstxt(cfg, out)
	write404(tmpl, cfg, filepath.Join(out, "404.html"))

	fmt.Printf("built %d pages to %s\n", len(cfg.Pages)+1, out)
}

func renderPage(tmpl *template.Template, cfg Site, p Page, dst string) {
	body := renderMarkdown(p.Body)
	// Docs pages: wrap in a simple prose layout. Home gets the marketing
	// chrome (hero + features + animated brand) from the template.
	layout := "page"
	if p.Slug == "index" {
		layout = "home"
	}
	buf := &bytes.Buffer{}
	if err := tmpl.ExecuteTemplate(buf, "base", map[string]any{
		"Site":   cfg,
		"Page":   p,
		"Body":   template.HTML(body),
		"Layout": layout,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "render %s: %v\n", p.Path, err)
		os.Exit(1)
	}
	if err := os.WriteFile(dst, buf.Bytes(), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "write %s: %v\n", dst, err)
		os.Exit(1)
	}
}

// renderMarkdown converts a markdown body to HTML with goldmark.
func renderMarkdown(src string) string {
	var buf bytes.Buffer
	if err := md.Convert([]byte(src), &buf); err != nil {
		return "<p>" + template.HTMLEscapeString(src) + "</p>"
	}
	return buf.String()
}

func loadSite(path string) Site {
	var s Site
	raw := readFile(path)
	if err := yaml.Unmarshal([]byte(raw), &s); err != nil {
		fmt.Fprintf(os.Stderr, "site.yaml: %v\n", err)
		os.Exit(1)
	}
	return s
}

func loadPages(dir string) []Page {
	var pages []Page
	entries, err := os.ReadDir(dir)
	if err != nil {
		return pages
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		slug := strings.TrimSuffix(e.Name(), ".md")
		raw := readFile(filepath.Join(dir, e.Name()))
		var p Page
		parts := splitFrontmatter(raw)
		if err := yaml.Unmarshal([]byte(parts.fm), &p); err != nil {
			fmt.Fprintf(os.Stderr, "%s frontmatter: %v\n", e.Name(), err)
			os.Exit(1)
		}
		p.Body = parts.body
		p.Slug = slug
		if slug == "index" {
			p.Path = "/"
		} else {
			p.Path = "/" + slug + "/"
		}
		pages = append(pages, p)
	}
	// Stable order: home first, then by Order field.
	return pages
}

type split struct{ fm, body string }

func splitFrontmatter(raw string) split {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "---\n")
	// Closing --- sits on its own line, possibly at EOF with no trailing NL.
	idx := strings.Index(s, "\n---")
	if idx < 0 {
		return split{"", strings.TrimSpace(s)}
	}
	fm := s[:idx]
	body := s[idx+len("\n---"):]
	return split{fm, strings.TrimSpace(body)}
}

func readFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", path, err)
		os.Exit(1)
	}
	return string(b)
}

func copyStatic(src, out string) {
	filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		dst := filepath.Join(out, rel)
		os.MkdirAll(filepath.Dir(dst), 0755)
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, b, 0644)
	})
}

func writeRobots(cfg Site, out string) {
	os.WriteFile(filepath.Join(out, "robots.txt"), []byte("User-agent: *\nAllow: /\n\nSitemap: "+cfg.URL+"/sitemap.xml\n"), 0644)
}

func writeSitemap(cfg Site, out string) {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">` + "\n")
	url := func(path string) {
		fmt.Fprintf(&b, "  <url><loc>%s%s</loc></url>\n", cfg.URL, path)
	}
	url("/")
	for _, p := range cfg.Pages {
		if p.Slug == "index" {
			continue
		}
		url(p.Path)
	}
	b.WriteString("</urlset>\n")
	os.WriteFile(filepath.Join(out, "sitemap.xml"), []byte(b.String()), 0644)
}

// writeLlmstxt emits a plain-text manifest for LLM tooling.
func writeLlmstxt(cfg Site, out string) {
	var b strings.Builder
	b.WriteString("# " + cfg.Title + "\n\n")
	b.WriteString(cfg.Description + "\n\n")
	b.WriteString("## Docs\n\n")
	for _, p := range cfg.Pages {
		if p.Slug == "index" {
			continue
		}
		fmt.Fprintf(&b, "- %s: %s (%s%s)\n", p.Title, p.Desc, cfg.URL, p.Path)
	}
	b.WriteString("\nSource: " + cfg.Repo + "\n")
	os.WriteFile(filepath.Join(out, "llms.txt"), []byte(b.String()), 0644)
}

func write404(tmpl *template.Template, cfg Site, dst string) {
	buf := &bytes.Buffer{}
	p := Page{Title: "Not found", Desc: "This page doesn't exist.", Slug: "404", Path: "/404/"}
	tmpl.ExecuteTemplate(buf, "base", map[string]any{"Site": cfg, "Page": p, "Body": template.HTML("<p>Move on — nothing here.</p>"), "Layout": "page"})
	os.WriteFile(dst, buf.Bytes(), 0644)
}
