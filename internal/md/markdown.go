// Package md provides markdown rendering and sanitisation for user-authored
// content (task descriptions, comments). Self-contained regex-based parser,
// no external dependencies. Covers the subset used in the app: bold, italic,
// code, links, mentions, KEY-refs, tables, lists, strikethrough, task lists.
package md

import (
	"html"
	"regexp"
	"strings"
)

var (
	mentionRe = regexp.MustCompile(`@([a-zA-Z0-9_\-\.]+)`)
	keyRefRe  = regexp.MustCompile(`\b([A-Z][A-Z0-9_]*-\d+)\b`)
	tagRe     = regexp.MustCompile(`<[^>]*>`)

	// Block-level regexes
	theadRe     = regexp.MustCompile(`^(\|.*\|)\s*$`)
	theadSepRe  = regexp.MustCompile(`^(\|[\s\-:]+\|)\s*$`)
	taskListRe  = regexp.MustCompile(`^-\s+\[([ xX])\]\s+(.*)$`)
	listRe      = regexp.MustCompile(`^-\s+(.*)$`)
	numListRe   = regexp.MustCompile(`^\d+[\.\)]\s+(.*)$`)
	codeFenceRe = regexp.MustCompile("^```(\\w*)\\s*$")
	headingRe   = regexp.MustCompile(`^(#{1,6})\s+(.*)$`)
	hrRe        = regexp.MustCompile(`^(\s*[-*_]\s*){2,}\s*$`)
)

// Render converts markdown source to safe HTML. Mentions and KEY-refs are
// rendered as inline links. Returns sanitised HTML safe for innerHTML.
func Render(src string) string {
	if strings.TrimSpace(src) == "" {
		return ""
	}

	// Escape raw HTML so only markdown-syntax output survives.
	safe := html.EscapeString(src)

	lines := strings.Split(safe, "\n")
	var out strings.Builder
	inTable := false
	inCode := false
	codeLang := ""

	for _, line := range lines {
		trimmed := line

		// Code fences
		if codeFenceRe.MatchString(trimmed) {
			if !inCode {
				inCode = true
				codeLang = codeFenceRe.FindStringSubmatch(trimmed)[1]
				out.WriteString("<pre><code")
				if codeLang != "" {
					out.WriteString(" class=\"language-" + codeLang + "\"")
				}
				out.WriteString(">\n")
				continue
			} else {
				inCode = false
				out.WriteString("</code></pre>\n")
				continue
			}
		}

		if inCode {
			out.WriteString(html.EscapeString(line) + "\n")
			continue
		}

		// Inside a table — data rows come before theadRe check
		if inTable && strings.HasPrefix(trimmed, "|") {
			// Check for separator (ends table)
			if theadSepRe.MatchString(trimmed) {
				out.WriteString("</tbody></table>\n")
				inTable = false
				continue
			}
			cells := parseTableRow(trimmed)
			if len(cells) > 0 {
				out.WriteString("<tr>")
				for _, c := range cells {
					out.WriteString("<td>" + inline(c) + "</td>")
				}
				out.WriteString("</tr>\n")
			}
			continue
		}

		// Table header / start
		if theadRe.MatchString(trimmed) && !theadSepRe.MatchString(trimmed) {
			cells := parseTableRow(trimmed)
			if inTable {
				out.WriteString("</tbody></table>\n")
			}
			out.WriteString("<table><thead><tr>")
			for _, c := range cells {
				out.WriteString("<th>" + inline(c) + "</th>")
			}
			out.WriteString("</tr></thead>\n<tbody>\n")
			inTable = true
			continue
		}

		// Separator line after header (|---|)
		if theadSepRe.MatchString(trimmed) {
			// Already handled by table-data branch or header branch
			continue
		}

		if inTable && trimmed == "" {
			out.WriteString("</tbody></table>\n")
			inTable = false
			continue
		}

		// Task list
		if m := taskListRe.FindStringSubmatch(trimmed); m != nil {
			checked := m[1] == "x" || m[1] == "X"
			out.WriteString(`<ul class="bc-tasklist"><li>`)
			if checked {
				out.WriteString(`<input type="checkbox" checked disabled>`)
			} else {
				out.WriteString(`<input type="checkbox" disabled>`)
			}
			out.WriteString(" " + inline(m[2]) + "</li></ul>\n")
			continue
		}

		// Unordered list
		if m := listRe.FindStringSubmatch(trimmed); m != nil {
			out.WriteString("<ul><li>" + inline(m[1]) + "</li></ul>\n")
			continue
		}

		// Ordered list
		if m := numListRe.FindStringSubmatch(trimmed); m != nil {
			out.WriteString("<ol><li>" + inline(m[1]) + "</li></ol>\n")
			continue
		}

		// Heading (atx)
		if m := headingRe.FindStringSubmatch(trimmed); m != nil {
			level := len(m[1])
			if level > 6 {
				level = 6
			}
			out.WriteString("<h" + itoa(level) + ">" + inline(m[2]) + "</h" + itoa(level) + ">\n")
			continue
		}

		// Horizontal rule
		if hrRe.MatchString(strings.TrimSpace(trimmed)) {
			out.WriteString("<hr>\n")
			continue
		}

		// Paragraph (default)
		if trimmed != "" {
			out.WriteString("<p>" + inline(trimmed) + "</p>\n")
		} else {
			out.WriteString("<br>\n")
		}
	}

	// Close any open code fence or table
	if inCode {
		out.WriteString("</code></pre>\n")
	}
	if inTable {
		out.WriteString("</tbody></table>\n")
	}

	result := out.String()
	result = mentionRe.ReplaceAllString(result, `<a href="/mention/$1" class="bc-mention">@$1</a>`)
	result = keyRefRe.ReplaceAllString(result, `<a href="/task/$1" class="bc-keyref">$1</a>`)
	return result
}

// inline processes inline markup within a single line of text.
func inline(s string) string {
	// Bold (**text**)
	s = regexp.MustCompile(`\*\*([^*]+)\*\*`).ReplaceAllString(s, `<strong>$1</strong>`)
	// Italic (*text*) — no lookaround (Go regexp doesn't support them)
	s = regexp.MustCompile(`(^|[^a-zA-Z0-9])\*([^*]+)\*($|[^a-zA-Z0-9])`).ReplaceAllString(s, `$1<em>$2</em>$3`)
	// Strikethrough (~~text~~)
	s = regexp.MustCompile(`~~([^~]+)~~`).ReplaceAllString(s, `<del>$1</del>`)
	// Inline code (`code`)
	s = regexp.MustCompile("`([^`]+)`").ReplaceAllString(s, `<code>$1</code>`)
	// Images ![alt](url) — must be before links
	s = regexp.MustCompile(`!\[([^\]]*)\]\(([^)]+)\)`).ReplaceAllString(s, `<img src="$2" alt="$1">`)
	// Links [text](url)
	s = regexp.MustCompile(`\[([^\]]+)\]\(([^)]+)\)`).ReplaceAllString(s, `<a href="$2">$1</a>`)
	// Bare URLs — disabled because it interferes with [text](url) link rendering.
	// Use explicit [text](url) syntax instead.
	return s
}

// RenderPlain returns plain text (no HTML) for search indexing or notifications.
// Strips markdown syntax and HTML entities to produce readable plain text.
func RenderPlain(src string) string {
	if strings.TrimSpace(src) == "" {
		return ""
	}
	// Escape HTML entities first so raw tags don't survive.
	plain := html.EscapeString(src)
	// Strip known markdown syntax: **bold**, *italic*, ~~strike~~, `code`, [link](), images, headings, hr, lists.
	plain = regexp.MustCompile(`\*\*([^*]+)\*\*`).ReplaceAllString(plain, `$1`)
	plain = regexp.MustCompile(`\*([^*]+)\*`).ReplaceAllString(plain, `$1`)
	plain = regexp.MustCompile(`~~([^~]+)~~`).ReplaceAllString(plain, `$1`)
	plain = regexp.MustCompile("`([^`]+)`").ReplaceAllString(plain, `$1`)
	plain = regexp.MustCompile(`\[([^\]]+)\]\([^)]+\)`).ReplaceAllString(plain, `$1`)
	plain = regexp.MustCompile(`!\[([^\]]*)\]\([^)]+\)`).ReplaceAllString(plain, `$1`)
	plain = regexp.MustCompile(`^#{1,6}\s+`).ReplaceAllString(plain, ``)
	plain = regexp.MustCompile(`^[-*_]{2,}\s*$`).ReplaceAllString(plain, ``)
	plain = regexp.MustCompile(`^-\s+`).ReplaceAllString(plain, ``)
	plain = regexp.MustCompile(`^\d+[\.\)]\s+`).ReplaceAllString(plain, ``)
	// Strip code fences
	plain = regexp.MustCompile("```.*?\n").ReplaceAllString(plain, ``)
	plain = regexp.MustCompile("^```\n?").ReplaceAllString(plain, ``)
	// Strip table syntax
	plain = regexp.MustCompile(`\|[\s\-:]+\|`).ReplaceAllString(plain, ``)
	plain = regexp.MustCompile(`^\|`).ReplaceAllString(plain, ``)
	plain = regexp.MustCompile(`\|`).ReplaceAllString(plain, ` `)
	// Strip task list checkboxes
	plain = regexp.MustCompile(`\[[ xX]\]`).ReplaceAllString(plain, ``)
	// Unescape back to literal
	plain = html.UnescapeString(plain)
	// Final pass: strip any remaining HTML tags that survived unescaping
	plain = tagRe.ReplaceAllString(plain, "")
	return strings.TrimSpace(plain)
}

// parseTableRow splits a markdown table row into cells.
func parseTableRow(line string) []string {
	parts := strings.Split(line, "|")
	if len(parts) < 2 {
		return nil
	}
	// First part is leading pipe or empty, last is trailing pipe or empty
	if parts[0] == "" {
		parts = parts[1:]
	}
	if len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	cells := make([]string, 0, len(parts))
	for _, p := range parts {
		cells = append(cells, strings.TrimSpace(p))
	}
	return cells
}

// itoa converts int to string for heading level.
func itoa(i int) string {
	return []string{"0", "1", "2", "3", "4", "5", "6"}[i]
}

// --- Fuzz corpora ---

type FuzzInput struct {
	Label string
	Src   string
}

func FuzzCorpus() []FuzzInput {
	return []FuzzInput{
		{Label: "plain text", Src: "hello world"},
		{Label: "bold and italic", Src: "**bold** *italic*"},
		{Label: "code block", Src: "```\ncode\n```"},
		{Label: "table", Src: "| a | b |\n|---|---|\n| 1 | 2 |"},
		{Label: "mention", Src: "hello @user how are you"},
		{Label: "key ref", Src: "see PROJ-123 for details"},
		{Label: "link", Src: "visit https://example.com"},
		{Label: "strikethrough", Src: "~~strike~~"},
		{Label: "task list", Src: "- [x] done\n- [ ] todo"},
		{Label: "mixed", Src: "**bold** @user PROJ-123 `code`"},
		{Label: "nested html", Src: "<script>alert(1)</script>"},
		{Label: "long text", Src: strings.Repeat("word ", 1000)},
	}
}
