package wiki

import (
	"regexp"
	"strings"
)

// sanitizeRe strips dangerous attribute vectors from HTML: inline event
// handlers, javascript:/vbscript:/data: URLs (except data:image), style,
// srcdoc, formaction, and autofocus.
var sanitizeRe = regexp.MustCompile(`(?i)\s*(?:on[a-z]+\s*=\s*"[^"]*"|on[a-z]+\s*=\s*'[^']*'|style\s*=\s*"[^"]*"|style\s*=\s*'[^']*'|srcdoc\s*=\s*"[^"]*"|srcdoc\s*=\s*'[^']*'|formaction\s*=\s*"[^"]*"|formaction\s*=\s*'[^']*'|autofocus)`)
var unsafeURLRe = regexp.MustCompile(`(?i)\s*(?:href|src)\s*=\s*"(?:javascript|vbscript|data):[^"]*"`)

// safeTags is the allowlist of tags kept in sanitized HTML. Everything else is
// removed (tags, not their text content). SVG presentation + structural tags
// are included so mermaid/embedded SVGs render.
var safeTags = map[string]bool{
	"a": true, "abbr": true, "b": true, "blockquote": true, "br": true,
	"code": true, "div": true, "em": true, "h1": true, "h2": true, "h3": true,
	"h4": true, "h5": true, "h6": true, "hr": true, "i": true, "img": true,
	"li": true, "ol": true, "p": true, "pre": true, "span": true,
	"strong": true, "table": true, "tbody": true, "td": true, "th": true,
	"thead": true, "tr": true, "ul": true, "del": true, "input": true,
	"svg": true, "path": true, "g": true, "text": true, "tspan": true,
	"circle": true, "rect": true, "line": true, "polyline": true,
	"polygon": true, "ellipse": true, "use": true, "defs": true,
 "title": true, "desc": true, "marker": true, "animate": true,
 "animateTransform": true, "clipPath": true, "mask": true,
 }

// SanitizeHTML strips XSS vectors while allowing safe SVG/inline markup:
//   - removes event-handler, style, srcdoc, formaction, autofocus attrs
//   - removes javascript:/vbscript:/data: (non-image) URLs
//   - removes any tag not in the safe allowlist (keeps text content)
//   - removes any attribute that is not a known-safe attribute
func SanitizeHTML(in []byte) []byte {
	s := sanitizeRe.ReplaceAllString(string(in), "")
	s = unsafeURLRe.ReplaceAllString(s, "")
	return sanitizeTags([]byte(s))
}

// sanitizeTags walks HTML and keeps only allowlisted tags + safe attributes.
func sanitizeTags(in []byte) []byte {
	var out strings.Builder
	src := string(in)
	i := 0
	for i < len(src) {
		// Copy text up to the next '<'.
		lt := strings.IndexByte(src[i:], '<')
		if lt < 0 {
			out.WriteString(src[i:])
			break
		}
		lt += i
		out.WriteString(src[i:lt])
		i = lt

		if i+1 < len(src) && (src[i+1] == '!' || src[i+1] == '?') {
			// Comments / declarations: drop entirely.
			end := strings.IndexByte(src[i:], '>')
			if end < 0 {
				break
			}
			i += end + 1
			continue
		}

		closing := i+1 < len(src) && src[i+1] == '/'
		nameStart := i + 1
		if closing {
			nameStart++
		}
		j := nameStart
		for j < len(src) && isNameChar(src[j]) {
			j++
		}
		tagName := src[nameStart:j]
		if !safeTags[tagName] {
			// Drop the whole tag (open or close). For content-bearing unsafe
			// tags (script, style), also drop everything through the matching
			// close tag so their payload can't leak as text.
			if !closing && (tagName == "script" || tagName == "style") {
				end := strings.IndexByte(src[i:], '>')
				if end < 0 {
					break
				}
				close := strings.Index(strings.ToLower(src[i:]), "</"+strings.ToLower(tagName)+">")
				if close < 0 {
					i += end + 1
					continue
				}
				i += close + len("</"+strings.ToLower(tagName)+">")
				continue
			}
			end := strings.IndexByte(src[i:], '>')
			if end < 0 {
				break
			}
			i += end + 1
			continue
		}

		// Keep the tag, filtering attributes on open tags.
		end := strings.IndexByte(src[i:], '>')
		if end < 0 {
			break
		}
		tagSrc := src[i : i+end+1]
		if !closing {
			tagSrc = filterAttrs(tagName, tagSrc)
		}
		out.WriteString(tagSrc)
		i += end + 1
	}
	return []byte(out.String())
}

func isNameChar(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-'
}

// filterAttrs keeps only safe attributes for a tag.
func filterAttrs(tag, tagSrc string) string {
	// Rebuild the tag with only safe attributes.
	m := regexp.MustCompile(`\s+([a-zA-Z][a-zA-Z0-9_:.-]*)\s*=\s*("[^"]*"|'[^']*')`)
	attrs := m.FindAllStringSubmatch(tagSrc, -1)
	name := tag
	if n := strings.IndexAny(tagSrc, " 	\r\n>"); n >= 0 {
		name = tagSrc[1:n]
	} else if n := strings.IndexByte(tagSrc, '>'); n >= 0 {
		name = tagSrc[1:n]
	}
	var sb strings.Builder
	sb.WriteByte('<')
	sb.WriteString(name)
	for _, a := range attrs {
		if !safeAttr(tag, a[1]) {
			continue
		}
		val := a[2]
		if strings.HasPrefix(strings.ToLower(val), "javascript:") ||
			strings.HasPrefix(strings.ToLower(val), "vbscript:") ||
			strings.HasPrefix(strings.ToLower(val), "data:") {
			continue
		}
		sb.WriteByte(' ')
		sb.WriteString(a[1])
		sb.WriteByte('=')
		sb.WriteString(val)
	}
	sb.WriteByte('>')
	return sb.String()
}

// safeAttr reports whether attr is safe for tag (per-tag href/src allowlist,
// generic attrs for all).
func safeAttr(tag, attr string) bool {
	a := strings.ToLower(attr)
	switch a {
	case "href", "src":
		if tag == "a" && a == "href" {
			return true
		}
		if tag == "img" && a == "src" {
			return true
		}
		if tag == "use" && a == "href" {
			return true
		}
		return false
	}
	switch a {
	case "alt", "title", "class", "id", "name", "role", "aria-label",
		"aria-hidden", "width", "height", "viewbox", "fill", "stroke",
		"stroke-width", "stroke-linecap", "stroke-linejoin", "d", "x", "y",
		"cx", "cy", "r", "rx", "ry", "points", "xmlns", "xmlns:xlink",
		"xlink:href", "data-name", "data-id", "checked", "type", "disabled",
		"value", "placeholder", "datetime", "cite", "colspan", "rowspan",
		"align", "border", "cellpadding", "cellspacing":
		return true
	}
	return false
}
