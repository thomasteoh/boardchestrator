package wiki

import (
	"regexp"
	"strings"
)

// autolinkTaskRe matches KEY-n exactly, used inside text segments.
var autolinkTaskRe = regexp.MustCompile(`([A-Z][A-Z0-9_]*)-([0-9]+)`)

// AutolinkTasks rewrites KEY-n tokens (e.g. ABC-123) into task links, skipping
// code/pre blocks and existing <a> anchors so links aren't nested or broken.
// baseURL is the href prefix; href = baseURL + "/KEY-n". Empty baseURL keeps
// the plain token (no autolink).
func AutolinkTasks(in []byte, baseURL string) []byte {
	if baseURL == "" {
		return in
	}
	src := string(in)
	var out strings.Builder
	// Scan with a skip-stack: inside pre/code/script and inside <a …>…</a>.
	// We track three states independently.
	skipPre := false
	skipA := false
	i := 0
	seg := 0 // start of current linkifiable segment
	for i < len(src) {
		lt := strings.IndexByte(src[i:], '<')
		if lt < 0 {
			break
		}
		lt += i
		// Flush the text before the tag, linkifying it (unless we're skipping).
		if !skipPre && !skipA {
			out.WriteString(linkify(src[seg:lt], baseURL))
		} else {
			out.WriteString(src[seg:lt])
		}
		seg = lt

		// Determine tag kind.
		tagEnd := strings.IndexByte(src[lt:], '>')
		if tagEnd < 0 {
			break
		}
		tagEnd += lt
		tag := src[lt : tagEnd+1]
		low := strings.ToLower(tag)
		closing := strings.HasPrefix(low, "</")
		switch {
		case !closing && strings.Contains(low, "<pre") || !closing && strings.Contains(low, "<code") ||
			!closing && strings.Contains(low, "<script"):
			skipPre = true
		case closing && (strings.Contains(low, "</pre>") || strings.Contains(low, "</code>") || strings.Contains(low, "</script>")):
			skipPre = false
		case !closing && strings.Contains(low, "<a "):
			skipA = true
		case closing && strings.Contains(low, "</a>"):
			skipA = false
		}
		i = tagEnd + 1
		seg = i
	}
	if seg < len(src) {
		if !skipPre && !skipA {
			out.WriteString(linkify(src[seg:], baseURL))
		} else {
			out.WriteString(src[seg:])
		}
	}
	return []byte(out.String())
}

// linkify replaces KEY-n in one text segment with an <a> task link.
func linkify(seg, baseURL string) string {
	return autolinkTaskRe.ReplaceAllStringFunc(seg, func(m string) string {
		return `<a href="` + baseURL + `/` + m + `">` + m + `</a>`
	})
}

// autolinkWikiRe matches [[name]] wiki references, name being [^]]+.
var autolinkWikiRe = regexp.MustCompile(`\[\[([^\]]+)\]\]`)

// AutolinkWiki rewrites [[name]] wiki-page references into wiki links, using
// resolve to map a page name to its repo path. resolve returns (path, ok);
// only ok=true references become links. Skipping rules mirror AutolinkTasks
// (pre/code/script and existing <a>). href = "/app/org/" + orgID + "/wiki/" + path.
func AutolinkWiki(in []byte, orgID string, resolve func(name string) (path string, ok bool)) []byte {
	if resolve == nil {
		return in
	}
	src := string(in)
	var out strings.Builder
	skipPre := false
	skipA := false
	i := 0
	seg := 0
	for i < len(src) {
		lt := strings.IndexByte(src[i:], '<')
		if lt < 0 {
			break
		}
		lt += i
		if !skipPre && !skipA {
			out.WriteString(wikiLinkify(src[seg:lt], orgID, resolve))
		} else {
			out.WriteString(src[seg:lt])
		}
		seg = lt

		tagEnd := strings.IndexByte(src[lt:], '>')
		if tagEnd < 0 {
			break
		}
		tagEnd += lt
		tag := src[lt : tagEnd+1]
		low := strings.ToLower(tag)
		closing := strings.HasPrefix(low, "</")
		switch {
		case !closing && (strings.Contains(low, "<pre") || strings.Contains(low, "<code") || strings.Contains(low, "<script")):
			skipPre = true
		case closing && (strings.Contains(low, "</pre>") || strings.Contains(low, "</code>") || strings.Contains(low, "</script>")):
			skipPre = false
		case !closing && strings.Contains(low, "<a "):
			skipA = true
		case closing && strings.Contains(low, "</a>"):
			skipA = false
		}
		i = tagEnd + 1
		seg = i
	}
	if seg < len(src) {
		if !skipPre && !skipA {
			out.WriteString(wikiLinkify(src[seg:], orgID, resolve))
		} else {
			out.WriteString(src[seg:])
		}
	}
	return []byte(out.String())
}

// wikiLinkify replaces [[name]] in one text segment with a wiki link when
// resolve reports the page exists.
func wikiLinkify(seg, orgID string, resolve func(name string) (path string, ok bool)) string {
	return autolinkWikiRe.ReplaceAllStringFunc(seg, func(m string) string {
		name := m[2 : len(m)-2] // strip [[ ]]
		path, ok := resolve(name)
		if !ok {
			return m
		}
		return `<a href="/app/org/` + orgID + `/wiki/` + path + `">` + name + `</a>`
	})
}
