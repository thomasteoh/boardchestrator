package auth

import (
	"net/url"
	"strings"
	"unicode"
)

// DefaultReturnTo is where a sign-in lands when no usable return_to is given.
const DefaultReturnTo = "/app"

// maxReturnTo bounds the stored path; the flow cookie must stay small.
const maxReturnTo = 1024

// SafeReturnTo validates a post-login destination (SPEC §7.2: relative paths
// only) and returns it, or DefaultReturnTo when it is unusable. It is the one
// check shared by GET /login and GET /auth/{providerID}, and the callback
// re-applies it before redirecting.
//
// Accepted: a path starting with a single "/" whose next character is not "/"
// or "\", with no scheme, host, user info, control characters or backslashes,
// optionally followed by a query (no fragment). The raw value is checked as
// well as its percent-decoded forms, so "%2F%2Fevil" and "/%5Cevil" are
// refused even though a browser would only collapse them after decoding.
func SafeReturnTo(raw string) string {
	if raw == "" || len(raw) > maxReturnTo {
		return DefaultReturnTo
	}
	// Check the raw value and up to two rounds of decoding: a value that is
	// still changing after that is refused outright.
	cur := raw
	for i := 0; ; i++ {
		if !plainLocalPath(cur) {
			return DefaultReturnTo
		}
		dec, err := url.PathUnescape(cur)
		if err != nil {
			return DefaultReturnTo
		}
		if dec == cur {
			break
		}
		if i == 2 {
			return DefaultReturnTo
		}
		cur = dec
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Opaque != "" || u.Fragment != "" {
		return DefaultReturnTo
	}
	return raw
}

// plainLocalPath reports whether s looks like a same-origin absolute path.
func plainLocalPath(s string) bool {
	if !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") || strings.HasPrefix(s, "/\\") {
		return false
	}
	for _, r := range s {
		// Browsers treat "\" as "/" in special-scheme URLs and strip tabs
		// and newlines, so "/\evil" and "/\t/evil" become "//evil".
		if r == '\\' || unicode.IsControl(r) || r == unicode.ReplacementChar {
			return false
		}
		if r != ' ' && unicode.IsSpace(r) {
			return false
		}
	}
	return !strings.Contains(s, "#")
}
