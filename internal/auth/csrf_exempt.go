package auth

import (
	"net/http"
	"strings"
)

// CSRFExemption is one route the global CSRF middleware lets through without
// a token (SPEC §7.11). Pattern segments in braces match exactly one
// non-empty path segment; a final "*" matches the rest of the path.
type CSRFExemption struct {
	Method  string
	Pattern string
}

// csrfExemptions is the complete list. Every route on it authenticates by
// other means and never reads the session cookie: the session middleware
// skips these paths too, so SessionFrom is always empty in their handlers.
// Later WUs append their own entries here (and to the test asserting the
// list): SAML ACS and SLO (WU-610), SCIM (WU-611), passkey login finish
// (WU-612).
var csrfExemptions = [...]CSRFExemption{
	// OIDC Back-Channel Logout 1.0: a server-to-server POST from the IdP,
	// authenticated by the signed logout_token (WU-609).
	{Method: http.MethodPost, Pattern: BackChannelLogoutPattern},
}

// CSRFExemptions returns a copy of the exemption list.
func CSRFExemptions() []CSRFExemption {
	return append([]CSRFExemption(nil), csrfExemptions[:]...)
}

// IsCSRFExempt reports whether method and path match an exemption.
func IsCSRFExempt(method, path string) bool {
	for _, e := range csrfExemptions {
		if e.Method == method && matchRoutePattern(e.Pattern, path) {
			return true
		}
	}
	return false
}

// matchRoutePattern matches path against a chi-style pattern: literal
// segments compare exactly, "{name}" matches one non-empty segment, and a
// trailing "*" matches any (possibly empty) remainder.
func matchRoutePattern(pattern, path string) bool {
	ps := strings.Split(strings.TrimPrefix(pattern, "/"), "/")
	xs := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, p := range ps {
		if p == "*" && i == len(ps)-1 {
			return true
		}
		if i >= len(xs) {
			return false
		}
		switch {
		case strings.HasPrefix(p, "{") && strings.HasSuffix(p, "}"):
			if xs[i] == "" {
				return false
			}
		case p != xs[i]:
			return false
		}
	}
	return len(xs) == len(ps)
}
