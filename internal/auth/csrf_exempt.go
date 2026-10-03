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
// list): passkey login finish (WU-612).
var csrfExemptions = [...]CSRFExemption{
	// OIDC Back-Channel Logout 1.0: a server-to-server POST from the IdP,
	// authenticated by the signed logout_token (WU-609).
	{Method: http.MethodPost, Pattern: BackChannelLogoutPattern},
	// SAML ACS: the IdP's cross-site HTTP-POST binding response, verified by
	// its XML signature and bound to the SameSite=None flow cookie (WU-610).
	{Method: http.MethodPost, Pattern: SAMLACSPattern},
	// SAML SLO, HTTP-POST binding: a signed LogoutRequest or LogoutResponse
	// from the IdP (WU-610).
	{Method: http.MethodPost, Pattern: SAMLSLOPattern},
	// SCIM 2.0 provisioning: server-to-server calls from the org's IdP,
	// authenticated by a bearer SCIM token (WU-611). Every method the SCIM
	// handler serves, including the safe ones, so the session middleware
	// never resolves a cookie there either.
	{Method: http.MethodGet, Pattern: SCIMPattern},
	{Method: http.MethodPost, Pattern: SCIMPattern},
	{Method: http.MethodPut, Pattern: SCIMPattern},
	{Method: http.MethodPatch, Pattern: SCIMPattern},
	{Method: http.MethodDelete, Pattern: SCIMPattern},
}

// SCIMPattern matches everything under the SCIM base path /scim/v2.
const SCIMPattern = "/scim/v2/*"

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
