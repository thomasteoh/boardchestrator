package idp

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// ClaimMap names the claim each assertion field is read from (SPEC §7.1).
// A value is a claim name or a dotted path into nested objects
// ("realm_access.roles"); names that themselves contain dots or colons
// ("https://example.com/groups", "urn:zitadel:iam:org:project:roles") work
// because an exact key match is tried before splitting. An empty value means
// "not provided by this IdP": in particular an empty EmailVerified means the
// email is never treated as verified.
type ClaimMap struct {
	Email         string `json:"email"`
	EmailVerified string `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	Groups        string `json:"groups"`
}

// standardClaims is the OIDC Core standard claim set, without groups.
var standardClaims = ClaimMap{
	Email:         "email",
	EmailVerified: "email_verified",
	Name:          "name",
	Picture:       "picture",
}

// Overlay returns m with every field present in raw (a claim_map_json
// object) replaced, including by "" to unmap a claim. Unknown keys are an
// error so a typo is not silently ignored.
func (m ClaimMap) Overlay(raw string) (ClaimMap, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "{}" {
		return m, nil
	}
	var over map[string]string
	if err := json.Unmarshal([]byte(raw), &over); err != nil {
		return m, fmt.Errorf("claim map: %w", err)
	}
	for k, v := range over {
		switch k {
		case "email":
			m.Email = v
		case "email_verified":
			m.EmailVerified = v
		case "name":
			m.Name = v
		case "picture":
			m.Picture = v
		case "groups":
			m.Groups = v
		default:
			return m, fmt.Errorf("claim map: unknown field %q", k)
		}
	}
	return m, nil
}

// LookupClaim finds path in claims: an exact key first, then a dotted walk
// through nested objects, trying the longest key prefix at each level.
func LookupClaim(claims map[string]any, path string) (any, bool) {
	if path == "" || claims == nil {
		return nil, false
	}
	if v, ok := claims[path]; ok {
		return v, true
	}
	for i := len(path) - 1; i > 0; i-- {
		if path[i] != '.' {
			continue
		}
		sub, ok := claims[path[:i]].(map[string]any)
		if !ok {
			continue
		}
		if v, ok := LookupClaim(sub, path[i+1:]); ok {
			return v, true
		}
	}
	return nil, false
}

// claimString reads a string claim; numbers are formatted, anything else is "".
func claimString(claims map[string]any, path string) string {
	v, _ := LookupClaim(claims, path)
	return scalarString(v)
}

func scalarString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64, json.Number, int, int64, bool:
		return fmt.Sprint(t)
	}
	return ""
}

// claimBool reads a boolean claim, accepting JSON true and the string
// "true" (some IdPs emit strings). Anything else, or absence, is false.
func claimBool(claims map[string]any, path string) bool {
	v, _ := LookupClaim(claims, path)
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(t, "true")
	}
	return false
}

// ClaimGroups extracts group values from the claim at path. Supported shapes:
// a string (one group), an array of strings or numbers, and an object whose
// keys are the groups (Zitadel's role claim:
// {"admin": {"<org id>": "<domain>"}}). The result is sorted and
// de-duplicated; empty values are dropped.
func ClaimGroups(claims map[string]any, path string) []string {
	v, ok := LookupClaim(claims, path)
	if !ok {
		return nil
	}
	seen := map[string]struct{}{}
	add := func(s string) {
		if s = strings.TrimSpace(s); s != "" {
			seen[s] = struct{}{}
		}
	}
	switch t := v.(type) {
	case string:
		add(t)
	case []any:
		for _, e := range t {
			add(scalarString(e))
		}
	case []string:
		for _, e := range t {
			add(e)
		}
	case map[string]any:
		for k := range t {
			add(k)
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
