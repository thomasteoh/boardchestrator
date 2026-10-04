package auth

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Claim helpers shared by the connectors (internal/auth/idp) and login
// resolution, which reads an org's group-claim override (WU-608).

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

// claimScalar formats a string or number claim; anything else is "".
func claimScalar(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64, json.Number, int, int64, bool:
		return fmt.Sprint(t)
	}
	return ""
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
			add(claimScalar(e))
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
