package views

import (
	"strings"
	"unicode"
)

// presetMarks are the sign-in button monograms per provider preset.
var presetMarks = map[string]string{
	"google":    "G",
	"microsoft": "M",
	"github":    "GH",
	"gitlab":    "GL",
	"okta":      "O",
	"auth0":     "A0",
	"keycloak":  "K",
	"zitadel":   "Z",
	"authentik": "a",
}

func presetMonogram(preset, name string) string {
	if m, ok := presetMarks[preset]; ok {
		return m
	}
	for _, r := range strings.TrimSpace(name) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return strings.ToUpper(string(r))
		}
	}
	return "?"
}

// presetMarkClass is the CSS modifier for a preset's badge colour; unknown
// presets share the generic style.
func presetMarkClass(preset string) string {
	if _, ok := presetMarks[preset]; ok {
		return preset
	}
	return "generic"
}
