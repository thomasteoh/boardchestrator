package web

import (
	"html"
	"regexp"
	"strings"
	"testing"
)

// WU-614: browsers compile an input's pattern attribute with the RegExp v
// flag, where a literal '-' at either end of a character class is a syntax
// error. Chromium then ignores the pattern and logs an error, so the
// provider id field had no client-side check. Found with a real browser.
func TestFormPatternsValidUnderVFlag(t *testing.T) {
	h := newIdPWeb(t)
	admin := h.session("u-admin")
	page := h.get("/admin/identity-providers/new?preset=keycloak", &admin).Body.String()
	pats := regexp.MustCompile(`pattern="([^"]*)"`).FindAllStringSubmatch(page, -1)
	if len(pats) == 0 {
		t.Fatal("provider form has no pattern attribute")
	}
	// An unescaped '-' straight after '[' or straight before ']'.
	bad := regexp.MustCompile(`\[-|[^\\]-\]`)
	for _, m := range pats {
		p := html.UnescapeString(m[1])
		if bad.MatchString(p) || strings.Contains(p, "--") {
			t.Errorf("pattern %q is invalid under the RegExp v flag (escape '-' as \\-)", p)
		}
		if _, err := regexp.Compile("^(?:" + p + ")$"); err != nil {
			t.Errorf("pattern %q: %v", p, err)
		}
	}
}
