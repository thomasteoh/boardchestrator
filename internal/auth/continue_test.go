package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/auth/oidctest"
)

// WU-614: a form submission that leads to an identity provider must not
// answer with a cross-origin redirect, because CSP form-action 'self'
// makes the browser block it. ContinueTo answers 200 with a meta refresh.
func TestContinueTo(t *testing.T) {
	dest := `https://idp.example/end?id_token_hint=a.b.c&state=x"><script>`
	rec := httptest.NewRecorder()
	ContinueTo(rec, dest)
	resp := rec.Result()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Location") != "" {
		t.Fatalf("status %d location %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("headers %v", resp.Header)
	}
	body := rec.Body.String()
	if strings.Contains(body, "<script>") || strings.Contains(body, `x">`) {
		t.Fatalf("destination not escaped: %s", body)
	}
	if got := oidctest.NextURL(rec.Result()); got != dest {
		t.Fatalf("continue target %q, want %q", got, dest)
	}
}

func TestCSPFormActionSelf(t *testing.T) {
	if !strings.Contains(cspPolicy("n"), "form-action 'self'") {
		t.Fatal("CSP lost form-action 'self'; ContinueTo exists because of it")
	}
}
