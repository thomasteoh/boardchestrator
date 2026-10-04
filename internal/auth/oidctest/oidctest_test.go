package oidctest_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/auth/oidctest"
)

// authorize runs /authorize with the given challenge and returns the code.
func authorize(t *testing.T, s *oidctest.Server, challenge string) string {
	t.Helper()
	q := url.Values{
		"client_id": {s.ClientID}, "redirect_uri": {"http://rp.test/cb"}, "response_type": {"code"},
		"state": {"st"}, "nonce": {"n"}, "scope": {"openid"},
	}
	if challenge != "" {
		q.Set("code_challenge", challenge)
		q.Set("code_challenge_method", "S256")
	}
	b := oidctest.NewBrowser(t)
	resp, err := b.Get(s.Issuer() + "/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("authorize did not redirect: %d", resp.StatusCode)
	}
	if loc.Query().Get("state") != "st" {
		t.Fatalf("state not echoed: %s", loc)
	}
	return loc.Query().Get("code")
}

func exchange(t *testing.T, s *oidctest.Server, code, verifier string) (int, map[string]any) {
	t.Helper()
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"http://rp.test/cb"},
		"client_id": {s.ClientID}, "client_secret": {s.ClientSecret}, "code_verifier": {verifier},
	}
	resp, err := http.Post(s.Issuer()+"/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestTokenEnforcesPKCEAndSingleUse(t *testing.T) {
	s := oidctest.New(t)
	verifier := strings.Repeat("v", 43)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	if st, _ := exchange(t, s, authorize(t, s, challenge), "wrong-verifier-"+verifier); st != http.StatusBadRequest {
		t.Errorf("wrong verifier: %d", st)
	}
	if st, _ := exchange(t, s, authorize(t, s, ""), ""); st != http.StatusBadRequest {
		t.Errorf("no PKCE while required: %d", st)
	}
	code := authorize(t, s, challenge)
	st, out := exchange(t, s, code, verifier)
	if st != http.StatusOK || out["id_token"] == nil {
		t.Fatalf("good exchange: %d %v", st, out)
	}
	if st, _ := exchange(t, s, code, verifier); st != http.StatusBadRequest {
		t.Errorf("code reuse: %d", st)
	}
}

func TestUnsignedJWTShape(t *testing.T) {
	tok, err := oidctest.UnsignedJWT(map[string]any{"sub": "x"})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 || parts[2] != "" {
		t.Fatalf("alg none token shape: %q", tok)
	}
	h, _ := base64.RawURLEncoding.DecodeString(parts[0])
	if !strings.Contains(string(h), `"none"`) {
		t.Errorf("header %s", h)
	}
}
