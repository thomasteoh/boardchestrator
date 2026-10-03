package auth_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/auth/oidctest"
	"github.com/thomasteoh/boardchestrator/internal/tenant"
)

const (
	ghClientID    = "gh-client"
	ghClientSec   = "gh-SECRET-do-not-leak"
	ghAccessToken = "gho_test_access_token"
)

// fakeGitHub is an httptest stand-in for github.com + api.github.com.
type fakeGitHub struct {
	srv *httptest.Server

	mu         sync.Mutex
	tokenURLs  []string
	tokenForms []url.Values
	tokenCType string
	failToken  bool
	userID     int64
	email      string
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	f := &fakeGitHub{userID: 4242, email: "octo@example.com"}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login/oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		dest, _ := url.Parse(q.Get("redirect_uri"))
		v := dest.Query()
		v.Set("code", "gh-code")
		v.Set("state", q.Get("state"))
		dest.RawQuery = v.Encode()
		http.Redirect(w, r, dest.String(), http.StatusFound)
	})
	mux.HandleFunc("POST /login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		f.tokenURLs = append(f.tokenURLs, r.URL.String())
		f.tokenForms = append(f.tokenForms, r.PostForm)
		f.tokenCType = r.Header.Get("Content-Type")
		fail := f.failToken
		f.mu.Unlock()
		if fail {
			http.Error(w, "UPSTREAM failure detail with client_secret echo "+r.PostForm.Get("client_secret"), http.StatusInternalServerError)
			return
		}
		if r.PostForm.Get("client_secret") != ghClientSec || r.PostForm.Get("code") != "gh-code" {
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "bad_verification_code"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": ghAccessToken, "token_type": "bearer"})
	})
	mux.HandleFunc("GET /user", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+ghAccessToken {
			http.Error(w, "nope", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": f.userID, "login": "octo", "name": "", "avatar_url": "https://avatars/x"})
	})
	mux.HandleFunc("GET /user/emails", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"email": "other@example.com", "primary": false, "verified": true},
			{"email": f.email, "primary": true, "verified": true},
		})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func newGitHubHarness(t *testing.T, f *fakeGitHub, key []byte) *loginHarness {
	return newLoginHarness(t, harnessOpts{
		encKey: key,
		github: &auth.GitHubConfig{
			ClientID: ghClientID, ClientSecret: ghClientSec,
			WebBase: f.srv.URL, APIBase: f.srv.URL,
		},
	})
}

func TestGitHubLoginSecretInBodyNotURL(t *testing.T) {
	f := newFakeGitHub(t)
	key := tenant.PadKey("test-encryption-key-32-bytes-long!!")
	lh := newGitHubHarness(t, f, key)

	b := oidctest.NewBrowser(t)
	steps, err := b.Follow(lh.app.URL+"/auth/github", 5, nil)
	if err != nil {
		t.Fatal(err)
	}
	end := last(steps)
	if end.Status != http.StatusOK || !strings.HasPrefix(end.Body, "user=") {
		t.Fatalf("github login ended %d %q", end.Status, end.Body)
	}
	f.mu.Lock()
	urls, forms, ctype := f.tokenURLs, f.tokenForms, f.tokenCType
	f.mu.Unlock()
	if len(urls) != 1 {
		t.Fatalf("token requests = %d", len(urls))
	}
	if strings.Contains(urls[0], ghClientSec) || strings.Contains(urls[0], "client_secret") || strings.Contains(urls[0], "?") {
		t.Errorf("token URL carries parameters: %q", urls[0])
	}
	if forms[0].Get("client_secret") != ghClientSec || forms[0].Get("client_id") != ghClientID {
		t.Errorf("credentials missing from body: %v", forms[0])
	}
	if ctype != "application/x-www-form-urlencoded" {
		t.Errorf("token request content type %q", ctype)
	}

	// Identity is (github, "4242"), name falls back to login, and the
	// access token is stored encrypted for WU-406.
	userID := strings.TrimPrefix(end.Body, "user=")
	var tokEnc []byte
	if err := lh.db.QueryRow(`SELECT token_enc FROM identities WHERE provider='github' AND subject='4242' AND user_id=?`, userID).Scan(&tokEnc); err != nil {
		t.Fatalf("github identity: %v", err)
	}
	if got, err := tenant.Decrypt(key, string(tokEnc)); err != nil || got != ghAccessToken {
		t.Errorf("stored token = %q, %v", got, err)
	}
	if n := lh.count(`SELECT COUNT(*) FROM users WHERE id = ? AND email = 'octo@example.com' AND name = 'octo'`, userID); n != 1 {
		t.Error("github user profile not stored")
	}

	// Second GitHub login: same user.
	end2 := last(mustFollow(t, oidctest.NewBrowser(t), lh.app.URL+"/auth/github"))
	if end2.Body != end.Body {
		t.Errorf("second github login %q, want %q", end2.Body, end.Body)
	}
}

func TestGitHubLoginLinksExistingGoogleUser(t *testing.T) {
	f := newFakeGitHub(t)
	f.email = "user1@example.com" // oidctest default user's email
	lh := newGitHubHarness(t, f, nil)
	g := last(lh.login(oidctest.NewBrowser(t), ""))
	gh := last(mustFollow(t, oidctest.NewBrowser(t), lh.app.URL+"/auth/github"))
	if g.Body == "" || g.Body != gh.Body {
		t.Errorf("google %q vs github %q: want same user", g.Body, gh.Body)
	}
}

func TestGitHubUpstreamErrorsNotReflected(t *testing.T) {
	t.Run("token endpoint 500", func(t *testing.T) {
		f := newFakeGitHub(t)
		f.failToken = true
		lh := newGitHubHarness(t, f, nil)
		end := last(mustFollow(t, oidctest.NewBrowser(t), lh.app.URL+"/auth/github"))
		if end.Status != http.StatusForbidden {
			t.Errorf("status %d", end.Status)
		}
		assertNoLeak(t, end.Body, ghClientSec, f.srv.URL)
	})
	t.Run("transport failure", func(t *testing.T) {
		f := newFakeGitHub(t)
		lh := newGitHubHarness(t, f, nil)
		b := oidctest.NewBrowser(t)
		cb, err := b.Follow(lh.app.URL+"/auth/github", 5, func(next *url.URL) bool {
			return strings.HasSuffix(next.Path, "/callback")
		})
		if err != nil {
			t.Fatal(err)
		}
		f.srv.Close() // GitHub goes away between authorize and callback
		resp, err := b.Get(cb[len(cb)-1].URL)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status %d", resp.StatusCode)
		}
		assertNoLeak(t, string(body), ghClientSec, f.srv.URL)
	})
}

func mustFollow(t *testing.T, b *oidctest.Browser, u string) []oidctest.Step {
	t.Helper()
	steps, err := b.Follow(u, 5, nil)
	if err != nil {
		t.Fatal(err)
	}
	return steps
}
