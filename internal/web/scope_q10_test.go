package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// WU-603a / Q10 through the three HTTP entry points. The registry-wide
// dispatch test lives in internal/perm (scope_q10_test.go).

func (h *idpWeb) count(q string, args ...any) int {
	h.t.Helper()
	var n int
	if err := h.db.QueryRow(q, args...).Scan(&n); err != nil {
		h.t.Fatalf("%s: %v", q, err)
	}
	return n
}

func (h *idpWeb) postJSON(path string, s idpSession, body string) *httptest.ResponseRecorder {
	h.t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(auth.CSRFHeader, s.csrf)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: s.raw})
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)
	return rec
}

func TestQ10WebActionRefusesOrgOwnerPlatformAction(t *testing.T) {
	h := newIdPWeb(t)
	owner := h.session("u-owner")
	admin := h.session("u-admin")
	orgs0 := h.count(`SELECT COUNT(*) FROM orgs`)

	// org_id in the form body used to become Opts.Org and pass on org-a's "*".
	rec := h.post("/api/action/org.create", &owner, url.Values{"name": {"Evil"}, "slug": {"evil"}, "org_id": {"org-a"}})
	if rec.Code == http.StatusOK || !strings.Contains(rec.Body.String(), "forbidden") {
		t.Fatalf("org.create as org owner with org_id: %d %s", rec.Code, rec.Body.String())
	}
	req := httptest.NewRequest(http.MethodPost, "/api/action/pricing.upsert",
		strings.NewReader(`{"provider_id":"p","model":"m","input_per_mtok":1,"output_per_mtok":1}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-Id", "org-a")
	req.Header.Set(auth.CSRFHeader, owner.csrf)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: owner.raw})
	rec = httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK || !strings.Contains(rec.Body.String(), "forbidden") {
		t.Fatalf("pricing.upsert as org owner with X-Org-Id: %d %s", rec.Code, rec.Body.String())
	}
	if n := h.count(`SELECT COUNT(*) FROM orgs`); n != orgs0 {
		t.Fatalf("orgs %d → %d after refused calls", orgs0, n)
	}

	rec = h.post("/api/action/org.create", &admin, url.Values{"name": {"Fine"}, "slug": {"fine"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("org.create as platform admin: %d %s", rec.Code, rec.Body.String())
	}
	if n := h.count(`SELECT COUNT(*) FROM orgs WHERE slug='fine'`); n != 1 {
		t.Fatal("platform admin's org.create did not create the org")
	}
}

func TestQ10WebSelfActionsForPlainUser(t *testing.T) {
	h := newIdPWeb(t)
	plain := h.session("u-plain")
	if _, err := h.db.Exec(`INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ('h-other','u-owner','2099-01-01'),('h-plain2','u-plain','2099-01-01')`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`INSERT INTO notifications (id, org_id, user_id, event_name) VALUES ('n-plain','org-a','u-plain','x'),('n-owner','org-a','u-owner','x')`); err != nil {
		t.Fatal(err)
	}

	// Settings page forms (no grants at all).
	if rec := h.post("/api/action/user.theme.update", &plain, url.Values{"theme": {"dark"}}); rec.Code != http.StatusOK {
		t.Fatalf("user.theme.update: %d %s", rec.Code, rec.Body.String())
	}
	if n := h.count(`SELECT COUNT(*) FROM users WHERE id='u-plain' AND theme='dark'`); n != 1 {
		t.Fatal("theme not updated")
	}
	// The same form carrying an org id is refused.
	if rec := h.post("/api/action/user.timezone.update", &plain, url.Values{"timezone": {"UTC"}, "org_id": {"org-a"}}); rec.Code == http.StatusOK {
		t.Fatal("self action accepted an org id")
	}

	// Sessions page: another user's session cannot be revoked; own can.
	if rec := h.postJSON("/api/action/session.revoke", plain, `{"token_hash":"h-other"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("revoke another user's session: %d %s", rec.Code, rec.Body.String())
	}
	if n := h.count(`SELECT COUNT(*) FROM sessions WHERE token_hash='h-other'`); n != 1 {
		t.Fatal("another user's session was deleted")
	}
	if rec := h.postJSON("/api/action/session.revoke", plain, `{"token_hash":"h-plain2"}`); rec.Code != http.StatusOK {
		t.Fatalf("revoke own session: %d %s", rec.Code, rec.Body.String())
	}
	if n := h.count(`SELECT COUNT(*) FROM sessions WHERE token_hash='h-plain2'`); n != 0 {
		t.Fatal("own session not revoked")
	}

	// Notifications: mark-read endpoints now dispatch the ScopeSelf actions.
	if rec := h.postJSON("/api/notif/mark-read", plain, `{"id":"n-owner"}`); rec.Code != http.StatusOK {
		t.Fatalf("mark-read: %d %s", rec.Code, rec.Body.String())
	}
	if rec := h.postJSON("/api/notif/mark-all-read", plain, `{}`); rec.Code != http.StatusOK {
		t.Fatalf("mark-all-read: %d %s", rec.Code, rec.Body.String())
	}
	if n := h.count(`SELECT COUNT(*) FROM notifications WHERE id='n-owner' AND read_at=''`); n != 1 {
		t.Fatal("another user's notification was marked read")
	}
	if n := h.count(`SELECT COUNT(*) FROM notifications WHERE id='n-plain' AND read_at<>''`); n != 1 {
		t.Fatal("own notification not marked read")
	}
}

// TestQ10APIKeyEntryPoints covers /api/v1/actions/{name} and /mcp with an API
// key owned by an org Owner.
func TestQ10APIKeyEntryPoints(t *testing.T) {
	h := newIdPWeb(t)
	secret := [32]byte{9, 9, 9}
	hash := sha256.Sum256(secret[:])
	prefix := "q10key01"
	if _, err := sqlc.New(h.db).CreateAPIKey(context.Background(), sqlc.CreateAPIKeyParams{
		ID: "key-owner", UserID: "u-owner", OrgID: "org-a", Name: "owner key",
		Prefix: prefix, Hash: hex.EncodeToString(hash[:]),
		ScopeJson: `["provider.list","provider.create","user.theme.update"]`,
	}); err != nil {
		t.Fatal(err)
	}
	token := prefix + hex.EncodeToString(secret[:])
	r := chi.NewRouter()
	r.Use(auth.CSP())
	r.Use(auth.APIKeyAuthMiddleware(h.db))
	Routes(r)
	resetV1()

	call := func(path, body string, hdr map[string]string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}

	// REST RPC: X-Org-Id on a platform action is refused at dispatch.
	rec := call("/api/v1/actions/provider.create", `{"name":"evil","base_url":"https://x.test","api_key":"k"}`, map[string]string{"X-Org-Id": "org-a"})
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "takes no org") {
		t.Fatalf("rpc provider.create with X-Org-Id: %d %s", rec.Code, rec.Body.String())
	}
	if rec := call("/api/v1/actions/provider.list", `{}`, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("rpc provider.list without org: %d %s", rec.Code, rec.Body.String())
	}
	// Self actions need a signed-in user, not an API key.
	if rec := call("/api/v1/actions/user.theme.update", `{"theme":"dark"}`, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("rpc user.theme.update via API key: %d %s", rec.Code, rec.Body.String())
	}
	var n int
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM providers`).Scan(&n)
	if n != 0 {
		t.Fatalf("providers = %d after refused calls", n)
	}

	// MCP: tools/list omits self actions; a platform tool call is refused.
	rec = call("/mcp", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, nil)
	if strings.Contains(rec.Body.String(), "user_theme_update") || !strings.Contains(rec.Body.String(), "provider_list") {
		t.Fatalf("mcp tools/list: %s", rec.Body.String())
	}
	rec = call("/mcp", `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"provider_list","arguments":{"org_id":"org-a"}}}`, nil)
	var res struct {
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	if res.Error == nil || !strings.Contains(res.Error.Message, "forbidden") {
		t.Fatalf("mcp provider_list as org owner key: %s", rec.Body.String())
	}
	rec = call("/mcp", `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"user_theme_update","arguments":{"theme":"dark"}}}`, nil)
	res.Error = nil
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	if res.Error == nil {
		t.Fatalf("mcp self tool via API key: %s", rec.Body.String())
	}
}
