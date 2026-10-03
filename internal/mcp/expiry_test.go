package mcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
)

// TestMCPExpiredKey (WU-613, SPEC §7.10): an expired key is refused by the
// API-key middleware, and the MCP handler's own key lookup refuses a key
// that expires after the middleware let the request through.
func TestMCPExpiredKey(t *testing.T) {
	db := dbtest.New(t)
	router, token := newMCPRouter(t, db, `[]`)
	initReq := `{"jsonrpc":"2.0","id":1,"method":"initialize"}`
	if rec := mcpCall(t, router, token, initReq); rec.Code != http.StatusOK {
		t.Fatalf("live key: %d", rec.Code)
	}
	// A future expiry still works.
	if _, err := db.Exec(`UPDATE api_keys SET expires_at='2999-01-01T00:00:00.000Z' WHERE id='mkey'`); err != nil {
		t.Fatal(err)
	}
	if rec := mcpCall(t, router, token, initReq); rec.Code != http.StatusOK {
		t.Fatalf("unexpired key: %d", rec.Code)
	}
	if _, err := db.Exec(`UPDATE api_keys SET expires_at='2000-01-01T00:00:00.000Z' WHERE id='mkey'`); err != nil {
		t.Fatal(err)
	}
	if rec := mcpCall(t, router, token, initReq); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expired key through the middleware: %d", rec.Code)
	}

	// Expire the key between the middleware and the handler.
	if _, err := db.Exec(`UPDATE api_keys SET expires_at=NULL WHERE id='mkey'`); err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	r.Use(auth.APIKeyAuthMiddleware(db))
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if _, err := db.Exec(`UPDATE api_keys SET expires_at='2000-01-01T00:00:00.000Z' WHERE id='mkey'`); err != nil {
				t.Error(err)
			}
			next.ServeHTTP(w, req)
		})
	})
	r.Post("/mcp", func(w http.ResponseWriter, req *http.Request) { New(db, action.New(db)).Handle(w, req) })
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(initReq))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "unauthorized") || strings.Contains(rec.Body.String(), "protocolVersion") {
		t.Fatalf("handler lookup accepted an expired key: %d %s", rec.Code, rec.Body.String())
	}
}

// TestAPIKeyWrongSecret: the right prefix with a wrong secret is refused
// (the hash compare is constant-time, action.APIKeyHashMatches).
func TestAPIKeyWrongSecret(t *testing.T) {
	db := dbtest.New(t)
	router, token := newMCPRouter(t, db, `[]`)
	bad := token[:8] + strings.Repeat("0", 64)
	if rec := mcpCall(t, router, bad, `{"jsonrpc":"2.0","id":1,"method":"initialize"}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong secret: %d", rec.Code)
	}
	if !action.APIKeyHashMatches("ab", "ab") || action.APIKeyHashMatches("ab", "ac") || action.APIKeyHashMatches("ab", "abc") {
		t.Fatal("APIKeyHashMatches")
	}
}
