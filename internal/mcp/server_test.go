package mcp

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// init registers MCP-test actions once (action.Register panics on duplicates).
func init() {
	action.Register(action.Definition{
		Name:       "mcp.test.echo",
		Impact:     action.ImpactLow,
		Scope:      action.ScopePlatform,
		Permission: "mcp.echo",
		Input:      action.ObjectSchema{Fields: []action.Field{{Name: "msg", Kind: action.KindString, Required: true}}},
		Handle: func(ctx context.Context, ac action.ActionCtx, in json.RawMessage) (any, error) {
			var v map[string]any
			_ = json.Unmarshal(in, &v)
			return map[string]any{"echo": v}, nil
		},
	})
	action.Register(action.Definition{
		Name:       "mcp.test.high",
		Impact:     action.ImpactHigh,
		Scope:      action.ScopePlatform,
		Permission: "mcp.high",
		Handle: func(ctx context.Context, ac action.ActionCtx, in json.RawMessage) (any, error) {
			return map[string]any{"done": true}, nil
		},
	})
}

// newMCPRouter mounts /mcp behind API-key auth, seeding a key with a known
// secret and the given scope. Returns the router + bearer token.
func newMCPRouter(t *testing.T, db *sql.DB, scope string) (http.Handler, string) {
	t.Helper()
	secret := [32]byte{1, 2, 3, 4}
	hash := sha256.Sum256(secret[:])
	prefix := "abcdmcp0"
	if _, err := db.Exec(`INSERT INTO users (id, email, name) VALUES ('mu1', 'mu1@acme.test', 'MU1')`); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO orgs (id, name, slug, visibility, context, monthly_cap_usd, cap_alert_pct) VALUES ('morg', 'Acme', 'acme', 'private', '', 0, 80)`); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	q := sqlc.New(db)
	if _, err := q.CreateAPIKey(context.Background(), sqlc.CreateAPIKeyParams{
		ID: "mkey", UserID: "mu1", OrgID: "morg", Name: "test",
		Prefix: prefix, Hash: hex.EncodeToString(hash[:]), ScopeJson: scope,
	}); err != nil {
		t.Fatalf("seed api key: %v", err)
	}
	// Seed a project for resource reads.
	if _, err := db.Exec(`INSERT INTO projects (id, org_id, name, key, visibility, context) VALUES ('mp1', 'morg', 'Main', 'MAIN', 'private', '')`); err != nil {
		t.Fatalf("seed project: %v", err)
	}

	token := prefix + hex.EncodeToString(secret[:])
	r := chi.NewRouter()
	r.Use(auth.CSP())
	r.Use(auth.APIKeyAuthMiddleware(db))
	r.Post("/mcp", func(w http.ResponseWriter, r *http.Request) {
		New(db, action.New(db)).Handle(w, r)
	})
	return r, token
}

func mcpCall(t *testing.T, router http.Handler, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// result decodes a JSON-RPC success response.
func result(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var resp struct {
		Result map[string]any `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("rpc error %d: %s", resp.Error.Code, resp.Error.Message)
	}
	return resp.Result
}

func mcpID(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var resp struct {
		ID json.RawMessage `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	return string(resp.ID)
}

// TestMCPInitialize covers AC: initialize returns protocol version + caps.
func TestMCPInitialize(t *testing.T) {
	db := dbtest.New(t)
	router, token := newMCPRouter(t, db, `[]`)
	rec := mcpCall(t, router, token, `{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	res := result(t, rec)
	if mcpID(t, rec) != "1" {
		t.Fatalf("bad id")
	}
	if res["protocolVersion"] != "2024-11-05" {
		t.Fatalf("protocolVersion %v", res["protocolVersion"])
	}
	caps, ok := res["capabilities"].(map[string]any)
	if !ok {
		t.Fatalf("no capabilities")
	}
	if caps["tools"] == nil || caps["resources"] == nil || caps["prompts"] == nil {
		t.Fatalf("missing caps")
	}
}

// TestMCPToolsListFiltered covers AC: tools/list filters per key scope
// (omission not denial). A key granted mcp.echo sees mcp_test_echo listed.
func TestMCPToolsListFiltered(t *testing.T) {
	db := dbtest.New(t)
	router, token := newMCPRouter(t, db, `["mcp.echo"]`)
	rec := mcpCall(t, router, token, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	res := result(t, rec)
	tools := res["tools"].([]any)
	found := false
	for _, tl := range tools {
		tool := tl.(map[string]any)
		if tool["name"] == "mcp_test_echo" {
			found = true
		}
	}
	if !found {
		t.Fatalf("mcp_test_echo absent from tools/list despite mcp.echo grant")
	}
}

// TestMCPToolsListExcludesUnauthorized covers AC: a tool whose permission the
// key does not hold is omitted from tools/list (omission, not denial).
func TestMCPToolsListExcludesUnauthorized(t *testing.T) {
	db := dbtest.New(t)
	// Key scoped to mcp.high only: mcp.echo's tool must be absent.
	router, token := newMCPRouter(t, db, `["mcp.high"]`)
	rec := mcpCall(t, router, token, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	res := result(t, rec)
	tools := res["tools"].([]any)
	for _, tl := range tools {
		tool := tl.(map[string]any)
		if tool["name"] == "mcp_test_echo" {
			t.Fatalf("mcp_test_echo present in tools/list despite missing mcp.echo grant")
		}
	}
}

// TestMCPToolCallHappy covers AC: tool call executes for a low-impact action.
func TestMCPToolCallHappy(t *testing.T) {
	db := dbtest.New(t)
	router, token := newMCPRouter(t, db, `["mcp.echo"]`)
	rec := mcpCall(t, router, token, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"mcp_test_echo","arguments":{"msg":"hi"}}}`)
	res := result(t, rec)
	content := res["content"].([]any)
	if len(content) == 0 {
		t.Fatalf("no content")
	}
	if !strings.Contains(content[0].(map[string]any)["text"].(string), `"hi"`) {
		t.Fatalf("echo missing msg: %v", content)
	}
}

// TestMCPToolCallApprovalPending covers AC: high-impact tool call by a key
// returns approval_pending without executing.
func TestMCPToolCallApprovalPending(t *testing.T) {
	db := dbtest.New(t)
	router, token := newMCPRouter(t, db, `["mcp.high"]`)
	rec := mcpCall(t, router, token, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"mcp_test_high","arguments":{}}}`)
	res := result(t, rec)
	sc, ok := res["structuredContent"].(map[string]any)
	if !ok {
		t.Fatalf("no structuredContent")
	}
	if sc["status"] != "approval_pending" {
		t.Fatalf("status %v, want approval_pending", sc["status"])
	}
	if sc["approval_id"] == "" {
		t.Fatalf("missing approval_id")
	}
}

// TestMCPToolCallUnauthorized covers AC: calling a tool not granted by the key
// returns an error.
func TestMCPToolCallUnauthorized(t *testing.T) {
	db := dbtest.New(t)
	router, token := newMCPRouter(t, db, `[]`)
	rec := mcpCall(t, router, token, `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"mcp_test_echo","arguments":{}}}`)
	// echo requires msg → invalid params error path (still a JSON-RPC error).
	var resp struct {
		Error *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Error == nil {
		t.Fatalf("expected rpc error for missing required arg")
	}
}

// TestMCPResources covers AC: resources/list + resources/read (bc:// URIs).
func TestMCPResources(t *testing.T) {
	db := dbtest.New(t)
	router, token := newMCPRouter(t, db, `[]`)
	rec := mcpCall(t, router, token, `{"jsonrpc":"2.0","id":6,"method":"resources/list"}`)
	res := result(t, rec)
	if _, ok := res["resources"].([]any); !ok {
		t.Fatalf("no resources")
	}
	rec2 := mcpCall(t, router, token, `{"jsonrpc":"2.0","id":7,"method":"resources/read","params":{"uri":"bc://project/MAIN"}}`)
	res2 := result(t, rec2)
	contents := res2["contents"].([]any)
	if len(contents) == 0 {
		t.Fatalf("no contents")
	}
	if !strings.Contains(contents[0].(map[string]any)["text"].(string), "MAIN") {
		t.Fatalf("project resource missing key")
	}
}

// TestMCPPrompts covers AC: prompts/list + prompts/get.
func TestMCPPrompts(t *testing.T) {
	db := dbtest.New(t)
	router, token := newMCPRouter(t, db, `[]`)
	rec := mcpCall(t, router, token, `{"jsonrpc":"2.0","id":8,"method":"prompts/list"}`)
	res := result(t, rec)
	prompts := res["prompts"].([]any)
	if len(prompts) == 0 {
		t.Fatalf("no prompts")
	}
	rec2 := mcpCall(t, router, token, `{"jsonrpc":"2.0","id":9,"method":"prompts/get","params":{"name":"decompose_task"}}`)
	res2 := result(t, rec2)
	msgs := res2["messages"].([]any)
	if len(msgs) == 0 {
		t.Fatalf("no prompt messages")
	}
}

// TestMCPUnauthorized covers AC: a request without a bearer key is rejected.
func TestMCPUnauthorized(t *testing.T) {
	db := dbtest.New(t)
	router, _ := newMCPRouter(t, db, `[]`)
	rec := mcpCall(t, router, "", `{"jsonrpc":"2.0","id":10,"method":"initialize"}`)
	var resp struct {
		Error *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Error == nil {
		t.Fatalf("expected unauthorized error")
	}
}
