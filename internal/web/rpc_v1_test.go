package web

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
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// init registers the two RPC-test actions exactly once (Register panics on
// duplicates, so this must not run per-test).
func init() {
	action.Register(action.Definition{
		Name:   "test.ping",
		Impact: action.ImpactLow,
		Scope:  action.ScopePlatform,
		Input:  action.ObjectSchema{Fields: []action.Field{{Name: "name", Kind: action.KindString, Required: true}}},
		Handle: func(ctx context.Context, ac action.ActionCtx, in json.RawMessage) (any, error) {
			var v map[string]any
			_ = json.Unmarshal(in, &v)
			return map[string]any{"pong": true, "echo": v}, nil
		},
	})
	action.Register(action.Definition{
		Name:   "test.scope",
		Impact: action.ImpactLow,
		Scope:  action.ScopeOrg,
		Handle: func(ctx context.Context, ac action.ActionCtx, in json.RawMessage) (any, error) {
			return nil, action.ErrScope
		},
	})
}

// newV1Router mounts the v1 RPC behind CSP + API-key middleware (mirroring
// production server.setupMiddleware), seeding an API key with a known secret.
// Returns the router and the bearer token to authenticate requests.
func newV1Router(t *testing.T, db *sql.DB) (http.Handler, string) {
	t.Helper()
	secret := [32]byte{1, 2, 3, 4}
	hash := sha256.Sum256(secret[:])
	prefix := "abcdef01"
	// Wire a real dispatcher for the RPC handler (defaults: noop scope + allow-all).
	SetDispatcher(action.New(db))
	// Seed the user + org the API key references.
	if _, err := db.Exec(`INSERT INTO users (id, email, name) VALUES ('u1', 'u1@acme.test', 'U1')`); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO orgs (id, name, slug, visibility, context, monthly_cap_usd, cap_alert_pct) VALUES ('org1', 'Acme', 'acme', 'private', '', 0, 80)`); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	q := sqlc.New(db)
	_, err := q.CreateAPIKey(context.Background(), sqlc.CreateAPIKeyParams{
		ID: "key1", UserID: "u1", OrgID: "org1", Name: "test",
		Prefix: prefix, Hash: hex.EncodeToString(hash[:]), ScopeJson: `{}`,
	})
	if err != nil {
		t.Fatalf("seed api key: %v", err)
	}
	token := prefix + hex.EncodeToString(secret[:])

	r := chi.NewRouter()
	r.Use(auth.CSP())
	r.Use(auth.APIKeyAuthMiddleware(db))
	Routes(r)
	return r, token
}

func rpcReq(t *testing.T, router http.Handler, token, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// TestRPCV1Auth covers WU-401 AC: no bearer API key → 401 problem+json
// `unauthorized`.
func TestRPCV1Auth(t *testing.T) {
	resetV1()
	t.Cleanup(resetV1)
	db := dbtest.New(t)
	router, _ := newV1Router(t, db)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost,
		"/api/v1/actions/test.ping", strings.NewReader(`{}`)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no bearer: status %d, want 401", rec.Code)
	}
	assertProblem(t, rec, "unauthorized")
}

// TestRPCV1UnknownAction covers WU-401 AC: unknown action → 404
// problem+json `unknown_action`.
func TestRPCV1UnknownAction(t *testing.T) {
	resetV1()
	t.Cleanup(resetV1)
	db := dbtest.New(t)
	router, token := newV1Router(t, db)
	rec := rpcReq(t, router, token, "/api/v1/actions/nope.doesnotexist", `{}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown action: status %d, want 404", rec.Code)
	}
	assertProblem(t, rec, "unknown_action")
}

// TestRPCV1Validation covers WU-401 AC: malformed input → 400 problem+json
// `invalid_input` (validation error shape).
func TestRPCV1Validation(t *testing.T) {
	resetV1()
	t.Cleanup(resetV1)
	db := dbtest.New(t)
	router, token := newV1Router(t, db)
	rec := rpcReq(t, router, token, "/api/v1/actions/test.ping", `not json`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad json: status %d, want 400", rec.Code)
	}
	assertProblem(t, rec, "invalid_input")
}

// TestRPCV1Scope covers WU-401 AC: scope resolution failure → 422 problem+json
// `scope_error`.
func TestRPCV1Scope(t *testing.T) {
	resetV1()
	t.Cleanup(resetV1)
	db := dbtest.New(t)
	router, token := newV1Router(t, db)
	rec := rpcReq(t, router, token, "/api/v1/actions/test.scope", `{}`)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("scope error: status %d, want 422", rec.Code)
	}
	assertProblem(t, rec, "scope_error")
}

// TestRPCV1SuccessAndIdempotency covers WU-401 AC: successful RPC returns 200
// JSON; replaying the same Idempotency-Key returns the stored result without
// re-executing.
func TestRPCV1SuccessAndIdempotency(t *testing.T) {
	resetV1()
	t.Cleanup(resetV1)
	db := dbtest.New(t)
	router, token := newV1Router(t, db)

	call := func() (int, string) {
		req := httptest.NewRequest(http.MethodPost,
			"/api/v1/actions/test.ping", strings.NewReader(`{"name":"x"}`))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Idempotency-Key", "idem-1")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	code1, body1 := call()
	if code1 != http.StatusOK {
		t.Fatalf("first call: status %d, want 200", code1)
	}
	if !strings.Contains(body1, `"pong":true`) {
		t.Fatalf("first call missing result: %s", body1)
	}
	code2, body2 := call()
	if code2 != http.StatusOK {
		t.Fatalf("replay: status %d, want 200", code2)
	}
	if body2 != body1 {
		t.Fatalf("idempotent replay mismatch:\n%s\n---\n%s", body1, body2)
	}
}

// TestRPCV1RateLimit covers WU-401 AC: exceeding the per-key token bucket →
// 429 problem+json `rate_limited` with X-RateLimit-* + Retry-After headers.
func TestRPCV1RateLimit(t *testing.T) {
	resetV1()
	t.Cleanup(resetV1)
	db := dbtest.New(t)
	SetRateLimit(2, time.Hour) // burst 2, no regeneration mid-test
	router, token := newV1Router(t, db)

	ok := 0
	limited := 0
	for i := 0; i < 4; i++ {
		rec := rpcReq(t, router, token, "/api/v1/actions/test.ping", `{"name":"x"}`)
		switch rec.Code {
		case http.StatusOK:
			ok++
			if h := rec.Header().Get("X-RateLimit-Limit"); h != "2" {
				t.Fatalf("limit header %q, want 2", h)
			}
		case http.StatusTooManyRequests:
			limited++
			assertProblem(t, rec, "rate_limited")
			if rec.Header().Get("Retry-After") == "" {
				t.Fatalf("missing Retry-After on 429")
			}
		default:
			t.Fatalf("call %d: unexpected status %d", i, rec.Code)
		}
	}
	if ok != 2 || limited != 2 {
		t.Fatalf("expected 2 allowed / 2 limited, got %d / %d", ok, limited)
	}
}

// assertProblem decodes a problem+json body and checks its stable code.
func assertProblem(t *testing.T, rec *httptest.ResponseRecorder, wantType string) {
	t.Helper()
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "problem+json") {
		t.Fatalf("content-type %q, want problem+json", ct)
	}
	var p problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("decode problem: %v (body %q)", err, rec.Body.String())
	}
	if p.Type != wantType {
		t.Fatalf("problem type %q, want %q", p.Type, wantType)
	}
	if p.Status != rec.Code {
		t.Fatalf("problem status %d, want %d", p.Status, rec.Code)
	}
}

// resetV1 resets the global rate limiter between tests (registered actions are
// package-level init, so they persist across tests).
func resetV1() {
	SetRateLimit(60, time.Second)
}
