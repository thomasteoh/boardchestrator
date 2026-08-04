package action

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

func TestApikeyCreateAndRevoke(t *testing.T) {
	reset()
	t.Cleanup(reset)
	Register(Definition{
		Name:   "org.create",
		Impact: ImpactHigh,
		Scope:  ScopePlatform,
		Handle: handleOrgCreate,
	})
	Register(Definition{
		Name:       "apikey.create",
		Impact:     ImpactHigh,
		Permission: "apikey.create",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleApikeyCreate,
	})
	Register(Definition{
		Name:       "apikey.revoke",
		Impact:     ImpactHigh,
		Permission: "apikey.revoke",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleApikeyRevoke,
	})
	Register(Definition{
		Name:       "apikey.list",
		Impact:     ImpactRead,
		Permission: "apikey.list",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleApikeyList,
	})

	db := dbtest.New(t)
	seedUser(t, db, "user-1", "user-1@test.io", "User One")
	d := New(db)
	ctx := context.Background()

	// Seed org for FK.
	orgResult, err := d.Dispatch(ctx, userActor(), "org.create",
		json.RawMessage(`{"name":"Test Org","slug":"test-org","visibility":"private"}`),
		Opts{})
	if err != nil {
		t.Fatalf("org.create: %v", err)
	}
	orgID := extractID(t, mustJSON(t, orgResult))

	actor := Actor{Type: ActorUser, ID: "user-1"}

	// Create an API key.
	result, err := d.Dispatch(ctx, actor, "apikey.create",
		json.RawMessage(`{"org_id":"`+orgID+`","name":"test-key","scope":["task.*"]}`),
		Opts{Org: orgID})
	if err != nil {
		t.Fatalf("apikey.create failed: %v", err)
	}
	m := result.(map[string]any)
	id, _ := m["id"].(string)
	secret, _ := m["secret"].(string)
	if id == "" || secret == "" {
		t.Fatal("expected non-empty id and secret")
	}
	if len(secret) < 8 {
		t.Fatal("secret too short")
	}

	// List keys.
	_, err = d.Dispatch(ctx, actor, "apikey.list",
		json.RawMessage(`{"org_id":"`+orgID+`","user_id":"user-1"}`),
		Opts{Org: orgID})
	if err != nil {
		t.Fatalf("apikey.list failed: %v", err)
	}

	// Revoke.
	_, err = d.Dispatch(ctx, actor, "apikey.revoke",
		json.RawMessage(`{"id":"`+id+`","org_id":"`+orgID+`","user_id":"user-1"}`),
		Opts{Org: orgID})
	if err != nil {
		t.Fatalf("apikey.revoke failed: %v", err)
	}
}

func TestApikeyCreateRejectsDupName(t *testing.T) {
	reset()
	t.Cleanup(reset)
	Register(Definition{
		Name:   "org.create",
		Impact: ImpactHigh,
		Scope:  ScopePlatform,
		Handle: handleOrgCreate,
	})
	Register(Definition{
		Name:       "apikey.create",
		Impact:     ImpactHigh,
		Permission: "apikey.create",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleApikeyCreate,
	})

	db := dbtest.New(t)
	seedUser(t, db, "user-1", "user-1@test.io", "User One")
	d := New(db)
	ctx := context.Background()

	orgResult, err := d.Dispatch(ctx, userActor(), "org.create",
		json.RawMessage(`{"name":"Test","slug":"dup-test","visibility":"private"}`),
		Opts{})
	if err != nil {
		t.Fatalf("org.create: %v", err)
	}
	orgID := extractID(t, mustJSON(t, orgResult))

	actor := Actor{Type: ActorUser, ID: "user-1"}

	// First succeeds.
	_, err = d.Dispatch(ctx, actor, "apikey.create",
		json.RawMessage(`{"org_id":"`+orgID+`","name":"dup-key","scope":[]}`),
		Opts{Org: orgID})
	if err != nil {
		t.Fatalf("first create failed: %v", err)
	}

	// Duplicate name in same org fails.
	_, err = d.Dispatch(ctx, actor, "apikey.create",
		json.RawMessage(`{"org_id":"`+orgID+`","name":"dup-key","scope":[]}`),
		Opts{Org: orgID})
	if err == nil {
		t.Fatal("expected error for duplicate key name")
	}
}

func TestApikeyCreatePrefixFormat(t *testing.T) {
	reset()
	t.Cleanup(reset)
	Register(Definition{
		Name:   "org.create",
		Impact: ImpactHigh,
		Scope:  ScopePlatform,
		Handle: handleOrgCreate,
	})
	Register(Definition{
		Name:       "apikey.create",
		Impact:     ImpactHigh,
		Permission: "apikey.create",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleApikeyCreate,
	})

	db := dbtest.New(t)
	seedUser(t, db, "user-1", "user-1@test.io", "User One")
	d := New(db)
	ctx := context.Background()

	orgResult, err := d.Dispatch(ctx, userActor(), "org.create",
		json.RawMessage(`{"name":"Test","slug":"prefix-test","visibility":"private"}`),
		Opts{})
	if err != nil {
		t.Fatalf("org.create: %v", err)
	}
	orgID := extractID(t, mustJSON(t, orgResult))

	actor := Actor{Type: ActorUser, ID: "user-1"}
	result, err := d.Dispatch(ctx, actor, "apikey.create",
		json.RawMessage(`{"org_id":"`+orgID+`","name":"test-auth","scope":[]}`),
		Opts{Org: orgID})
	if err != nil {
		t.Fatalf("create failed: %v", err)
	}
	m := result.(map[string]any)
	secret := m["secret"].(string)
	if len(secret) < 8 {
		t.Fatal("secret too short")
	}
	if secret[:8] == "" {
		t.Fatal("prefix should be 8 hex chars")
	}
}

// --- helpers ----------------------------------------------------------------

func seedUser(t *testing.T, db sqlc.DBTX, id, email, name string) {
	t.Helper()
	_, err := db.ExecContext(context.Background(),
		`INSERT INTO users (id, email, name) VALUES (?, ?, ?)`,
		id, email, name,
	)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
}
