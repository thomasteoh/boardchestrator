package action

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/tenant"
)

// TestGithubConnectionCRUD covers WU-406 AC: PAT connect stores an encrypted
// token (retrievable via round-trip), status shows connected, disconnect wipes
// it, and the oauth source reuses an SSO identity token.
func TestGithubConnectionCRUD(t *testing.T) {
	reset()
	t.Cleanup(reset)
	Register(Definition{Name: "github.connect", Impact: ImpactLow, Permission: "github.connect", Scope: ScopePlatform, Input: FuncSchema(func(raw json.RawMessage) error { return nil }), Handle: handleGithubConnect})
	Register(Definition{Name: "github.disconnect", Impact: ImpactLow, Permission: "github.disconnect", Scope: ScopePlatform, Input: FuncSchema(func(raw json.RawMessage) error { return nil }), Handle: handleGithubDisconnect})
	Register(Definition{Name: "github.status", Impact: ImpactRead, Permission: "github.status", Scope: ScopePlatform, Input: FuncSchema(func(raw json.RawMessage) error { return nil }), Handle: handleGithubStatus})

	db := dbtest.New(t)
	key := tenant.PadKey("test-secret-key")
	d := New(db, WithSecretKey(key))
	ctx := context.Background()

	if _, err := db.Exec(`INSERT INTO users (id, email, name) VALUES ('u1','a@b.c','A')`); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	// Not connected initially.
	statusOut, err := d.Dispatch(ctx, userActor(), "github.status", json.RawMessage(`{}`), Opts{})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !strings.Contains(mustJSON(t, statusOut), `"connected":false`) {
		t.Fatalf("initial status: %s", mustJSON(t, statusOut))
	}

	// Connect with a PAT.
	const pat = "ghp_ABCDEF1234567890secret"
	upOut, err := d.Dispatch(ctx, userActor(), "github.connect",
		json.RawMessage(`{"source":"pat","token":"`+pat+`","login":"octocat"}`), Opts{})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if !strings.Contains(mustJSON(t, upOut), `"login":"octocat"`) {
		t.Fatalf("connect result: %s", mustJSON(t, upOut))
	}

	// The stored ciphertext must differ from the plaintext (encrypted at rest).
	var enc string
	if err := db.QueryRow(`SELECT token_enc FROM github_connections WHERE user_id='u1'`).Scan(&enc); err != nil {
		t.Fatalf("read token_enc: %v", err)
	}
	if enc == pat {
		t.Fatalf("token stored in plaintext — expected encryption")
	}

	// Status shows connected + provider pat.
	statusOut2, err := d.Dispatch(ctx, userActor(), "github.status", json.RawMessage(`{}`), Opts{})
	if err != nil {
		t.Fatalf("status2: %v", err)
	}
	if !strings.Contains(mustJSON(t, statusOut2), `"connected":true`) || !strings.Contains(mustJSON(t, statusOut2), `"provider":"pat"`) {
		t.Fatalf("status after connect: %s", mustJSON(t, statusOut2))
	}

	// TokenForUser decrypts back to the original PAT (round-trip). Replicate
	// the decrypt inline (importing internal/github would create a cycle).
	got, connected, err := decryptToken(t, db, key, "u1")
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if !connected || got != pat {
		t.Fatalf("round-trip: connected=%v got=%q want=%q", connected, got, pat)
	}

	// Disconnect wipes the token.
	delOut, err := d.Dispatch(ctx, userActor(), "github.disconnect", json.RawMessage(`{}`), Opts{})
	if err != nil {
		t.Fatalf("disconnect: %v", err)
	}
	if !strings.Contains(mustJSON(t, delOut), `"deleted":true`) {
		t.Fatalf("disconnect result: %s", mustJSON(t, delOut))
	}
	got2, connected2, err := decryptToken(t, db, key, "u1")
	if err != nil {
		t.Fatalf("token after disconnect: %v", err)
	}
	if connected2 || got2 != "" {
		t.Fatalf("token not wiped: connected=%v got=%q", connected2, got2)
	}
}

// TestGithubConnectionOAuth verifies github.connect(source=oauth) reuses the
// SSO identity token (identities.token_enc) rather than requiring a PAT.
func TestGithubConnectionOAuth(t *testing.T) {
	reset()
	t.Cleanup(reset)
	Register(Definition{Name: "github.connect", Impact: ImpactLow, Permission: "github.connect", Scope: ScopePlatform, Input: FuncSchema(func(raw json.RawMessage) error { return nil }), Handle: handleGithubConnect})

	db := dbtest.New(t)
	key := tenant.PadKey("test-secret-key")
	d := New(db, WithSecretKey(key))
	ctx := context.Background()

	if _, err := db.Exec(`INSERT INTO users (id, email, name) VALUES ('u1','a@b.c','A')`); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	// Seed a github identity carrying an encrypted OAuth token.
	tokenEnc, err := tenant.Encrypt(key, "gho_oauth-token-123")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO identities (id, user_id, provider, subject, email, token_enc) VALUES ('i1','u1','github','gh-1','a@b.c',?)`, tokenEnc); err != nil {
		t.Fatalf("seed identity: %v", err)
	}

	out, err := d.Dispatch(ctx, userActor(), "github.connect",
		json.RawMessage(`{"source":"oauth","login":"octocat"}`), Opts{})
	if err != nil {
		t.Fatalf("connect oauth: %v", err)
	}
	if !strings.Contains(mustJSON(t, out), `"provider":"oauth"`) {
		t.Fatalf("oauth connect result: %s", mustJSON(t, out))
	}
	got, connected, err := decryptToken(t, db, key, "u1")
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if !connected || got != "gho_oauth-token-123" {
		t.Fatalf("oauth token reuse: connected=%v got=%q", connected, got)
	}
}

// decryptToken replicates github.TokenForUser's decrypt inline (importing
// internal/github from the action test would create an import cycle).
func decryptToken(t *testing.T, db *sql.DB, key []byte, userID string) (string, bool, error) {
	t.Helper()
	conn, err := sqlc.New(db).FindGithubConnection(context.Background(), userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", false, nil
		}
		return "", false, err
	}
	if conn.TokenEnc == "" {
		return "", false, nil
	}
	plain, err := tenant.Decrypt(key, conn.TokenEnc)
	if err != nil {
		return "", false, err
	}
	return plain, true, nil
}
