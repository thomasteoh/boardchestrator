package db_test

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/db"
)

func openTemp(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	d, err := db.Open(path)
	if err != nil {
		t.Fatalf("Open(%q): %v", path, err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

// migratedTables are the tables the embedded migrations must create:
// 0001 (identity) and 0002 (action-dispatch infra).
var migratedTables = []string{
	"users", "identities", "sessions", "platform_settings",
	"idempotency_keys", "audit_log",
}

func tableExists(t *testing.T, d *sql.DB, name string) bool {
	t.Helper()
	var n int
	err := d.QueryRow(
		"SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?", name,
	).Scan(&n)
	if err != nil {
		t.Fatalf("query sqlite_master for %s: %v", name, err)
	}
	return n == 1
}

func TestOpenPragmas(t *testing.T) {
	d := openTemp(t)

	tests := []struct {
		pragma string
		want   string
	}{
		{"journal_mode", "wal"},
		{"foreign_keys", "1"},
		{"busy_timeout", "5000"},
	}
	for _, tc := range tests {
		t.Run(tc.pragma, func(t *testing.T) {
			var got string
			if err := d.QueryRow("PRAGMA " + tc.pragma).Scan(&got); err != nil {
				t.Fatalf("PRAGMA %s: %v", tc.pragma, err)
			}
			if got != tc.want {
				t.Errorf("PRAGMA %s = %q, want %q", tc.pragma, got, tc.want)
			}
		})
	}
}

func TestMigrateRoundTrip(t *testing.T) {
	d := openTemp(t)

	// Up: all four tables exist and platform_settings is seeded.
	if err := db.MigrateUp(d); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	for _, name := range migratedTables {
		if !tableExists(t, d, name) {
			t.Errorf("after up: table %s missing", name)
		}
	}
	assertSeedRow(t, d)

	// Up again: no-op, no error (runs at every startup).
	if err := db.MigrateUp(d); err != nil {
		t.Fatalf("MigrateUp (repeat): %v", err)
	}

	// Down: all four tables gone.
	if err := db.MigrateDown(d); err != nil {
		t.Fatalf("MigrateDown: %v", err)
	}
	for _, name := range migratedTables {
		if tableExists(t, d, name) {
			t.Errorf("after down: table %s still exists", name)
		}
	}

	// Up again: round-trips cleanly, seed row restored.
	if err := db.MigrateUp(d); err != nil {
		t.Fatalf("MigrateUp (after down): %v", err)
	}
	for _, name := range migratedTables {
		if !tableExists(t, d, name) {
			t.Errorf("after re-up: table %s missing", name)
		}
	}
	assertSeedRow(t, d)
}

func assertSeedRow(t *testing.T, d *sql.DB) {
	t.Helper()
	var id, bootstrapDone int
	err := d.QueryRow("SELECT id, bootstrap_done FROM platform_settings").Scan(&id, &bootstrapDone)
	if err != nil {
		t.Fatalf("platform_settings seed row: %v", err)
	}
	if id != 1 || bootstrapDone != 0 {
		t.Errorf("platform_settings seed = (id=%d, bootstrap_done=%d), want (1, 0)", id, bootstrapDone)
	}
}

func TestForeignKeysEnforced(t *testing.T) {
	d := openTemp(t)
	if err := db.MigrateUp(d); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}

	_, err := d.Exec(
		"INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ('h', 'no-such-user', '2027-01-01T00:00:00Z')",
	)
	if err == nil {
		t.Fatal("insert with dangling user_id succeeded; foreign keys not enforced")
	}
}
