// Package dbtest provides the test helper mandated by SPEC §3: handler and
// data-layer tests run against a real temp-file SQLite database with all
// migrations applied — never a mock.
package dbtest

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/db"
)

// New returns an open database backed by a file in t.TempDir() with every
// embedded migration applied. The connection is closed via t.Cleanup and the
// backing file is destroyed with the temp dir when the test completes.
func New(t testing.TB) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bc_test.db")
	d, err := db.Open(path)
	if err != nil {
		t.Fatalf("dbtest: open %s: %v", path, err)
	}
	t.Cleanup(func() { _ = d.Close() })
	if err := db.MigrateUp(d); err != nil {
		t.Fatalf("dbtest: migrate: %v", err)
	}
	return d
}
