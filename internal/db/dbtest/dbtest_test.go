package dbtest

import (
	"os"
	"testing"
)

// TestNewLifecycle proves the helper spins up a migrated temp-file database,
// that it is usable, and that the backing file is destroyed once the test
// that created it completes.
func TestNewLifecycle(t *testing.T) {
	var path string

	t.Run("spin_and_use", func(t *testing.T) {
		d := New(t)

		// Locate the backing file so the parent can assert destruction.
		var seq int
		var name string
		if err := d.QueryRow("PRAGMA database_list").Scan(&seq, &name, &path); err != nil {
			t.Fatalf("PRAGMA database_list: %v", err)
		}
		if path == "" {
			t.Fatal("expected a file-backed database, got empty path")
		}

		// Migrations applied: seeded platform_settings row is present.
		var bootstrapDone int
		if err := d.QueryRow("SELECT bootstrap_done FROM platform_settings WHERE id = 1").Scan(&bootstrapDone); err != nil {
			t.Fatalf("platform_settings seed row: %v", err)
		}
		if bootstrapDone != 0 {
			t.Errorf("bootstrap_done = %d, want 0", bootstrapDone)
		}

		// Usable for writes and reads.
		if _, err := d.Exec(
			"INSERT INTO users (id, email, name) VALUES ('u1', 'test@example.com', 'Test User')",
		); err != nil {
			t.Fatalf("insert user: %v", err)
		}
		var email string
		if err := d.QueryRow("SELECT email FROM users WHERE id = 'u1'").Scan(&email); err != nil {
			t.Fatalf("select user: %v", err)
		}
		if email != "test@example.com" {
			t.Errorf("email = %q, want test@example.com", email)
		}
	})

	// Subtest cleanups have run: the temp DB file must be gone.
	if path == "" {
		t.Fatal("subtest did not capture the database path")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("temp database %s still exists after test completed (stat err: %v)", path, err)
	}
}
