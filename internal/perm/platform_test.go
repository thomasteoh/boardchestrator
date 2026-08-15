package perm

import (
	"context"
	"database/sql"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
)

// TestAllowPlatformScope verifies a platform admin (Org Owner membership in the
// sentinel org) can perform platform-scope actions (org.create) even though
// ac.Org is empty (WU-508).
func TestAllowPlatformScope(t *testing.T) {
	d := dbtest.New(t)
	c := NewChecker(d)
	ctx := context.Background()

	// Seed platform admin: u1 is Org Owner (seeded system role, grants ["*"])
	// of the sentinel org. Role id/org from migrations/0005_roles.up.sql.
	if _, err := d.Exec(`INSERT INTO memberships (id, org_id, actor_id, actor_type, resource_type, resource_id, role_id)
		VALUES ('m1','00000000000000000000000000000000','u1','user','org','00000000000000000000000000000000','00000000000000000000000000000000')`); err != nil {
		t.Fatal(err)
	}

	ok, err := c.Allow(ctx, "u1", "", "", "", "org.create")
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if !ok {
		t.Fatal("platform admin should be allowed org.create with empty org scope")
	}
}

// TestAllowPlatformScopeNonAdmin denies non-members platform-scope actions.
func TestAllowPlatformScopeNonAdmin(t *testing.T) {
	d := dbtest.New(t)
	c := NewChecker(d)
	ctx := context.Background()

	ok, err := c.Allow(ctx, "u1", "", "", "", "org.create")
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if ok {
		t.Fatal("non-admin should be denied org.create")
	}
}

var _ = sql.ErrNoRows // keep database/sql import if unused elsewhere
