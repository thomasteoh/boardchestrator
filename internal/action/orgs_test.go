package action

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

func TestOrgCreateAndLookup(t *testing.T) {
	reset()
	t.Cleanup(reset)
	Register(Definition{
		Name:   "org.create",
		Impact: ImpactHigh,
		Scope:  ScopePlatform,
		Handle: handleOrgCreate,
	})

	d := New(dbtest.New(t))
	ctx := context.Background()

	out, err := d.Dispatch(ctx, userActor(), "org.create",
		json.RawMessage(`{"name":"My Org","slug":"my-org","visibility":"private"}`),
		Opts{Org: ""})
	if err != nil {
		t.Fatalf("org.create: %v", err)
	}
	got := mustJSON(t, out)
	if !contains(got, `"id"`) {
		t.Fatalf("result missing id: %s", got)
	}
}

func TestOrgCreateDuplicateSlug(t *testing.T) {
	reset()
	t.Cleanup(reset)
	Register(Definition{
		Name:   "org.create",
		Impact: ImpactHigh,
		Scope:  ScopePlatform,
		Handle: handleOrgCreate,
	})

	d := New(dbtest.New(t))
	ctx := context.Background()

	_, err := d.Dispatch(ctx, userActor(), "org.create",
		json.RawMessage(`{"name":"Org","slug":"dup","visibility":"private"}`),
		Opts{Org: ""})
	if err != nil {
		t.Fatalf("first create: %v", err)
	}
	_, err = d.Dispatch(ctx, userActor(), "org.create",
		json.RawMessage(`{"name":"Org2","slug":"dup","visibility":"private"}`),
		Opts{Org: ""})
	if err == nil {
		t.Fatal("expected error on duplicate slug")
	}
}

func TestTeamCreateAndLookup(t *testing.T) {
	reset()
	t.Cleanup(reset)

	// Need org.create + team.create registered
	Register(Definition{
		Name:   "org.create",
		Impact: ImpactHigh,
		Scope:  ScopePlatform,
		Handle: handleOrgCreate,
	})
	Register(Definition{
		Name:   "team.create",
		Impact: ImpactHigh,
		Scope:  ScopeOrg,
		Handle: handleTeamCreate,
	})

	db := dbtest.New(t)
	d := New(db, WithScopeResolver(NewDBScopeResolver(db)))
	ctx := context.Background()

	// Create org first
	orgOut, err := d.Dispatch(ctx, userActor(), "org.create",
		json.RawMessage(`{"name":"O","slug":"o","visibility":"private"}`),
		Opts{Org: ""})
	if err != nil {
		t.Fatalf("org.create: %v", err)
	}
	orgID := mustParseID(t, orgOut)

	// Create team in that org
	out, err := d.Dispatch(ctx, userActor(), "team.create",
		json.RawMessage(`{"org_id":"`+orgID+`","name":"Team","slug":"team","visibility":"private"}`),
		Opts{Org: orgID})
	if err != nil {
		t.Fatalf("team.create: %v", err)
	}
	got := mustJSON(t, out)
	if !contains(got, `"id"`) {
		t.Fatalf("result missing id: %s", got)
	}
}

func TestProjectCreateKeyValidation(t *testing.T) {
	reset()
	t.Cleanup(reset)
	Register(Definition{
		Name:   "org.create",
		Impact: ImpactHigh,
		Scope:  ScopePlatform,
		Handle: handleOrgCreate,
	})
	Register(Definition{
		Name:   "project.create",
		Impact: ImpactHigh,
		Scope:  ScopeOrg,
		Handle: handleProjectCreate,
	})

	db := dbtest.New(t)
	d := New(db, WithScopeResolver(NewDBScopeResolver(db)))
	ctx := context.Background()

	orgOut, err := d.Dispatch(ctx, userActor(), "org.create",
		json.RawMessage(`{"name":"O","slug":"o","visibility":"private"}`),
		Opts{Org: ""})
	if err != nil {
		t.Fatalf("org.create: %v", err)
	}
	orgID := mustParseID(t, orgOut)

	// Bad key — lowercase
	_, err = d.Dispatch(ctx, userActor(), "project.create",
		json.RawMessage(`{"org_id":"`+orgID+`","name":"P","key":"abc","visibility":"private"}`),
		Opts{Org: orgID})
	if err == nil {
		t.Fatal("expected error on invalid key (lowercase)")
	}

	// Good key
	out, err := d.Dispatch(ctx, userActor(), "project.create",
		json.RawMessage(`{"org_id":"`+orgID+`","name":"P","key":"ABC","visibility":"private"}`),
		Opts{Org: orgID})
	if err != nil {
		t.Fatalf("project.create: %v", err)
	}
	if !contains(mustJSON(t, out), `"id"`) {
		t.Fatalf("result missing id")
	}
}

func TestProjectArchiveUnarchive(t *testing.T) {
	reset()
	t.Cleanup(reset)
	Register(Definition{
		Name:   "org.create",
		Impact: ImpactHigh,
		Scope:  ScopePlatform,
		Handle: handleOrgCreate,
	})
	Register(Definition{
		Name:   "project.create",
		Impact: ImpactHigh,
		Scope:  ScopeOrg,
		Handle: handleProjectCreate,
	})
	Register(Definition{
		Name:   "project.archive",
		Impact: ImpactHigh,
		Scope:  ScopeProject,
		Handle: handleProjectArchive,
	})
	Register(Definition{
		Name:   "project.unarchive",
		Impact: ImpactHigh,
		Scope:  ScopeProject,
		Handle: handleProjectUnarchive,
	})

	db := dbtest.New(t)
	d := New(db, WithScopeResolver(NewDBScopeResolver(db)))
	ctx := context.Background()

	orgOut, err := d.Dispatch(ctx, userActor(), "org.create",
		json.RawMessage(`{"name":"O","slug":"o","visibility":"private"}`),
		Opts{Org: ""})
	if err != nil {
		t.Fatalf("org.create: %v", err)
	}
	orgID := mustParseID(t, orgOut)

	projOut, err := d.Dispatch(ctx, userActor(), "project.create",
		json.RawMessage(`{"org_id":"`+orgID+`","name":"P","key":"ABC","visibility":"private"}`),
		Opts{Org: orgID})
	if err != nil {
		t.Fatalf("project.create: %v", err)
	}
	projID := mustParseID(t, projOut)

	// Archive
	_, err = d.Dispatch(ctx, userActor(), "project.archive",
		json.RawMessage(`{"id":"`+projID+`","org_id":"`+orgID+`"}`),
		Opts{Org: orgID, Proj: projID})
	if err != nil {
		t.Fatalf("project.archive: %v", err)
	}

	// Unarchive
	_, err = d.Dispatch(ctx, userActor(), "project.unarchive",
		json.RawMessage(`{"id":"`+projID+`","org_id":"`+orgID+`"}`),
		Opts{Org: orgID, Proj: projID})
	if err != nil {
		t.Fatalf("project.unarchive: %v", err)
	}
}

// --- helpers ---

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && stringContains(s, substr)
}

func stringContains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func mustParseID(t *testing.T, v any) string {
	t.Helper()
	raw, ok := v.(json.RawMessage)
	if !ok {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		raw = json.RawMessage(b)
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	id, ok := m["id"]
	if !ok {
		t.Fatal("result has no id field")
	}
	return id
}

// TestDBScopeResolver ensures scope resolution works for org/team/project scopes.
func TestDBScopeResolverOrgNotFound(t *testing.T) {
	r := &DBScopeResolver{q: newQueries(t)}
	err := r.Resolve(context.Background(), ActionCtx{Org: "nonexistent"}, Definition{Scope: ScopeOrg})
	if err == nil {
		t.Fatal("expected error for nonexistent org")
	}
}

func TestDBScopeResolverPlatformNoOp(t *testing.T) {
	r := &DBScopeResolver{q: newQueries(t)}
	err := r.Resolve(context.Background(), ActionCtx{}, Definition{Scope: ScopePlatform})
	if err != nil {
		t.Fatalf("platform scope should always pass: %v", err)
	}
}

func newQueries(t *testing.T) *sqlc.Queries {
	t.Helper()
	return sqlc.New(dbtest.New(t))
}
