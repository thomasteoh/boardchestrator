package wiki

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
	wikidb "github.com/thomasteoh/boardchestrator/internal/db/sqlc/wiki"
	"github.com/thomasteoh/boardchestrator/internal/search"
)

// TestIndexPagesOnRefresh (WU-503 AC1): a fresh checkout indexes the org's
// pages into wiki_fts, and a refresh (stale TTL) re-indexes so search reflects
// newly added pages.
func TestIndexPagesOnRefresh(t *testing.T) {
	db := dbtest.New(t)
	q := wikidb.New(db)
	orgID := "org-idx"

	fixture := t.TempDir()
	if err := os.MkdirAll(filepath.Join(fixture, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture, "docs", "index.md"), []byte("# Home\n\nSee ABC-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	seedOrg(t, db, orgID)
	seedConfig(t, q, orgID, fixture, "main", "docs")
	st := NewStore(db, t.TempDir(), WithCloneFunc(fixtureClone))

	// Fresh checkout auto-indexes (indexOnRefresh=true).
	if _, err := st.Checkout(context.Background(), orgID); err != nil {
		t.Fatalf("checkout: %v", err)
	}
	res, err := search.QueryWiki(context.Background(), db, "home", "", 50)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(res) != 1 || res[0].Path != "docs/index.md" {
		t.Fatalf("index after fresh checkout = %+v, want [docs/index.md]", res)
	}

	// Add a page to the fixture and force a refresh (negative TTL ⇒ stale).
	if err := os.WriteFile(filepath.Join(fixture, "docs", "new.md"), []byte("fresh content\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	st.checkoutTTL = -1 * time.Second
	if _, err := st.Checkout(context.Background(), orgID); err != nil {
		t.Fatalf("refresh checkout: %v", err)
	}
	res, err = search.QueryWiki(context.Background(), db, "fresh", "", 50)
	if err != nil {
		t.Fatalf("query fresh: %v", err)
	}
	if len(res) != 1 || res[0].Path != "docs/new.md" {
		t.Fatalf("index after refresh = %+v, want [docs/new.md]", res)
	}
}

// TestQueryWikiVisibility (WU-503 AC2): wiki search results are scoped to the
// orgs a user is a member of — pages in orgs the user cannot access are hidden.
func TestQueryWikiVisibility(t *testing.T) {
	db := dbtest.New(t)
	q := wikidb.New(db)

	fixture := t.TempDir()
	if err := os.MkdirAll(filepath.Join(fixture, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture, "docs", "index.md"), []byte("secret onboarding\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	seedOrg(t, db, "org-a")
	seedOrg(t, db, "org-b")
	seedConfig(t, q, "org-a", fixture, "main", "docs")
	seedConfig(t, q, "org-b", fixture, "main", "docs")

	st := NewStore(db, t.TempDir(), WithCloneFunc(fixtureClone))
	for _, orgID := range []string{"org-a", "org-b"} {
		if _, err := st.Checkout(context.Background(), orgID); err != nil {
			t.Fatalf("checkout %s: %v", orgID, err)
		}
	}

	// user-1 is a member of org-a only → sees only org-a's page.
	seedMembership(t, db, "org-a", "user-1")
	res, err := search.QueryWiki(context.Background(), db, "secret", "user-1", 50)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(res) != 1 || res[0].OrgID != "org-a" {
		t.Fatalf("user-1 sees %+v, want only org-a", res)
	}

	// user-2 has no memberships → sees nothing.
	res, err = search.QueryWiki(context.Background(), db, "secret", "user-2", 50)
	if err != nil {
		t.Fatalf("query user-2: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("user-2 sees %+v, want none", res)
	}
}

// TestBacklinks (WU-503 AC3): tasks in an org referencing a page via
// [[name]] syntax (description or comment) are listed for that page.
func TestBacklinks(t *testing.T) {
	db := dbtest.New(t)
	orgID := "org-bl"
	seedOrg(t, db, orgID)
	seedProject(t, db, "proj-1", orgID)
	seedProject(t, db, "proj-2", orgID)

	// Task in proj-1 references [[onboarding]] (page docs/guides/onboarding.md).
	mustExec(t, db, `INSERT INTO tasks (id, project_id, key, title, description, status) VALUES ('t1', 'proj-1', 'ABC-1', 'Do onboarding', 'See [[onboarding]]', 'todo')`)
	// Task in proj-2 references via comment.
	mustExec(t, db, `INSERT INTO tasks (id, project_id, key, title, description, status) VALUES ('t2', 'proj-2', 'ABC-2', 'Other', '', 'doing')`)
	mustExec(t, db, `INSERT INTO users (id, name, email) VALUES ('u1', 'U', 'u@x.io')`)
	mustExec(t, db, `INSERT INTO comments (id, task_id, project_id, author_id, body) VALUES ('c1', 't2', 'proj-2', 'u1', 'uses [[onboarding]] too')`)
	// Task in proj-1 has no reference.
	mustExec(t, db, `INSERT INTO tasks (id, project_id, key, title, description, status) VALUES ('t3', 'proj-1', 'ABC-3', 'No ref', '', 'todo')`)

	st := NewStore(db, t.TempDir())
	links, err := st.Backlinks(context.Background(), orgID, "docs/guides/onboarding.md")
	if err != nil {
		t.Fatalf("backlinks: %v", err)
	}
	if len(links) != 2 {
		t.Fatalf("backlinks = %+v, want 2 (t1 via desc, t2 via comment)", links)
	}
	keys := map[string]bool{}
	for _, l := range links {
		keys[l.Key] = true
	}
	if !keys["ABC-1"] || !keys["ABC-2"] || keys["ABC-3"] {
		t.Fatalf("backlinks keys = %v, want ABC-1 + ABC-2, not ABC-3", keys)
	}
}

// TestResolvePage maps a [[name]] reference to a page path in the org.
func TestResolvePage(t *testing.T) {
	db := dbtest.New(t)
	q := wikidb.New(db)
	orgID := "org-rp"
	fixture := t.TempDir()
	if err := os.MkdirAll(filepath.Join(fixture, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture, "docs", "onboarding.md"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	seedOrg(t, db, orgID)
	seedConfig(t, q, orgID, fixture, "main", "docs")
	st := NewStore(db, t.TempDir(), WithCloneFunc(fixtureClone))

	path, err := st.ResolvePage(context.Background(), orgID, "onboarding")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if path != "docs/onboarding.md" {
		t.Fatalf("resolve onboarding = %q, want docs/onboarding.md", path)
	}
	path, err = st.ResolvePage(context.Background(), orgID, "nope")
	if err != nil {
		t.Fatalf("resolve nope: %v", err)
	}
	if path != "" {
		t.Fatalf("resolve nope = %q, want ''", path)
	}
}

// TestAutolinkWiki links [[name]] when the page resolves, skips pre/code and
// existing anchors, and leaves unresolved refs as-is.
func TestAutolinkWiki(t *testing.T) {
	resolve := func(name string) (string, bool) {
		if name == "onboarding" {
			return "docs/onboarding.md", true
		}
		return "", false
	}
	in := []byte("Read [[onboarding]] and [[missing]].\n<pre>[[onboarding]]</pre>\n<a href=\"/x\">[[onboarding]]</a>")
	out := string(AutolinkWiki(in, "org-1", resolve))
	if !contains(out, `href="/app/org/org-1/wiki/docs/onboarding.md"`) {
		t.Fatalf("no link: %s", out)
	}
	if !contains(out, "[[missing]]") {
		t.Fatalf("unresolved ref changed: %s", out)
	}
	if contains(out, "<pre><a ") || contains(out, "href=\"<a ") {
		t.Fatalf("linked inside pre/anchor: %s", out)
	}
	if count(out, `href="/app/org/org-1/wiki/docs/onboarding.md"`) != 1 {
		t.Fatalf("expected exactly 1 link, got: %s", out)
	}
}

// seedMembership grants userID membership in an org (visibility scoping).
func seedMembership(t *testing.T, db *sql.DB, orgID, userID string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO memberships (id, org_id, actor_id, actor_type, resource_type, resource_id) VALUES (?, ?, ?, 'user', 'org', '')`,
		orgID+"-"+userID, orgID, userID); err != nil {
		t.Fatalf("seed membership: %v", err)
	}
}

// seedProject inserts a project row in an org (needed for tasks FK).
func seedProject(t *testing.T, db *sql.DB, id, orgID string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO projects (id, org_id, name, key) VALUES (?, ?, ?, ?)`, id, orgID, "Project "+id, "p-"+id); err != nil {
		t.Fatalf("seed project: %v", err)
	}
}

// mustExec runs a SQL statement, failing the test on error.
func mustExec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatalf("exec %s: %v", q, err)
	}
}

// count reports the number of non-overlapping occurrences of sub in s.
func count(s, sub string) int {
	n := 0
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			n++
			i += len(sub) - 1
		}
	}
	return n
}
