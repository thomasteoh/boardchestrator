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
)

// fixtureClone is a cloneFunc that copies a fixture wiki dir into the worktree
// (no network/git): url = path to a local dir containing the wiki files.
func fixtureClone(ctx context.Context, url, ref, worktree string, shallow bool) error {
	return copyDir(url, worktree)
}

// copyDir recursively copies src → dst.
func copyDir(src, dst string) error {
	return filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o644)
	})
}

// seedOrg inserts an org row so wiki_configs' FK (org_id → orgs.id) holds.
func seedOrg(t *testing.T, db *sql.DB, orgID string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO orgs (id, name, slug) VALUES (?, ?, ?)`, orgID, "Org "+orgID, "org-"+orgID); err != nil {
		t.Fatalf("seed org: %v", err)
	}
}

// seedConfig writes a wiki config row for orgID.
func seedConfig(t *testing.T, db *wikidb.Queries, orgID, repo, ref, path string) {
	t.Helper()
	if err := db.UpsertWikiConfig(context.Background(), wikidb.UpsertWikiConfigParams{
		OrgID: orgID, Repo: repo, Ref: ref, Path: path,
		CreatedAt: "2026-01-01T00:00:00.000Z",
		UpdatedAt: "2026-01-01T00:00:00.000Z",
	}); err != nil {
		t.Fatalf("seed config: %v", err)
	}
}

// TestStoreReadPage exercises config load, checkout (fixture clone), page
// read + render, and path confinement.
func TestStoreReadPage(t *testing.T) {
	db := dbtest.New(t)
	q := wikidb.New(db)
	orgID := "org-1"

	// Fixture wiki: docs/ with two markdown pages.
	fixture := t.TempDir()
	if err := os.MkdirAll(filepath.Join(fixture, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(fixture, "docs", "guides"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture, "docs", "index.md"), []byte("# Home\n\nSee ABC-1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture, "docs", "guides", "onboarding.md"), []byte("## Onboarding\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	seedOrg(t, db, orgID)
	seedConfig(t, q, orgID, fixture, "main", "docs")
	st := NewStore(db, t.TempDir(), WithCloneFunc(fixtureClone))

	page, err := st.ReadPage(context.Background(), orgID, "index.md")
	if err != nil {
		t.Fatalf("read page: %v", err)
	}
	if page.Name != "index" {
		t.Fatalf("name = %q, want index", page.Name)
	}
	if !contains(page.HTML, "ABC-1") {
		t.Fatalf("page not rendered: %s", page.HTML)
	}
	if !contains(page.HTML, "<h1>") {
		t.Fatalf("heading not rendered: %s", page.HTML)
	}
}

// TestStorePageTree lists markdown pages under the wiki path (tree nav).
func TestStorePageTree(t *testing.T) {
	db := dbtest.New(t)
	q := wikidb.New(db)
	orgID := "org-2"
	fixture := t.TempDir()
	for _, f := range []string{"a.md", "b.md", "notes/c.md"} {
		if err := os.MkdirAll(filepath.Join(fixture, filepath.Dir(f)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(fixture, f), []byte("x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	seedOrg(t, db, orgID)
	seedConfig(t, q, orgID, fixture, "main", "")
	st := NewStore(db, t.TempDir(), WithCloneFunc(fixtureClone))

	pages, err := st.PageTree(context.Background(), orgID)
	if err != nil {
		t.Fatalf("tree: %v", err)
	}
	if len(pages) != 3 {
		t.Fatalf("got %d pages, want 3", len(pages))
	}
	// Only .md files are listed.
	for _, p := range pages {
		if p.Name == "" {
			t.Fatalf("empty name for %s", p.Path)
		}
	}
}

// TestStoreNoConfig verifies a missing config → ErrNoConfig.
func TestStoreNoConfig(t *testing.T) {
	db := dbtest.New(t)
	st := NewStore(db, t.TempDir(), WithCloneFunc(fixtureClone))
	if _, err := st.ReadPage(context.Background(), "nope", "index.md"); err == nil {
		t.Fatal("expected ErrNoConfig")
	}
}

// TestStorePathConfined verifies traversal outside the wiki path is rejected.
func TestStorePathConfined(t *testing.T) {
	db := dbtest.New(t)
	q := wikidb.New(db)
	orgID := "org-3"
	fixture := t.TempDir()
	if err := os.MkdirAll(filepath.Join(fixture, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A secret file outside docs.
	if err := os.WriteFile(filepath.Join(fixture, "secret.md"), []byte("top secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	seedOrg(t, db, orgID)
	seedConfig(t, q, orgID, fixture, "main", "docs")
	st := NewStore(db, t.TempDir(), WithCloneFunc(fixtureClone))

	// Traversal attempts must fail.
	for _, bad := range []string{"../secret.md", "../../etc/passwd", "/etc/passwd", "a/../../secret.md"} {
		if _, err := st.ReadPage(context.Background(), orgID, bad); err == nil {
			t.Fatalf("traversal %q was not rejected", bad)
		}
	}
}

// TestStoreRefreshPolicy verifies a stale checkout (past TTL) is refreshed.
func TestStoreRefreshPolicy(t *testing.T) {
	db := dbtest.New(t)
	q := wikidb.New(db)
	orgID := "org-4"
	fixture := t.TempDir()
	if err := os.WriteFile(filepath.Join(fixture, "page.md"), []byte("v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	seedOrg(t, db, orgID)
	seedConfig(t, q, orgID, fixture, "main", "")
	now := time.Now()
	st := NewStore(db, t.TempDir(), WithCloneFunc(fixtureClone), WithNow(func() time.Time { return now }))

	// First read clones. Then bump the fixture content to v2.
	if err := os.WriteFile(filepath.Join(fixture, "page.md"), []byte("v2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Advance past TTL → refresh on next read picks up v2.
	now = now.Add(10 * time.Minute)
	p, err := st.ReadPage(context.Background(), orgID, "page.md")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !contains(p.Markdown, "v2") {
		t.Fatalf("stale content not refreshed: %q", p.Markdown)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || (len(s) > 0 && indexOf(s, sub) >= 0))
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
