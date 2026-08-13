package action

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
	wikidb "github.com/thomasteoh/boardchestrator/internal/db/sqlc/wiki"
	"github.com/thomasteoh/boardchestrator/internal/wiki"
)

// wikiFixtureStore builds a wiki.Store backed by a temp-dir fixture (no
// network/git): the clone func just copies the fixture dir. db is the DB the
// store reads wiki_configs from.
func wikiFixtureStore(t *testing.T, db *sql.DB, files map[string]string) *wiki.Store {
	t.Helper()
	fixture := t.TempDir()
	for p, content := range files {
		if err := os.MkdirAll(filepath.Join(fixture, filepath.Dir(p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(fixture, p), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	copyFn := func(ctx context.Context, url, ref, worktree string, shallow bool) error {
		return filepath.Walk(fixture, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(fixture, p)
			tgt := filepath.Join(worktree, rel)
			if info.IsDir() {
				return os.MkdirAll(tgt, 0o755)
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			return os.WriteFile(tgt, b, 0o600)
		})
	}
	return wiki.NewStore(db, t.TempDir(),
		wiki.WithCloneFunc(copyFn))
}

// seedOrg inserts an org row so wiki_configs' FK (org_id → orgs.id) holds.
func seedOrg(t *testing.T, db *sql.DB, orgID string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO orgs (id, name, slug) VALUES (?, ?, ?)`, orgID, "Org "+orgID, "org-"+orgID); err != nil {
		t.Fatalf("seed org: %v", err)
	}
}

// TestWikiConfigDistinctPermissions verifies wiki.config.repo (org owner) and
// wiki.config.ref (team admin) are distinct permissions with read-modify-write
// semantics: setting repo preserves ref/path, setting ref/path preserves repo.
func TestWikiConfigDistinctPermissions(t *testing.T) {
	reset()
	t.Cleanup(reset)
	Register(Definition{Name: "wiki.config.repo", Impact: ImpactLow, Permission: "wiki.config.repo", Scope: ScopeOrg, Input: ObjectSchema{Fields: []Field{{Name: "org_id", Kind: KindString, Required: true}, {Name: "repo", Kind: KindString, Required: true}}}, Handle: handleWikiConfigRepo})
	Register(Definition{Name: "wiki.config.ref", Impact: ImpactLow, Permission: "wiki.config.ref", Scope: ScopeOrg, Input: ObjectSchema{Fields: []Field{{Name: "org_id", Kind: KindString, Required: true}, {Name: "ref", Kind: KindString, Required: false}, {Name: "path", Kind: KindString, Required: false}}}, Handle: handleWikiConfigRef})

	db := dbtest.New(t)
	d := New(db)
	ctx := context.Background()

	// Seed the org row (wiki_configs.org_id → orgs.id FK) and the store.
	seedOrg(t, db, "o1")
	SetWikiStore(wiki.NewStore(db, t.TempDir()))
	t.Cleanup(func() { SetWikiStore(nil) })

	// Distinct permissions on the two actions.
	repoDef := mustFind(t, "wiki.config.repo")
	refDef := mustFind(t, "wiki.config.ref")
	if repoDef.Permission == refDef.Permission {
		t.Fatalf("repo and ref permissions must differ (got both %q)", repoDef.Permission)
	}
	if repoDef.Permission != "wiki.config.repo" || refDef.Permission != "wiki.config.ref" {
		t.Fatalf("unexpected permissions: repo=%q ref=%q", repoDef.Permission, refDef.Permission)
	}

	// Org owner sets repo.
	out, err := d.Dispatch(ctx, userActor(), "wiki.config.repo",
		json.RawMessage(`{"org_id":"o1","repo":"https://github.com/acme/wiki"}`), Opts{})
	if err != nil {
		t.Fatalf("config.repo: %v", err)
	}
	if !strings.Contains(mustJSON(t, out), `"repo":"https://github.com/acme/wiki"`) {
		t.Fatalf("repo not set: %s", mustJSON(t, out))
	}

	// Team admin sets ref+path; repo must be preserved.
	out, err = d.Dispatch(ctx, userActor(), "wiki.config.ref",
		json.RawMessage(`{"org_id":"o1","ref":"dev","path":"docs"}`), Opts{})
	if err != nil {
		t.Fatalf("config.ref: %v", err)
	}
	s := mustJSON(t, out)
	if !strings.Contains(s, `"ref":"dev"`) || !strings.Contains(s, `"path":"docs"`) ||
		!strings.Contains(s, `"repo":"https://github.com/acme/wiki"`) {
		t.Fatalf("ref/path set but repo clobbered: %s", s)
	}

	// Setting repo again preserves ref/path.
	out, err = d.Dispatch(ctx, userActor(), "wiki.config.repo",
		json.RawMessage(`{"org_id":"o1","repo":"https://github.com/acme/wiki2"}`), Opts{})
	if err != nil {
		t.Fatalf("config.repo 2: %v", err)
	}
	s = mustJSON(t, out)
	if !strings.Contains(s, `"repo":"https://github.com/acme/wiki2"`) ||
		!strings.Contains(s, `"ref":"dev"`) || !strings.Contains(s, `"path":"docs"`) {
		t.Fatalf("repo update clobbered ref/path: %s", s)
	}
}

// TestWikiReadAndTree verifies wiki.read renders a page and wiki.tree lists
// the page tree via the injected store.
func TestWikiReadAndTree(t *testing.T) {
	reset()
	t.Cleanup(reset)
	Register(Definition{Name: "wiki.read", Impact: ImpactRead, Permission: "wiki.read", Scope: ScopeOrg, Input: ObjectSchema{Fields: []Field{{Name: "org_id", Kind: KindString, Required: true}, {Name: "path", Kind: KindString, Required: true}}}, Handle: handleWikiRead})
	Register(Definition{Name: "wiki.tree", Impact: ImpactRead, Permission: "wiki.read", Scope: ScopeOrg, Input: ObjectSchema{Fields: []Field{{Name: "org_id", Kind: KindString, Required: true}}}, Handle: handleWikiTree})

	db := dbtest.New(t)
	st := wikiFixtureStore(t, db, map[string]string{
		"index.md":       "# Home\n\nSee ABC-1\n",
		"guides/read.md": "## Guide\n",
	})
	// Config the org's wiki to the fixture repo.
	seedOrg(t, db, "o2")
	q := wikidb.New(db)
	if err := q.UpsertWikiConfig(context.Background(), wikidb.UpsertWikiConfigParams{
		OrgID: "o2", Repo: "fixture", Ref: "main", Path: "",
		CreatedAt: "2026-01-01T00:00:00.000Z",
		UpdatedAt: "2026-01-01T00:00:00.000Z",
	}); err != nil {
		t.Fatalf("seed wiki config: %v", err)
	}
	SetWikiStore(st)
	t.Cleanup(func() { SetWikiStore(nil) })

	d := New(db)
	ctx := context.Background()

	// Tree lists both pages.
	out, err := d.Dispatch(ctx, userActor(), "wiki.tree", json.RawMessage(`{"org_id":"o2"}`), Opts{})
	if err != nil {
		t.Fatalf("tree: %v", err)
	}
	if !strings.Contains(mustJSON(t, out), `"name":"index"`) || !strings.Contains(mustJSON(t, out), `"name":"read"`) {
		t.Fatalf("tree missing pages: %s", mustJSON(t, out))
	}

	// Read renders a page.
	out, err = d.Dispatch(ctx, userActor(), "wiki.read", json.RawMessage(`{"org_id":"o2","path":"index.md"}`), Opts{})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	s := mustJSON(t, out)
	if !strings.Contains(s, `"name":"index"`) || !strings.Contains(s, `\u003ch1\u003e`) {
		t.Fatalf("read not rendered: %s", s)
	}

	// Missing page → error.
	if _, err := d.Dispatch(ctx, userActor(), "wiki.read", json.RawMessage(`{"org_id":"o2","path":"nope.md"}`), Opts{}); err == nil {
		t.Fatal("expected error for missing page")
	}
}

func mustFind(t *testing.T, name string) Definition {
	t.Helper()
	for _, d := range All() {
		if d.Name == name {
			return d
		}
	}
	t.Fatalf("action %s not registered", name)
	return Definition{}
}
