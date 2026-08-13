package action

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
	wikidb "github.com/thomasteoh/boardchestrator/internal/db/sqlc/wiki"
	"github.com/thomasteoh/boardchestrator/internal/wiki"
)

// initGitOrigin creates a bare local git repo with one initial commit holding
// the given files under "docs/". Returns the bare path.
func initGitOrigin(t *testing.T, files map[string]string) string {
	t.Helper()
	origin := t.TempDir()
	if _, err := gogit.PlainInit(origin, true); err != nil {
		t.Fatalf("init bare: %v", err)
	}
	wt := t.TempDir()
	wrepo, err := gogit.PlainInit(wt, false)
	if err != nil {
		t.Fatalf("init wt: %v", err)
	}
	w, err := wrepo.Worktree()
	if err != nil {
		t.Fatalf("worktree: %v", err)
	}
	for p, content := range files {
		target := filepath.Join(wt, "docs", p)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Add("docs/" + p); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := w.Commit("initial", &gogit.CommitOptions{All: true, Author: &object.Signature{Name: "seed", Email: "seed@example.com", When: time.Now()}}); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if _, err := wrepo.CreateRemote(&config.RemoteConfig{Name: "origin", URLs: []string{origin}}); err != nil {
		t.Fatalf("remote: %v", err)
	}
	if err := wrepo.Push(&gogit.PushOptions{RemoteName: "origin", RefSpecs: []config.RefSpec{"refs/heads/master:refs/heads/main"}}); err != nil {
		t.Fatalf("push: %v", err)
	}
	return origin
}

// TestWikiEditCommitAsUser verifies wiki.edit saves a page and commits it as
// the actor's linked GitHub identity (via the injected token fn).
func TestWikiEditCommitAsUser(t *testing.T) {
	reset()
	t.Cleanup(reset)
	Register(Definition{Name: "wiki.edit", Impact: ImpactLow, Permission: "wiki.edit", Scope: ScopeOrg, Input: ObjectSchema{Fields: []Field{{Name: "org_id", Kind: KindString, Required: true}, {Name: "path", Kind: KindString, Required: true}, {Name: "markdown", Kind: KindString, Required: true}, {Name: "message", Kind: KindString, Required: false}}}, Handle: handleWikiEdit})
	Register(Definition{Name: "wiki.history", Impact: ImpactRead, Permission: "wiki.read", Scope: ScopeOrg, Input: ObjectSchema{Fields: []Field{{Name: "org_id", Kind: KindString, Required: true}, {Name: "path", Kind: KindString, Required: true}}}, Handle: handleWikiHistory})

	db := dbtest.New(t)
	seedOrg(t, db, "oe1")
	origin := initGitOrigin(t, map[string]string{"index.md": "# Hello\n"})
	q := wikidb.New(db)
	if err := q.UpsertWikiConfig(context.Background(), wikidb.UpsertWikiConfigParams{
		OrgID: "oe1", Repo: origin, Ref: "main", Path: "docs",
		CreatedAt: "2026-01-01T00:00:00.000Z", UpdatedAt: "2026-01-01T00:00:00.000Z",
	}); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	// The store reads config from db and clones from the local origin.
	cloneFn := func(ctx context.Context, url, ref, worktree string, shallow bool) error {
		_, err := gogit.PlainClone(worktree, false, &gogit.CloneOptions{URL: url, ReferenceName: plumbing.ReferenceName("refs/heads/" + ref), SingleBranch: true})
		return err
	}
	st2 := wiki.NewStore(db, t.TempDir(),
		wiki.WithCloneFunc(cloneFn),
		wiki.WithTokenFn(func(ctx context.Context, userID string) (string, string, string, string, bool, error) {
			return "tok-fake", "octocat", "Ada Lovelace", "ada@example.com", true, nil
		}))
	SetWikiStore(st2)
	t.Cleanup(func() { SetWikiStore(nil) })

	d := New(db)
	ctx := context.Background()
	out, err := d.Dispatch(ctx, userActor(), "wiki.edit",
		json.RawMessage(`{"org_id":"oe1","path":"index.md","markdown":"# Edited\n","message":"update"}`), Opts{})
	if err != nil {
		t.Fatalf("wiki.edit: %v", err)
	}
	if !strings.Contains(mustJSON(t, out), `"saved":"true"`) {
		t.Fatalf("edit not saved: %s", mustJSON(t, out))
	}
	// History should now show the edit commit.
	out, err = d.Dispatch(ctx, userActor(), "wiki.history",
		json.RawMessage(`{"org_id":"oe1","path":"index.md"}`), Opts{})
	if err != nil {
		t.Fatalf("wiki.history: %v", err)
	}
	if !strings.Contains(mustJSON(t, out), `"message":"update"`) {
		t.Fatalf("history missing edit commit: %s", mustJSON(t, out))
	}
	if !strings.Contains(mustJSON(t, out), `"author":"Ada Lovelace"`) {
		t.Fatalf("history missing author identity: %s", mustJSON(t, out))
	}
}

// TestWikiEditUnlinked verifies an actor without a linked GitHub token gets
// read-only: wiki.edit returns ErrNotConnected.
func TestWikiEditUnlinked(t *testing.T) {
	reset()
	t.Cleanup(reset)
	Register(Definition{Name: "wiki.edit", Impact: ImpactLow, Permission: "wiki.edit", Scope: ScopeOrg, Input: ObjectSchema{Fields: []Field{{Name: "org_id", Kind: KindString, Required: true}, {Name: "path", Kind: KindString, Required: true}, {Name: "markdown", Kind: KindString, Required: true}}}, Handle: handleWikiEdit})

	db := dbtest.New(t)
	seedOrg(t, db, "oe2")
	origin := initGitOrigin(t, map[string]string{"index.md": "# Hello\n"})
	q := wikidb.New(db)
	if err := q.UpsertWikiConfig(context.Background(), wikidb.UpsertWikiConfigParams{
		OrgID: "oe2", Repo: origin, Ref: "main", Path: "docs",
		CreatedAt: "2026-01-01T00:00:00.000Z", UpdatedAt: "2026-01-01T00:00:00.000Z",
	}); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	cloneFn := func(ctx context.Context, url, ref, worktree string, shallow bool) error {
		_, err := gogit.PlainClone(worktree, false, &gogit.CloneOptions{URL: url, ReferenceName: plumbing.ReferenceName("refs/heads/" + ref), SingleBranch: true})
		return err
	}
	st := wiki.NewStore(db, t.TempDir(),
		wiki.WithCloneFunc(cloneFn),
		wiki.WithTokenFn(func(ctx context.Context, userID string) (string, string, string, string, bool, error) {
			return "", "", "", "", false, nil // not linked
		}))
	SetWikiStore(st)
	t.Cleanup(func() { SetWikiStore(nil) })

	d := New(db)
	_, err := d.Dispatch(context.Background(), userActor(), "wiki.edit",
		json.RawMessage(`{"org_id":"oe2","path":"index.md","markdown":"# Edited\n"}`), Opts{})
	if err == nil || !strings.Contains(err.Error(), "connect GitHub") {
		t.Fatalf("expected read-only error, got %v", err)
	}
}

// TestWikiReadRevisionAction verifies wiki.read_revision renders a past commit.
func TestWikiReadRevisionAction(t *testing.T) {
	reset()
	t.Cleanup(reset)
	Register(Definition{Name: "wiki.edit", Impact: ImpactLow, Permission: "wiki.edit", Scope: ScopeOrg, Input: ObjectSchema{Fields: []Field{{Name: "org_id", Kind: KindString, Required: true}, {Name: "path", Kind: KindString, Required: true}, {Name: "markdown", Kind: KindString, Required: true}}}, Handle: handleWikiEdit})
	Register(Definition{Name: "wiki.history", Impact: ImpactRead, Permission: "wiki.read", Scope: ScopeOrg, Input: ObjectSchema{Fields: []Field{{Name: "org_id", Kind: KindString, Required: true}, {Name: "path", Kind: KindString, Required: true}}}, Handle: handleWikiHistory})
	Register(Definition{Name: "wiki.read_revision", Impact: ImpactRead, Permission: "wiki.read", Scope: ScopeOrg, Input: ObjectSchema{Fields: []Field{{Name: "org_id", Kind: KindString, Required: true}, {Name: "path", Kind: KindString, Required: true}, {Name: "rev", Kind: KindString, Required: false}}}, Handle: handleWikiReadRevision})

	db := dbtest.New(t)
	seedOrg(t, db, "oe3")
	origin := initGitOrigin(t, map[string]string{"index.md": "# Hello\n"})
	q := wikidb.New(db)
	if err := q.UpsertWikiConfig(context.Background(), wikidb.UpsertWikiConfigParams{
		OrgID: "oe3", Repo: origin, Ref: "main", Path: "docs",
		CreatedAt: "2026-01-01T00:00:00.000Z", UpdatedAt: "2026-01-01T00:00:00.000Z",
	}); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	cloneFn := func(ctx context.Context, url, ref, worktree string, shallow bool) error {
		_, err := gogit.PlainClone(worktree, false, &gogit.CloneOptions{URL: url, ReferenceName: plumbing.ReferenceName("refs/heads/" + ref), SingleBranch: true})
		return err
	}
	st := wiki.NewStore(db, t.TempDir(), wiki.WithCloneFunc(cloneFn),
		wiki.WithTokenFn(func(ctx context.Context, userID string) (string, string, string, string, bool, error) {
			return "tok-fake", "octocat", "Ada", "ada@example.com", true, nil
		}))
	SetWikiStore(st)
	t.Cleanup(func() { SetWikiStore(nil) })

	d := New(db)
	ctx := context.Background()
	// Edit once so there are two revisions.
	if _, err := d.Dispatch(ctx, userActor(), "wiki.edit",
		json.RawMessage(`{"org_id":"oe3","path":"index.md","markdown":"# Hello v2\n"}`), Opts{}); err != nil {
		t.Fatalf("edit: %v", err)
	}
	// Get history to find the initial commit hash.
	hout, err := d.Dispatch(ctx, userActor(), "wiki.history",
		json.RawMessage(`{"org_id":"oe3","path":"index.md"}`), Opts{})
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	hs := mustJSON(t, hout)
	// Parse the oldest hash.
	var commits []map[string]string
	if err := json.Unmarshal([]byte(hs), &commits); err != nil {
		t.Fatalf("parse history: %v", err)
	}
	oldestHash := commits[len(commits)-1]["hash"]

	out, err := d.Dispatch(ctx, userActor(), "wiki.read_revision",
		json.RawMessage(`{"org_id":"oe3","path":"index.md","rev":"`+oldestHash+`"}`), Opts{})
	if err != nil {
		t.Fatalf("read_revision: %v", err)
	}
	s := mustJSON(t, out)
	if !strings.Contains(s, `# Hello`) || strings.Contains(s, "v2") {
		t.Fatalf("revision wrong: %s", s)
	}
}
