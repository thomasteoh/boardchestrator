package wiki

import (
	"context"
	"errors"
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
)

// initBareOrigin creates a bare git repo with one initial commit containing the
// given files under "docs/". Returns the bare repo path (usable as a local
// remote for PlainClone / Push).
func initBareOrigin(t *testing.T, files map[string]string) string {
	t.Helper()
	origin := t.TempDir()
	repo, err := gogit.PlainInit(origin, true)
	if err != nil {
		t.Fatalf("init bare origin: %v", err)
	}
	_ = repo
	// Build a worktree, commit files, then push to the bare origin.
	wt := t.TempDir()
	wrepo, err := gogit.PlainInit(wt, false)
	if err != nil {
		t.Fatalf("init worktree: %v", err)
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
	if _, err := w.Commit("initial", &gogit.CommitOptions{
		All:    true,
		Author: &object.Signature{Name: "seed", Email: "seed@example.com", When: time.Now()},
	}); err != nil {
		t.Fatalf("commit initial: %v", err)
	}
	_, err = wrepo.CreateRemote(&config.RemoteConfig{Name: "origin", URLs: []string{origin}})
	if err != nil {
		t.Fatalf("create remote: %v", err)
	}
	if err := wrepo.Push(&gogit.PushOptions{
		RemoteName: "origin",
		RefSpecs:   []config.RefSpec{"refs/heads/master:refs/heads/main"},
	}); err != nil {
		t.Fatalf("push initial: %v", err)
	}
	return origin
}

// seedTokenStore returns a tokenFn that always yields a fake token for userID.
func seedTokenStore(tok, login, name, email string) tokenFn {
	return func(ctx context.Context, userID string) (string, string, string, string, bool, error) {
		return tok, login, name, email, true, nil
	}
}

// TestWritePageCommitAsUser verifies a page edit is committed + pushed to the
// origin with the linked user's identity.
func TestWritePageCommitAsUser(t *testing.T) {
	db := dbtest.New(t)
	orgID := "org-edit-1"
	seedOrg(t, db, orgID)
	origin := initBareOrigin(t, map[string]string{"index.md": "# Hello\n"})
	seedConfig(t, wikidb.New(db), orgID, origin, "main", "docs")

	st := NewStore(db, t.TempDir(), WithCloneFunc(plainClone), WithTokenFn(seedTokenStore("tok-abc", "octocat", "Ada Lovelace", "ada@example.com")))
	if err := st.WritePage(context.Background(), orgID, "index.md", "# Edited\n", "update index", "user-1"); err != nil {
		t.Fatalf("WritePage: %v", err)
	}

	// Verify the origin now has the edited content, committed by the user.
	repo, err := gogit.PlainOpen(origin)
	if err != nil {
		t.Fatalf("open origin: %v", err)
	}
	ref, err := repo.Reference(plumbing.ReferenceName("refs/heads/main"), true)
	if err != nil {
		t.Fatalf("ref main: %v", err)
	}
	commit, err := repo.CommitObject(ref.Hash())
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if commit.Author.Name != "Ada Lovelace" {
		t.Fatalf("author name = %q, want Ada Lovelace", commit.Author.Name)
	}
	f, err := commit.File("docs/index.md")
	if err != nil {
		t.Fatalf("file: %v", err)
	}
	c, err := f.Contents()
	if err != nil {
		t.Fatalf("contents: %v", err)
	}
	if !strings.Contains(c, "# Edited") {
		t.Fatalf("origin content not updated: %q", c)
	}
}

// TestWritePageUnlinked verifies a user without a linked token gets read-only:
// WritePage returns ErrNotConnected.
func TestWritePageUnlinked(t *testing.T) {
	db := dbtest.New(t)
	orgID := "org-edit-2"
	seedOrg(t, db, orgID)
	origin := initBareOrigin(t, map[string]string{"index.md": "# Hello\n"})
	seedConfig(t, wikidb.New(db), orgID, origin, "main", "docs")

	st := NewStore(db, t.TempDir(), WithCloneFunc(plainClone), WithTokenFn(func(ctx context.Context, userID string) (string, string, string, string, bool, error) {
		return "", "", "", "", false, nil
	}))
	err := st.WritePage(context.Background(), orgID, "index.md", "# Edited\n", "update", "user-1")
	if !errors.Is(err, ErrNotConnected) {
		t.Fatalf("expected ErrNotConnected, got %v", err)
	}
}

// TestWritePageNoTokenResolver verifies the store errors when no token fn is
// wired (server not configured).
func TestWritePageNoTokenResolver(t *testing.T) {
	db := dbtest.New(t)
	orgID := "org-edit-3"
	seedOrg(t, db, orgID)
	origin := initBareOrigin(t, map[string]string{"index.md": "# Hello\n"})
	seedConfig(t, wikidb.New(db), orgID, origin, "main", "docs")

	st := NewStore(db, t.TempDir(), WithCloneFunc(plainClone))
	err := st.WritePage(context.Background(), orgID, "index.md", "# Edited\n", "update", "user-1")
	if err == nil || !strings.Contains(err.Error(), "token resolver") {
		t.Fatalf("expected token-resolver error, got %v", err)
	}
}

// TestHistory verifies the commit log for a page, newest-first.
func TestHistory(t *testing.T) {
	db := dbtest.New(t)
	orgID := "org-hist-1"
	seedOrg(t, db, orgID)
	origin := initBareOrigin(t, map[string]string{"index.md": "# Hello\n"})
	seedConfig(t, wikidb.New(db), orgID, origin, "main", "docs")

	st := NewStore(db, t.TempDir(), WithCloneFunc(plainClone), WithTokenFn(seedTokenStore("tok", "octocat", "Ada", "ada@example.com")))
	if err := st.WritePage(context.Background(), orgID, "index.md", "# Hello v2\n", "second edit", "user-1"); err != nil {
		t.Fatalf("WritePage: %v", err)
	}

	commits, err := st.History(context.Background(), orgID, "index.md")
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(commits) < 2 {
		t.Fatalf("got %d commits, want >=2", len(commits))
	}
	if commits[0].Message != "second edit" {
		t.Fatalf("newest commit = %q, want 'second edit'", commits[0].Message)
	}
	if commits[0].Author != "Ada" {
		t.Fatalf("author = %q, want Ada", commits[0].Author)
	}
}

// TestReadPageRevision verifies rendering a page at a past commit.
func TestReadPageRevision(t *testing.T) {
	db := dbtest.New(t)
	orgID := "org-rev-1"
	seedOrg(t, db, orgID)
	origin := initBareOrigin(t, map[string]string{"index.md": "# Hello\n"})
	seedConfig(t, wikidb.New(db), orgID, origin, "main", "docs")

	st := NewStore(db, t.TempDir(), WithCloneFunc(plainClone), WithTokenFn(seedTokenStore("tok", "octocat", "Ada", "ada@example.com")))
	// Commit a second edit.
	if err := st.WritePage(context.Background(), orgID, "index.md", "# Hello v2\n", "second", "user-1"); err != nil {
		t.Fatalf("WritePage: %v", err)
	}
	// History gives us the two hashes.
	commits, err := st.History(context.Background(), orgID, "index.md")
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	oldest := commits[len(commits)-1]

	page, err := st.ReadPageRevision(context.Background(), orgID, "index.md", oldest.Hash)
	if err != nil {
		t.Fatalf("ReadPageRevision: %v", err)
	}
	if !strings.Contains(page.Markdown, "# Hello") {
		t.Fatalf("revision content = %q, want original", page.Markdown)
	}
	if strings.Contains(page.Markdown, "v2") {
		t.Fatalf("revision leaked later content: %q", page.Markdown)
	}
}

// TestRenamePageConflict verifies a non-fast-forward push on a rename maps to
// ErrConflict (rename cannot auto-reapply on a fresh checkout).
func TestRenamePageConflict(t *testing.T) {
	db := dbtest.New(t)
	orgID := "org-renconf-1"
	seedOrg(t, db, orgID)
	origin := initBareOrigin(t, map[string]string{"index.md": "# Hello\n"})
	seedConfig(t, wikidb.New(db), orgID, origin, "main", "docs")

	st := NewStore(db, t.TempDir(), WithCloneFunc(plainClone), WithTokenFn(seedTokenStore("tok", "octocat", "Ada", "ada@example.com")))
	// First rename pushes cleanly.
	if err := st.RenamePage(context.Background(), orgID, "index.md", "guide.md", "rename one", "user-1"); err != nil {
		t.Fatalf("first rename: %v", err)
	}
	// Another store makes an upstream edit that diverges st's clone.
	other := NewStore(db, t.TempDir(), WithCloneFunc(plainClone), WithTokenFn(seedTokenStore("tok", "octocat", "Bob", "bob@example.com")))
	if err := other.WritePage(context.Background(), orgID, "guide.md", "# upstream\n", "upstream", "user-2"); err != nil {
		t.Fatalf("upstream WritePage: %v", err)
	}
	// st's clone is now behind; renaming a page pushes non-FF → ErrConflict.
	err := st.RenamePage(context.Background(), orgID, "guide.md", "final.md", "rename two", "user-1")
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict, got %v", err)
	}
}

// TestRenamePage verifies rename commits + pushes to the origin.
func TestRenamePage(t *testing.T) {
	db := dbtest.New(t)
	orgID := "org-ren-1"
	seedOrg(t, db, orgID)
	origin := initBareOrigin(t, map[string]string{"index.md": "# Hello\n"})
	seedConfig(t, wikidb.New(db), orgID, origin, "main", "docs")

	st := NewStore(db, t.TempDir(), WithCloneFunc(plainClone), WithTokenFn(seedTokenStore("tok", "octocat", "Ada", "ada@example.com")))
	if err := st.RenamePage(context.Background(), orgID, "index.md", "guide.md", "rename", "user-1"); err != nil {
		t.Fatalf("RenamePage: %v", err)
	}

	repo, err := gogit.PlainOpen(origin)
	if err != nil {
		t.Fatalf("open origin: %v", err)
	}
	ref, err := repo.Reference(plumbing.ReferenceName("refs/heads/main"), true)
	if err != nil {
		t.Fatalf("ref main: %v", err)
	}
	commit, err := repo.CommitObject(ref.Hash())
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if _, err := commit.File("docs/guide.md"); err != nil {
		t.Fatalf("guide.md missing after rename: %v", err)
	}
	if _, err := commit.File("docs/index.md"); err == nil {
		t.Fatalf("index.md still present after rename")
	}
}
