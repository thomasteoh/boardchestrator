package wiki

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
)

// ErrConflict is returned when a wiki push is rejected as a non-fast-forward
// twice in a row — the page changed upstream and the edit cannot be merged.
var ErrConflict = errors.New("wiki: conflict — the page changed upstream; reload and reapply")

// ErrNotConnected is returned when the actor has no linked GitHub token.
var ErrNotConnected = errors.New("wiki: connect GitHub in settings to edit the wiki")

// ErrNonFastForward wraps a go-git non-fast-forward push rejection. go-git
// returns a plain fmt.Errorf("non-fast-forward update: <ref>") that is NOT the
// exported ErrNonFastForwardUpdate sentinel, so we normalize it here.
var ErrNonFastForward = errors.New("wiki: non-fast-forward update")

// tokenFn resolves a user's GitHub token + author identity for commit-as-user.
// Returns ok=false when the user has no linked token.
type tokenFn func(ctx context.Context, userID string) (token, login, name, email string, ok bool, err error)

// Commit is one wiki page change (from git history).
type Commit struct {
	Hash      string `json:"hash"`
	Message   string `json:"message"`
	Author    string `json:"author"`
	AuthorAt  string `json:"author_at"`
	Committer string `json:"committer"`
	When      string `json:"when"`
}

// WritePage saves pagePath's markdown, commits it as the linked GitHub user,
// and pushes. On a non-fast-forward push it refreshes the checkout once and
// retries; if still rejected it returns ErrConflict. The org's wiki must be
// configured and the user must have a linked GitHub token.
func (s *Store) WritePage(ctx context.Context, orgID, pagePath, markdown, message, userID string) error {
	cfg, err := s.config(ctx, orgID)
	if err != nil {
		return err
	}
	if !confined(cfg.Path, pagePath) {
		return fmt.Errorf("wiki: page path %q escapes the wiki path %q", pagePath, cfg.Path)
	}
	if s.token == nil {
		return fmt.Errorf("wiki: token resolver not configured")
	}
	tok, login, name, email, ok, terr := s.token(ctx, userID)
	if terr != nil {
		return fmt.Errorf("wiki: resolve token: %w", terr)
	}
	if !ok {
		return ErrNotConnected
	}
	worktree, err := s.syncCheckout(ctx, cfg)
	if err != nil {
		return err
	}
	msg := message
	if msg == "" {
		msg = "Edit " + pagePath
	}
	author := name
	if author == "" {
		author = login
	}
	if author == "" {
		author = "wiki user"
	}
	commitEmail := email
	if commitEmail == "" {
		commitEmail = login + "@users.noreply.github.com"
	}
	// Write + commit locally.
	if err := writeFileUnder(worktree, cfg.Path, pagePath, markdown); err != nil {
		return fmt.Errorf("wiki: write %s: %w", pagePath, err)
	}
	if err := s.commitAndPush(ctx, cfg, worktree, pagePath, markdown, msg, author, commitEmail, tok); err != nil {
		if errors.Is(err, ErrConflict) {
			return err
		}
		return err
	}
	return nil
}

// commitAndPush commits the staged page change and pushes with token auth.
// On ErrNonFastForwardUpdate it refreshes the checkout from the remote once
// and retries; a second rejection returns ErrConflict.
func (s *Store) commitAndPush(ctx context.Context, cfg Config, worktree, pagePath, markdown, msg, author, email, tok string) error {
	repo, err := gogit.PlainOpen(worktree)
	if err != nil {
		return fmt.Errorf("wiki: open checkout: %w", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("wiki: worktree: %w", err)
	}
	// pagePath is relative to the wiki sub-path; the git repo is rooted at the
	// worktree, so the repo-relative path is cfg.Path + "/" + pagePath.
	repoPath := filepath.ToSlash(filepath.Join(cfg.Path, pagePath))
	if _, err := wt.Add(repoPath); err != nil {
		return fmt.Errorf("wiki: add %s: %w", pagePath, err)
	}
	hash, err := wt.Commit(msg, &gogit.CommitOptions{
		All: true,
		Author: &object.Signature{
			Name:  author,
			Email: email,
			When:  time.Now(),
		},
	})
	if err != nil {
		if errors.Is(err, gogit.ErrEmptyCommit) {
			// No change to commit — nothing to push.
			return nil
		}
		return fmt.Errorf("wiki: commit: %w", err)
	}
	_ = hash
	if err := s.push(ctx, cfg, worktree, tok); err != nil {
		if !errors.Is(err, ErrNonFastForward) {
			return fmt.Errorf("wiki: push: %w", err)
		}
		// Non-fast-forward: refresh from remote once, re-apply the change, retry.
		if err := s.clone(ctx, cfg.Repo, cfg.Ref, worktree, true); err != nil {
			return fmt.Errorf("wiki: refresh after conflict: %w", err)
		}
		if err := os.WriteFile(filepath.Join(worktree, ".bc-wiki-ref"), []byte(cfg.Ref), 0o600); err != nil {
			return fmt.Errorf("wiki: re-stamp: %w", err)
		}
		// Re-open the fresh checkout, re-write the page, commit, and push once more.
		repo2, err := gogit.PlainOpen(worktree)
		if err != nil {
			return fmt.Errorf("wiki: reopen checkout: %w", err)
		}
		wt2, err := repo2.Worktree()
		if err != nil {
			return fmt.Errorf("wiki: worktree: %w", err)
		}
		if err := writeFileUnder(worktree, cfg.Path, pagePath, markdown); err != nil {
			return fmt.Errorf("wiki: reapply %s: %w", pagePath, err)
		}
		if _, err := wt2.Add(repoPath); err != nil {
			return fmt.Errorf("wiki: re-add: %w", err)
		}
		if _, err := wt2.Commit(msg, &gogit.CommitOptions{All: true, Author: &object.Signature{Name: author, Email: email, When: time.Now()}}); err != nil {
			return fmt.Errorf("wiki: re-commit: %w", err)
		}
		if err := s.push(ctx, cfg, worktree, tok); err != nil {
			if errors.Is(err, ErrNonFastForward) {
				return ErrConflict
			}
			return fmt.Errorf("wiki: retry push: %w", err)
		}
	}
	return nil
}

// push pushes the local branch (refs/heads/<ref>) to the remote at the same
// ref with token auth. It must name the concrete ref — go-git does not resolve
// the literal "HEAD" refspec (it would silently no-op).
func (s *Store) push(ctx context.Context, cfg Config, worktree, tok string) error {
	repo, err := gogit.PlainOpen(worktree)
	if err != nil {
		return fmt.Errorf("wiki: open for push: %w", err)
	}
	auth := &http.BasicAuth{Username: "x-access-token", Password: tok}
	refspec := config.RefSpec("refs/heads/" + cfg.Ref + ":refs/heads/" + cfg.Ref)
	err = repo.PushContext(ctx, &gogit.PushOptions{
		RemoteName: "origin",
		RefSpecs:   []config.RefSpec{refspec},
		Auth:       auth,
	})
	if err != nil {
		if errors.Is(err, gogit.NoErrAlreadyUpToDate) {
			return nil
		}
		if strings.HasPrefix(err.Error(), "non-fast-forward update") {
			return ErrNonFastForward
		}
		return err
	}
	return nil
}

// RenamePage moves pagePath to newPath and commits as the linked GitHub user.
func (s *Store) RenamePage(ctx context.Context, orgID, pagePath, newPath, message, userID string) error {
	cfg, err := s.config(ctx, orgID)
	if err != nil {
		return err
	}
	if !confined(cfg.Path, pagePath) || !confined(cfg.Path, newPath) {
		return fmt.Errorf("wiki: rename path escapes wiki path")
	}
	worktree, err := s.syncCheckout(ctx, cfg)
	if err != nil {
		return err
	}
	tok, login, name, email, ok, terr := s.token(ctx, userID)
	if terr != nil {
		return fmt.Errorf("wiki: resolve token: %w", terr)
	}
	if !ok {
		return ErrNotConnected
	}
	author := name
	if author == "" {
		author = login
	}
	if author == "" {
		author = "wiki user"
	}
	commitEmail := email
	if commitEmail == "" {
		commitEmail = login + "@users.noreply.github.com"
	}
	repo, err := gogit.PlainOpen(worktree)
	if err != nil {
		return fmt.Errorf("wiki: open checkout: %w", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("wiki: worktree: %w", err)
	}
	if err := os.Rename(filepath.Join(worktree, cfg.Path, pagePath), filepath.Join(worktree, cfg.Path, newPath)); err != nil {
		return fmt.Errorf("wiki: rename %s→%s: %w", pagePath, newPath, err)
	}
	newRepoPath := filepath.ToSlash(filepath.Join(cfg.Path, newPath))
	oldRepoPath := filepath.ToSlash(filepath.Join(cfg.Path, pagePath))
	if _, err := wt.Add(newRepoPath); err != nil {
		return fmt.Errorf("wiki: add new: %w", err)
	}
	if _, err := wt.Remove(oldRepoPath); err != nil {
		return fmt.Errorf("wiki: remove old: %w", err)
	}
	msg := message
	if msg == "" {
		msg = "Rename " + pagePath + " to " + newPath
	}
	if _, err := wt.Commit(msg, &gogit.CommitOptions{All: true, Author: &object.Signature{Name: author, Email: commitEmail, When: time.Now()}}); err != nil {
		return fmt.Errorf("wiki: commit rename: %w", err)
	}
	return s.pushOnce(ctx, cfg, worktree, tok)
}

// DeletePage removes pagePath and commits as the linked GitHub user.
func (s *Store) DeletePage(ctx context.Context, orgID, pagePath, message, userID string) error {
	cfg, err := s.config(ctx, orgID)
	if err != nil {
		return err
	}
	if !confined(cfg.Path, pagePath) {
		return fmt.Errorf("wiki: delete path escapes wiki path")
	}
	worktree, err := s.syncCheckout(ctx, cfg)
	if err != nil {
		return err
	}
	tok, login, name, email, ok, terr := s.token(ctx, userID)
	if terr != nil {
		return fmt.Errorf("wiki: resolve token: %w", terr)
	}
	if !ok {
		return ErrNotConnected
	}
	author := name
	if author == "" {
		author = login
	}
	if author == "" {
		author = "wiki user"
	}
	commitEmail := email
	if commitEmail == "" {
		commitEmail = login + "@users.noreply.github.com"
	}
	repo, err := gogit.PlainOpen(worktree)
	if err != nil {
		return fmt.Errorf("wiki: open checkout: %w", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("wiki: worktree: %w", err)
	}
	if _, err := wt.Remove(filepath.ToSlash(filepath.Join(cfg.Path, pagePath))); err != nil {
		return fmt.Errorf("wiki: remove %s: %w", pagePath, err)
	}
	msg := message
	if msg == "" {
		msg = "Delete " + pagePath
	}
	if _, err := wt.Commit(msg, &gogit.CommitOptions{All: true, Author: &object.Signature{Name: author, Email: commitEmail, When: time.Now()}}); err != nil {
		return fmt.Errorf("wiki: commit delete: %w", err)
	}
	return s.pushOnce(ctx, cfg, worktree, tok)
}

// pushOnce pushes and maps a non-fast-forward rejection to ErrConflict. Used
// by rename/delete, where auto-retry can't re-apply the operation on a fresh
// checkout — the UI tells the user to reload and reapply.
func (s *Store) pushOnce(ctx context.Context, cfg Config, worktree, tok string) error {
	if err := s.push(ctx, cfg, worktree, tok); err != nil {
		if errors.Is(err, ErrNonFastForward) {
			return ErrConflict
		}
		return err
	}
	return nil
}

func (s *Store) History(ctx context.Context, orgID, pagePath string) ([]Commit, error) {
	cfg, err := s.config(ctx, orgID)
	if err != nil {
		return nil, err
	}
	worktree, err := s.syncCheckout(ctx, cfg)
	if err != nil {
		return nil, err
	}
	repo, err := gogit.PlainOpen(worktree)
	if err != nil {
		return nil, fmt.Errorf("wiki: open for history: %w", err)
	}
	iter, err := repo.Log(&gogit.LogOptions{
		PathFilter: func(p string) bool { return p == filepath.ToSlash(filepath.Join(cfg.Path, pagePath)) },
		Order:      gogit.LogOrderCommitterTime,
	})
	if err != nil {
		return nil, fmt.Errorf("wiki: history: %w", err)
	}
	defer iter.Close()
	var out []Commit
	_ = iter.ForEach(func(c *object.Commit) error {
		out = append(out, Commit{
			Hash:      c.Hash.String(),
			Message:   c.Message,
			Author:    c.Author.Name,
			AuthorAt:  c.Author.When.Format(time.RFC3339),
			Committer: c.Committer.Name,
			When:      c.Committer.When.Format(time.RFC3339),
		})
		return nil
	})
	if out == nil {
		out = []Commit{}
	}
	return out, nil
}

// ReadPageRevision renders one page at a specific commit hash. rev may be a
// full hash or a short prefix; "" renders the current head.
func (s *Store) ReadPageRevision(ctx context.Context, orgID, pagePath, rev string) (Page, error) {
	cfg, err := s.config(ctx, orgID)
	if err != nil {
		return Page{}, err
	}
	worktree, err := s.syncCheckout(ctx, cfg)
	if err != nil {
		return Page{}, err
	}
	repo, err := gogit.PlainOpen(worktree)
	if err != nil {
		return Page{}, fmt.Errorf("wiki: open for revision: %w", err)
	}
	var hash plumbing.Hash
	if rev == "" {
		ref, err := repo.Reference(plumbing.HEAD, true)
		if err != nil {
			return Page{}, fmt.Errorf("wiki: head: %w", err)
		}
		hash = ref.Hash()
	} else {
		hash = plumbing.NewHash(rev)
	}
	commit, err := repo.CommitObject(hash)
	if err != nil {
		return Page{}, fmt.Errorf("wiki: commit %s: %w", rev, err)
	}
	f, err := commit.File(filepath.ToSlash(filepath.Join(cfg.Path, pagePath)))
	if err != nil {
		return Page{}, fmt.Errorf("wiki: page %s not in revision: %w", pagePath, err)
	}
	md, err := f.Contents()
	if err != nil {
		return Page{}, fmt.Errorf("wiki: read revision: %w", err)
	}
	html, err := Render([]byte(md), RenderOptions{})
	if err != nil {
		return Page{}, fmt.Errorf("wiki: render revision: %w", err)
	}
	return Page{
		Path:     filepath.ToSlash(filepath.Join(cfg.Path, pagePath)),
		Name:     strings.TrimSuffix(filepath.Base(pagePath), ".md"),
		Markdown: md,
		HTML:     string(html),
	}, nil
}

// writeFileUnder writes a page file inside the wiki sub-path, confining the
// target so a malicious path cannot escape worktree.
func writeFileUnder(worktree, wikiPath, pagePath, content string) error {
	target := filepath.Join(worktree, wikiPath, pagePath)
	// Confine: target must stay under worktree/wikiPath.
	root := filepath.Join(worktree, wikiPath)
	abs := filepath.Join("/", target)
	absRoot := filepath.Join("/", root)
	if !strings.HasPrefix(abs, absRoot+"/") && abs != absRoot {
		return fmt.Errorf("page path escapes wiki path")
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	return os.WriteFile(target, []byte(content), 0o600)
}
