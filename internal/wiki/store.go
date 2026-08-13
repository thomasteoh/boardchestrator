package wiki

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"

	wikidb "github.com/thomasteoh/boardchestrator/internal/db/sqlc/wiki"
)

// plainClone is the default cloneFunc: a shallow (depth-1) clone at `ref`.
// Used by production; tests inject a local fixture clone via WithCloneFunc.
func plainClone(ctx context.Context, url, ref, worktree string, shallow bool) error {
	depth := 0
	if shallow {
		depth = 1
	}
	_, err := gogit.PlainCloneContext(ctx, worktree, false, &gogit.CloneOptions{
		URL:          url,
		Depth:        depth,
		ReferenceName: plumbing.ReferenceName("refs/heads/" + ref),
		SingleBranch: true,
	})
	return err
}

// config loads the org's wiki Config (repo required).
func (s *Store) config(ctx context.Context, orgID string) (Config, error) {
	return loadConfig(ctx, wikidb.New(s.db), orgID)
}

// syncCheckout ensures the org's wiki checkout is present and fresh: clones if
// the cache dir is missing, otherwise refreshes when stale (TTL) or on a
// different ref. Returns the worktree path.
func (s *Store) syncCheckout(ctx context.Context, cfg Config) (string, error) {
	key := cacheKey(cfg.Repo, cfg.Ref)
	worktree := filepath.Join(s.baseDir, key)
	stamp := filepath.Join(worktree, ".bc-wiki-ref")

	// No checkout yet → clone.
	if _, err := os.Stat(worktree); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("wiki: stat cache: %w", err)
		}
		if err := os.MkdirAll(filepath.Dir(worktree), 0o755); err != nil {
			return "", fmt.Errorf("wiki: mkdir cache: %w", err)
		}
		if err := s.clone(ctx, cfg.Repo, cfg.Ref, worktree, true); err != nil {
			return "", fmt.Errorf("wiki: clone %s: %w", cfg.Repo, err)
		}
		if err := os.WriteFile(stamp, []byte(cfg.Ref), 0o644); err != nil {
			return "", fmt.Errorf("wiki: stamp: %w", err)
		}
		return worktree, nil
	}

	// Existing checkout → refresh if stale or ref changed.
	stale := s.refreshNeeded(worktree, stamp, cfg.Ref)
	if stale {
		if err := s.clone(ctx, cfg.Repo, cfg.Ref, worktree, true); err != nil {
			return "", fmt.Errorf("wiki: refresh %s: %w", cfg.Repo, err)
		}
		if err := os.WriteFile(stamp, []byte(cfg.Ref), 0o644); err != nil {
			return "", fmt.Errorf("wiki: re-stamp: %w", err)
		}
	}
	return worktree, nil
}

// refreshNeeded reports whether a checkout is stale: the stamp ref differs or
// the checkout is older than the TTL.
func (s *Store) refreshNeeded(worktree, stamp, ref string) bool {
	if b, err := os.ReadFile(stamp); err == nil && string(b) == ref {
		info, err := os.Stat(worktree)
		if err == nil {
			return s.now().Sub(info.ModTime()) > s.checkoutTTL
		}
	}
	return true
}

// cacheKey derives a safe, deterministic cache subdir from repo + ref.
func cacheKey(repo, ref string) string {
	h := sha256.Sum256([]byte(repo + "\x00" + ref))
	return hex.EncodeToString(h[:8])
}

// confined reports whether pagePath (relative to the wiki root) stays within
// the configured wiki sub-path. A page outside the wiki root is rejected.
func confined(root, pagePath string) bool {
	if strings.Contains(pagePath, "..") {
		return false
	}
	if strings.HasPrefix(pagePath, "/") {
		return false
	}
	abs := filepath.Join("/", root, pagePath)
	return filepath.Join("/", root) == filepath.Dir(abs) || strings.HasPrefix(abs, filepath.Join("/", root)+"/")
}

// listPages walks the wiki path for *.md files and returns their Page shells
// (name + path), newest-first by mtime.
func listPages(cfg Config, worktree string) ([]Page, error) {
	root := filepath.Join(worktree, cfg.Path)
	var pages []Page
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(p, ".md") {
			return nil
		}
		rel, _ := filepath.Rel(worktree, p)
		name := strings.TrimSuffix(filepath.Base(p), ".md")
		pages = append(pages, Page{Path: rel, Name: name})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("wiki: walk %s: %w", root, err)
	}
	sort.Slice(pages, func(i, j int) bool {
		// newest-first by mtime
		mi, _ := os.Stat(filepath.Join(worktree, pages[i].Path))
		mj, _ := os.Stat(filepath.Join(worktree, pages[j].Path))
		ti, tj := int64(0), int64(0)
		if mi != nil {
			ti = mi.ModTime().UnixNano()
		}
		if mj != nil {
			tj = mj.ModTime().UnixNano()
		}
		return ti > tj
	})
	return pages, nil
}

// readPage reads + renders one page under the wiki path.
func readPage(cfg Config, worktree, pagePath string) (Page, error) {
	full := filepath.Join(worktree, cfg.Path, pagePath)
	b, err := os.ReadFile(full)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Page{}, fmt.Errorf("wiki: page %s not found", pagePath)
		}
		return Page{}, fmt.Errorf("wiki: read %s: %w", pagePath, err)
	}
	rel, _ := filepath.Rel(worktree, full)
	name := strings.TrimSuffix(filepath.Base(full), ".md")
	html, err := Render(b, RenderOptions{})
	if err != nil {
		return Page{}, fmt.Errorf("wiki: render %s: %w", pagePath, err)
	}
	return Page{Path: rel, Name: name, Markdown: string(b), HTML: string(html)}, nil
}
