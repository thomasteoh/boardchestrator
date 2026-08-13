// Package wiki implements the org wiki: a connected git repository that the
// team uses as a shared knowledge base. WU-501 covers read + render — clone
// cache, refresh policy, page tree, and markdown rendering with mermaid +
// sanitized SVG + KEY-n autolinks. WU-502 adds editing/history on top.
package wiki

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	wikidb "github.com/thomasteoh/boardchestrator/internal/db/sqlc/wiki"
)

// Config is an org's wiki configuration.
type Config struct {
	OrgID     string `json:"org_id"`
	Repo      string `json:"repo"` // git URL (https), set by org owner
	Ref       string `json:"ref"`  // branch/tag/commit, set by team admin
	Path      string `json:"path"` // subdirectory within the repo, set by team admin
	CreatedAt string `json:"created_at,omitempty"` // preserved on update
}

// ErrNoConfig is returned when an org has no wiki configured.
var ErrNoConfig = errors.New("wiki: no wiki configured for org")

// loadConfig reads an org's wiki config. A missing row returns ErrNoConfig.
func loadConfig(ctx context.Context, q *wikidb.Queries, orgID string) (Config, error) {
	cfg, err := q.FindWikiConfig(ctx, orgID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Config{}, ErrNoConfig
		}
		return Config{}, fmt.Errorf("wiki: load config: %w", err)
	}
	if cfg.Repo == "" {
		return Config{}, ErrNoConfig
	}
	c := Config{OrgID: cfg.OrgID, Repo: cfg.Repo, Ref: cfg.Ref, Path: cfg.Path, CreatedAt: cfg.CreatedAt}
	if c.Ref == "" {
		c.Ref = "main"
	}
	return c, nil
}

// Store clones + serves org wikis. checkoutTTL controls the refresh policy:
// a checkout older than the TTL (or on a different ref) is refreshed.
type Store struct {
	db        *sql.DB
	baseDir   string // cache root for clones
	checkoutTTL time.Duration
	clone     cloneFunc
	now       func() time.Time
}

// cloneFunc is the clone/refresh primitive, injected for tests (local fixture
// repos) so Store tests never touch the network.
type cloneFunc func(ctx context.Context, url, ref, worktree string, shallow bool) error

// NewStore builds a wiki Store rooted at baseDir.
func NewStore(db *sql.DB, baseDir string, opts ...Option) *Store {
	s := &Store{
		db:         db,
		baseDir:    baseDir,
		checkoutTTL: 5 * time.Minute,
		clone:      plainClone,
		now:        time.Now,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Option configures a Store.
type Option func(*Store)

// WithCloneFunc overrides the clone primitive (tests).
func WithCloneFunc(f cloneFunc) Option { return func(s *Store) { s.clone = f } }

// WithCheckoutTTL overrides the refresh TTL.
func WithCheckoutTTL(d time.Duration) Option { return func(s *Store) { s.checkoutTTL = d } }

// WithNow overrides the clock (tests).
func WithNow(f func() time.Time) Option { return func(s *Store) { s.now = f } }

// Page is one wiki page (markdown file under the configured path).
type Page struct {
	Path     string `json:"path"`     // repo-relative path, e.g. docs/guides/onboarding.md
	Name     string `json:"name"`     // display name (filename sans .md)
	Markdown string `json:"markdown"` // raw markdown
	HTML     string `json:"html"`     // rendered + sanitized HTML
}

// Checkout returns the worktree path for the org's wiki, refreshing it if the
// cache is stale or the ref changed. Returns "" + error when no wiki is set.
func (s *Store) Checkout(ctx context.Context, orgID string) (string, error) {
	cfg, err := s.config(ctx, orgID)
	if err != nil {
		return "", err
	}
	return s.syncCheckout(ctx, cfg)
}

// SetConfig writes the org's wiki config (read-modify-write of the full row:
// repo set by org owner, ref/path by team admin). created_at is preserved on
// update; updated_at bumps to now. Returns the resulting Config.
func (s *Store) SetConfig(ctx context.Context, orgID, repo, ref, path string) (Config, error) {
	q := wikidb.New(s.db)
	cur, err := loadConfig(ctx, q, orgID)
	if errors.Is(err, ErrNoConfig) {
		cur = Config{}
	} else if err != nil {
		return Config{}, err
	}
	if ref == "" {
		ref = cur.Ref
	}
	if ref == "" {
		ref = "main"
	}
	if path == "" {
		path = cur.Path
	}
	if repo == "" {
		repo = cur.Repo
	}
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	if err := q.UpsertWikiConfig(ctx, wikidb.UpsertWikiConfigParams{
		OrgID:     orgID,
		Repo:      repo,
		Ref:       ref,
		Path:      path,
		CreatedAt: cur.CreatedAt,
		UpdatedAt: now,
	}); err != nil {
		return Config{}, fmt.Errorf("wiki: set config: %w", err)
	}
	cfg, err := loadConfig(ctx, q, orgID)
	if err != nil {
		return Config{}, fmt.Errorf("wiki: re-read config: %w", err)
	}
	return cfg, nil
}

// PageTree lists markdown pages under the wiki path (tree nav), newest-first.
func (s *Store) PageTree(ctx context.Context, orgID string) ([]Page, error) {
	cfg, err := s.config(ctx, orgID)
	if err != nil {
		return nil, err
	}
	worktree, err := s.syncCheckout(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return listPages(cfg, worktree)
}

// ReadPage renders one wiki page. pagePath is relative to the wiki path and
// must stay within it (traversal is rejected).
func (s *Store) ReadPage(ctx context.Context, orgID, pagePath string) (Page, error) {
	cfg, err := s.config(ctx, orgID)
	if err != nil {
		return Page{}, err
	}
	if !confined(cfg.Path, pagePath) {
		return Page{}, fmt.Errorf("wiki: page path %q escapes the wiki path %q", pagePath, cfg.Path)
	}
	worktree, err := s.syncCheckout(ctx, cfg)
	if err != nil {
		return Page{}, err
	}
	return readPage(cfg, worktree, pagePath)
}
