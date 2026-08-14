package wiki

import (
	"context"
	"errors"
)

// IndexPages explicitly (re)builds the wiki_fts index for an org by walking
// its checkout. It is called automatically after clone/refresh (see
// syncCheckout / indexCheckout); this public method lets callers reindex on
// demand (e.g. after a config change or an out-of-band edit). A missing wiki
// config is a no-op.
func (s *Store) IndexPages(ctx context.Context, orgID string) error {
	cfg, err := s.config(ctx, orgID)
	if err != nil {
		if errors.Is(err, ErrNoConfig) {
			return nil
		}
		return err
	}
	worktree, err := s.syncCheckout(ctx, cfg)
	if err != nil {
		return err
	}
	return s.indexCheckout(ctx, cfg, worktree)
}
