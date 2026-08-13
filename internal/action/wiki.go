package action

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/thomasteoh/boardchestrator/internal/wiki"
)

// wikiStore is the wiki backend, set via SetWikiStore before dispatch
// (pattern: attachmentStore). Handlers delegate to it for read/tree; config
// actions call SetConfig (read-modify-write of the config row).
var wikiStore *wiki.Store

// SetWikiStore sets the wiki backend for the action handlers.
func SetWikiStore(s *wiki.Store) { wikiStore = s }

// wikiConfigRepoInput is the input for wiki.config.repo (org owner: set repo).
type wikiConfigRepoInput struct {
	OrgID string `json:"org_id"`
	Repo  string `json:"repo"`
}

// wikiConfigRefInput is the input for wiki.config.ref (team admin: set ref/path).
type wikiConfigRefInput struct {
	OrgID string `json:"org_id"`
	Ref   string `json:"ref,omitempty"`
	Path  string `json:"path,omitempty"`
}

// wikiReadInput is the input for wiki.read.
type wikiReadInput struct {
	OrgID string `json:"org_id"`
	Path  string `json:"path"`
}

// wikiTreeInput is the input for wiki.tree.
type wikiTreeInput struct {
	OrgID string `json:"org_id"`
}

func init() {
	Register(Definition{
		Name:       "wiki.config.repo",
		Impact:     ImpactLow,
		Permission: "wiki.config.repo",
		Scope:      ScopeOrg,
		Input:      ObjectSchema{Fields: []Field{{Name: "org_id", Kind: KindString, Required: true}, {Name: "repo", Kind: KindString, Required: true}}},
		Handle:     handleWikiConfigRepo,
	})
	Register(Definition{
		Name:       "wiki.config.ref",
		Impact:     ImpactLow,
		Permission: "wiki.config.ref",
		Scope:      ScopeOrg,
		Input:      ObjectSchema{Fields: []Field{{Name: "org_id", Kind: KindString, Required: true}, {Name: "ref", Kind: KindString, Required: false}, {Name: "path", Kind: KindString, Required: false}}},
		Handle:     handleWikiConfigRef,
	})
	Register(Definition{
		Name:       "wiki.read",
		Impact:     ImpactRead,
		Permission: "wiki.read",
		Scope:      ScopeOrg,
		Input:      ObjectSchema{Fields: []Field{{Name: "org_id", Kind: KindString, Required: true}, {Name: "path", Kind: KindString, Required: true}}},
		Handle:     handleWikiRead,
	})
	Register(Definition{
		Name:       "wiki.tree",
		Impact:     ImpactRead,
		Permission: "wiki.read",
		Scope:      ScopeOrg,
		Input:      ObjectSchema{Fields: []Field{{Name: "org_id", Kind: KindString, Required: true}}},
		Handle:     handleWikiTree,
	})
}

// handleWikiConfigRepo sets the wiki repo URL (org owner). Read-modify-write:
// preserves current ref/path so setting repo doesn't clobber team-admin fields.
func handleWikiConfigRepo(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input wikiConfigRepoInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("wiki.config.repo: %w", err)
	}
	if input.Repo == "" {
		return nil, fmt.Errorf("wiki.config.repo: repo required")
	}
	if wikiStore == nil {
		return nil, fmt.Errorf("wiki.config.repo: wiki store not configured")
	}
	cfg, err := wikiStore.SetConfig(ctx, input.OrgID, input.Repo, "", "")
	if err != nil {
		return nil, fmt.Errorf("wiki.config.repo: %w", err)
	}
	return map[string]string{"org_id": cfg.OrgID, "repo": cfg.Repo, "ref": cfg.Ref, "path": cfg.Path}, nil
}

// handleWikiConfigRef sets the wiki ref/path (team admin). Read-modify-write:
// preserves repo; only supplied fields are changed.
func handleWikiConfigRef(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input wikiConfigRefInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("wiki.config.ref: %w", err)
	}
	if wikiStore == nil {
		return nil, fmt.Errorf("wiki.config.ref: wiki store not configured")
	}
	cfg, err := wikiStore.SetConfig(ctx, input.OrgID, "", input.Ref, input.Path)
	if err != nil {
		return nil, fmt.Errorf("wiki.config.ref: %w", err)
	}
	return map[string]string{"org_id": cfg.OrgID, "repo": cfg.Repo, "ref": cfg.Ref, "path": cfg.Path}, nil
}

// handleWikiRead renders a wiki page.
func handleWikiRead(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input wikiReadInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("wiki.read: %w", err)
	}
	if wikiStore == nil {
		return nil, fmt.Errorf("wiki.read: wiki store not configured")
	}
	page, err := wikiStore.ReadPage(ctx, input.OrgID, input.Path)
	if err != nil {
		return nil, fmt.Errorf("wiki.read: %w", err)
	}
	return page, nil
}

// handleWikiTree lists the page tree (nav).
func handleWikiTree(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input wikiTreeInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("wiki.tree: %w", err)
	}
	if wikiStore == nil {
		return nil, fmt.Errorf("wiki.tree: wiki store not configured")
	}
	pages, err := wikiStore.PageTree(ctx, input.OrgID)
	if err != nil {
		return nil, fmt.Errorf("wiki.tree: %w", err)
	}
	if pages == nil {
		pages = []wiki.Page{}
	}
	return pages, nil
}
