package action

import (
	"context"
	"encoding/json"
	"errors"
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

// wikiEditInput is the input for wiki.edit (save/commit a page).
type wikiEditInput struct {
	OrgID    string `json:"org_id"`
	Path     string `json:"path"`
	Markdown string `json:"markdown"`
	Message  string `json:"message,omitempty"`
}

// wikiRenameInput is the input for wiki.rename.
type wikiRenameInput struct {
	OrgID   string `json:"org_id"`
	Path    string `json:"path"`
	NewPath string `json:"new_path"`
	Message string `json:"message,omitempty"`
}

// wikiDeleteInput is the input for wiki.delete.
type wikiDeleteInput struct {
	OrgID   string `json:"org_id"`
	Path    string `json:"path"`
	Message string `json:"message,omitempty"`
}

// wikiHistoryInput is the input for wiki.history.
type wikiHistoryInput struct {
	OrgID string `json:"org_id"`
	Path  string `json:"path"`
}

// wikiReadRevisionInput is the input for wiki.read_revision.
type wikiReadRevisionInput struct {
	OrgID string `json:"org_id"`
	Path  string `json:"path"`
	Rev   string `json:"rev,omitempty"`
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
	Register(Definition{
		Name:       "wiki.edit",
		Impact:     ImpactLow,
		Permission: "wiki.edit",
		Scope:      ScopeOrg,
		Input:      ObjectSchema{Fields: []Field{{Name: "org_id", Kind: KindString, Required: true}, {Name: "path", Kind: KindString, Required: true}, {Name: "markdown", Kind: KindString, Required: true}, {Name: "message", Kind: KindString, Required: false}}},
		Handle:     handleWikiEdit,
	})
	Register(Definition{
		Name:       "wiki.rename",
		Impact:     ImpactLow,
		Permission: "wiki.edit",
		Scope:      ScopeOrg,
		Input:      ObjectSchema{Fields: []Field{{Name: "org_id", Kind: KindString, Required: true}, {Name: "path", Kind: KindString, Required: true}, {Name: "new_path", Kind: KindString, Required: true}, {Name: "message", Kind: KindString, Required: false}}},
		Handle:     handleWikiRename,
	})
	Register(Definition{
		Name:       "wiki.delete",
		Impact:     ImpactLow,
		Permission: "wiki.edit",
		Scope:      ScopeOrg,
		Input:      ObjectSchema{Fields: []Field{{Name: "org_id", Kind: KindString, Required: true}, {Name: "path", Kind: KindString, Required: true}, {Name: "message", Kind: KindString, Required: false}}},
		Handle:     handleWikiDelete,
	})
	Register(Definition{
		Name:       "wiki.history",
		Impact:     ImpactRead,
		Permission: "wiki.read",
		Scope:      ScopeOrg,
		Input:      ObjectSchema{Fields: []Field{{Name: "org_id", Kind: KindString, Required: true}, {Name: "path", Kind: KindString, Required: true}}},
		Handle:     handleWikiHistory,
	})
	Register(Definition{
		Name:       "wiki.read_revision",
		Impact:     ImpactRead,
		Permission: "wiki.read",
		Scope:      ScopeOrg,
		Input:      ObjectSchema{Fields: []Field{{Name: "org_id", Kind: KindString, Required: true}, {Name: "path", Kind: KindString, Required: true}, {Name: "rev", Kind: KindString, Required: false}}},
		Handle:     handleWikiReadRevision,
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

// handleWikiEdit saves + commits a page as the linked GitHub user.
func handleWikiEdit(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input wikiEditInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("wiki.edit: %w", err)
	}
	if input.Path == "" {
		return nil, fmt.Errorf("wiki.edit: path required")
	}
	if wikiStore == nil {
		return nil, fmt.Errorf("wiki.edit: wiki store not configured")
	}
	err := wikiStore.WritePage(ctx, input.OrgID, input.Path, input.Markdown, input.Message, ac.Actor.ID)
	if errors.Is(err, wiki.ErrNotConnected) {
		return nil, fmt.Errorf("wiki.edit: %w", err)
	}
	if err != nil {
		return nil, fmt.Errorf("wiki.edit: %w", err)
	}
	return map[string]string{"path": input.Path, "saved": "true"}, nil
}

// handleWikiRename renames a page (git mv + commit).
func handleWikiRename(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input wikiRenameInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("wiki.rename: %w", err)
	}
	if input.Path == "" || input.NewPath == "" {
		return nil, fmt.Errorf("wiki.rename: path and new_path required")
	}
	if wikiStore == nil {
		return nil, fmt.Errorf("wiki.rename: wiki store not configured")
	}
	err := wikiStore.RenamePage(ctx, input.OrgID, input.Path, input.NewPath, input.Message, ac.Actor.ID)
	if err != nil {
		return nil, fmt.Errorf("wiki.rename: %w", err)
	}
	return map[string]string{"path": input.NewPath, "renamed": "true"}, nil
}

// handleWikiDelete deletes a page (git rm + commit).
func handleWikiDelete(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input wikiDeleteInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("wiki.delete: %w", err)
	}
	if input.Path == "" {
		return nil, fmt.Errorf("wiki.delete: path required")
	}
	if wikiStore == nil {
		return nil, fmt.Errorf("wiki.delete: wiki store not configured")
	}
	err := wikiStore.DeletePage(ctx, input.OrgID, input.Path, input.Message, ac.Actor.ID)
	if err != nil {
		return nil, fmt.Errorf("wiki.delete: %w", err)
	}
	return map[string]string{"path": input.Path, "deleted": "true"}, nil
}

// handleWikiHistory returns the commit log for a page.
func handleWikiHistory(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input wikiHistoryInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("wiki.history: %w", err)
	}
	if input.Path == "" {
		return nil, fmt.Errorf("wiki.history: path required")
	}
	if wikiStore == nil {
		return nil, fmt.Errorf("wiki.history: wiki store not configured")
	}
	commits, err := wikiStore.History(ctx, input.OrgID, input.Path)
	if err != nil {
		return nil, fmt.Errorf("wiki.history: %w", err)
	}
	if commits == nil {
		commits = []wiki.Commit{}
	}
	return commits, nil
}

// handleWikiReadRevision renders a page at a specific commit.
func handleWikiReadRevision(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input wikiReadRevisionInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("wiki.read_revision: %w", err)
	}
	if input.Path == "" {
		return nil, fmt.Errorf("wiki.read_revision: path required")
	}
	if wikiStore == nil {
		return nil, fmt.Errorf("wiki.read_revision: wiki store not configured")
	}
	page, err := wikiStore.ReadPageRevision(ctx, input.OrgID, input.Path, input.Rev)
	if err != nil {
		return nil, fmt.Errorf("wiki.read_revision: %w", err)
	}
	return page, nil
}
