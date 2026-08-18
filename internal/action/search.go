package action

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/thomasteoh/boardchestrator/internal/search"
)

type searchQueryInput struct {
	Query     string `json:"query"`
	ProjectID string `json:"project_id,omitempty"`
}

type searchQueryOutput struct {
	Results []search.QueryResult `json:"results"`
}

func init() {
	Register(Definition{
		Name:       "search.query",
		Impact:     ImpactRead,
		Permission: "search",
		Scope:      ScopeProject,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleSearchQuery,
	})
}

func handleSearchQuery(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input searchQueryInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("search.query: %w", err)
	}

	results, err := search.Query(ctx, ac.DB, input.Query, ac.Actor.ID, 50)
	if err != nil {
		return nil, fmt.Errorf("search.query: %w", err)
	}

	// Scoping is enforced inside search.Query (org membership for tasks,
	// comments, and wiki pages — WU-520), so no caller-side filter is needed.
	// A FilterByVisibility pass here would additionally drop wiki hits (they
	// carry no project_id), masking the wiki results from the action path.
	return searchQueryOutput{Results: results}, nil
}
