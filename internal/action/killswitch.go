package action

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
)

// handleAgentKillAll is the kill-switch (WU-311): the org owner disables every
// agent in the org instantly (active=0). Gated by the `agent.kill` permission,
// which is granted only to the org-owner role (seeded at org creation).
// Returns the org id and a confirmation.
func handleAgentKillAll(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	// Input is optional and ignored; the org is taken from the dispatch scope.
	if err := ac.Tx.DeactivateAllAgentsByOrg(ctx, sql.NullString{String: ac.Org, Valid: ac.Org != ""}); err != nil {
		return nil, fmt.Errorf("agent.kill-all: %w", err)
	}
	return map[string]any{
		"org_id":   ac.Org,
		"disabled": true,
		"message":  "all agents disabled",
	}, nil
}

func init() {
	Register(Definition{
		Name:       "agent.kill-all",
		Impact:     ImpactHigh,
		Permission: "agent.kill",
		Scope:      ScopeOrg,
		Input:      nil,
		Handle:     handleAgentKillAll,
	})
}
