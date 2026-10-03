package action

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

type auditListInput struct {
	OrgID   string `json:"org_id"`
	ActorID string `json:"actor_id,omitempty"`
	Action  string `json:"action,omitempty"`
	Since   string `json:"since,omitempty"`
	Until   string `json:"until,omitempty"`
	Limit   int    `json:"limit,omitempty"`
	Offset  int    `json:"offset,omitempty"`
}

type auditExportInput struct {
	OrgID   string `json:"org_id"`
	ActorID string `json:"actor_id,omitempty"`
	Action  string `json:"action,omitempty"`
	Since   string `json:"since,omitempty"`
	Until   string `json:"until,omitempty"`
}

func init() {
	Register(Definition{
		Name:       "audit.log.list",
		Impact:     ImpactRead,
		Permission: "audit.log.list",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleAuditList,
	})
	Register(Definition{
		Name:       "audit.platform.list",
		Impact:     ImpactRead,
		Permission: "platform.audit",
		Scope:      ScopePlatform,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleAuditPlatformList,
	})
	Register(Definition{
		Name:       "audit.log.export",
		Impact:     ImpactRead,
		Permission: "audit.log.export",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleAuditExport,
	})
}

func handleAuditList(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input auditListInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("audit.log.list: %w", err)
	}

	limit := int64(input.Limit)
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	// Always the dispatch-verified org: input.org_id is not trusted (a caller
	// permitted in one org must not read another's log).
	org := sql.NullString{String: ac.Org, Valid: ac.Org != ""}

	if input.ActorID == "" && input.Action == "" && input.Since == "" && input.Until == "" {
		rows, err := ac.Tx.ListAuditLogsByOrg(ctx, sqlc.ListAuditLogsByOrgParams{
			OrgID:  org,
			Limit:  limit,
			Offset: int64(input.Offset),
		})
		if err != nil {
			return nil, fmt.Errorf("audit.log.list: %w", err)
		}
		return rows, nil
	}

	rows, err := ac.Tx.ListAuditLogsByOrgFiltered(ctx, sqlc.ListAuditLogsByOrgFilteredParams{
		OrgID:       org,
		Column2:     input.ActorID,
		ActorID:     input.ActorID,
		Column4:     input.Action,
		Action:      input.Action,
		Column6:     input.Since,
		CreatedAt:   input.Since,
		Column8:     input.Until,
		CreatedAt_2: input.Until,
		Limit:       limit,
		Offset:      int64(input.Offset),
	})
	if err != nil {
		return nil, fmt.Errorf("audit.log.list: %w", err)
	}
	return rows, nil
}

func handleAuditExport(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input auditExportInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("audit.log.export: %w", err)
	}

	// Always the dispatch-verified org: input.org_id is not trusted (a caller
	// permitted in one org must not read another's log).
	org := sql.NullString{String: ac.Org, Valid: ac.Org != ""}

	rows, err := ac.Tx.ListAuditLogsByOrgFiltered(ctx, sqlc.ListAuditLogsByOrgFilteredParams{
		OrgID:       org,
		Column2:     input.ActorID,
		ActorID:     input.ActorID,
		Column4:     input.Action,
		Action:      input.Action,
		Column6:     input.Since,
		CreatedAt:   input.Since,
		Column8:     input.Until,
		CreatedAt_2: input.Until,
		Limit:       50000,
		Offset:      0,
	})
	if err != nil {
		return nil, fmt.Errorf("audit.log.export: %w", err)
	}
	return rows, nil
}

type auditPlatformListInput struct {
	Limit  int `json:"limit,omitempty"`
	Offset int `json:"offset,omitempty"`
}

// handleAuditPlatformList lists the platform audit rows (org_id NULL):
// sign-ins, sign-outs, failed sign-ins, bootstrap and platform admin
// actions (WU-605). Org rows stay in each org's own log.
func handleAuditPlatformList(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input auditPlatformListInput
	if len(in) > 0 {
		if err := json.Unmarshal(in, &input); err != nil {
			return nil, fmt.Errorf("%w: audit.platform.list: %v", ErrInvalidInput, err)
		}
	}
	limit := int64(input.Limit)
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := ac.Tx.ListAuditLogsPlatform(ctx, sqlc.ListAuditLogsPlatformParams{
		Limit: limit, Offset: int64(input.Offset),
	})
	if err != nil {
		return nil, fmt.Errorf("audit.platform.list: %w", err)
	}
	return rows, nil
}
