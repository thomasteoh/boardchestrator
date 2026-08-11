package action

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// pricingInput is the input to pricing.upsert.
type pricingInput struct {
	ProviderID    string  `json:"provider_id"`
	Model         string  `json:"model"`
	InputPerMTok  float64 `json:"input_per_mtok"`
	OutputPerMTok float64 `json:"output_per_mtok"`
}

// handlePricingUpsert creates/updates a platform pricing row for a provider+model
// (WU-310, editable by platform admin). Returns the pricing row.
func handlePricingUpsert(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input pricingInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("pricing.upsert: bad input: %w", err)
	}
	if input.ProviderID == "" || input.Model == "" {
		return nil, fmt.Errorf("pricing.upsert: provider_id and model are required")
	}
	p, err := ac.Tx.UpsertModelPricing(ctx, sqlc.UpsertModelPricingParams{
		ID:            newID(),
		ProviderID:    input.ProviderID,
		Model:         input.Model,
		InputPerMtok:  input.InputPerMTok,
		OutputPerMtok: input.OutputPerMTok,
	})
	if err != nil {
		return nil, fmt.Errorf("pricing.upsert: %w", err)
	}
	return p, nil
}

// handlePricingDelete removes a platform pricing row (WU-310).
func handlePricingDelete(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input struct {
		ProviderID string `json:"provider_id"`
		Model      string `json:"model"`
	}
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("pricing.delete: bad input: %w", err)
	}
	if err := ac.Tx.DeleteModelPricing(ctx, sqlc.DeleteModelPricingParams{
		ProviderID: input.ProviderID,
		Model:      input.Model,
	}); err != nil {
		return nil, fmt.Errorf("pricing.delete: %w", err)
	}
	return map[string]string{"provider_id": input.ProviderID, "model": input.Model}, nil
}

// handlePricingList lists all platform pricing rows (WU-310 admin view).
func handlePricingList(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	pricing, err := ac.Tx.ListModelPricing(ctx)
	if err != nil {
		return nil, fmt.Errorf("pricing.list: %w", err)
	}
	return pricing, nil
}

// orgCapInput is the input to org.cap.set.
type orgCapInput struct {
	MonthlyCapUSD float64 `json:"monthly_cap_usd"`
	CapAlertPct   float64 `json:"cap_alert_pct,omitempty"`
}

// handleOrgCapSet sets the org's monthly spend cap + threshold alert % (WU-310).
// monthly_cap_usd 0 = unlimited; cap_alert_pct 0 disables the alert.
func handleOrgCapSet(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input orgCapInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("org.cap.set: bad input: %w", err)
	}
	org, err := ac.Tx.UpdateOrgCap(ctx, sqlc.UpdateOrgCapParams{
		MonthlyCapUsd: input.MonthlyCapUSD,
		CapAlertPct:   input.CapAlertPct,
		ID:            ac.Org,
	})
	if err != nil {
		return nil, fmt.Errorf("org.cap.set: %w", err)
	}
	return org, nil
}

// usageInput is the input to usage.read.
type usageInput struct {
	Month string `json:"month,omitempty"` // RFC3339 start-of-month; defaults to current UTC month
}

// handleUsageRead returns the org's usage summary for a month (WU-310): total
// spend + tokens + per-agent + per-project rows (dashboard aggregation).
func handleUsageRead(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input usageInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("usage.read: bad input: %w", err)
	}
	start := monthStart(input.Month)
	org, err := ac.Tx.FindOrgByID(ctx, ac.Org)
	if err != nil {
		return nil, fmt.Errorf("usage.read: find org: %w", err)
	}
	totalUSD, err := ac.Tx.OrgMonthlySpend(ctx, sqlc.OrgMonthlySpendParams{OrgID: ac.Org, FinishedAt: sql.NullString{String: start, Valid: true}})
	if err != nil {
		return nil, fmt.Errorf("usage.read: spend: %w", err)
	}
	tokens, err := ac.Tx.OrgMonthlyTokens(ctx, sqlc.OrgMonthlyTokensParams{OrgID: ac.Org, FinishedAt: sql.NullString{String: start, Valid: true}})
	if err != nil {
		return nil, fmt.Errorf("usage.read: tokens: %w", err)
	}
	byAgent, err := ac.Tx.AgentUsageByMonth(ctx, sqlc.AgentUsageByMonthParams{OrgID: ac.Org, FinishedAt: sql.NullString{String: start, Valid: true}})
	if err != nil {
		return nil, fmt.Errorf("usage.read: by agent: %w", err)
	}
	byProject, err := ac.Tx.ProjectUsageByMonth(ctx, sqlc.ProjectUsageByMonthParams{OrgID: ac.Org, FinishedAt: sql.NullString{String: start, Valid: true}})
	if err != nil {
		return nil, fmt.Errorf("usage.read: by project: %w", err)
	}
	return map[string]any{
		"org_id":          ac.Org,
		"month":           start,
		"total_usd":       totalUSD,
		"total_tokens":    tokens,
		"monthly_cap_usd": org.MonthlyCapUsd,
		"by_agent":        byAgent,
		"by_project":      byProject,
	}, nil
}

// monthStart returns the UTC start of the month for the given RFC3339 start
// (or the current UTC month if empty).
func monthStart(s string) string {
	now := time.Now().UTC()
	if s != "" {
		if t, err := time.Parse("2006-01-02T15:04:05.000Z", s); err == nil {
			now = t
		}
	}
	return time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).Format("2006-01-02T15:04:05.000Z")
}

func init() {
	Register(Definition{
		Name:       "pricing.upsert",
		Impact:     ImpactHigh,
		Permission: "pricing.upsert",
		Scope:      ScopePlatform,
		Input: ObjectSchema{Fields: []Field{
			{Name: "provider_id", Kind: KindString, Required: true},
			{Name: "model", Kind: KindString, Required: true},
			{Name: "input_per_mtok", Kind: KindNumber, Required: true},
			{Name: "output_per_mtok", Kind: KindNumber, Required: true},
		}},
		Handle: handlePricingUpsert,
	})
	Register(Definition{
		Name:       "pricing.delete",
		Impact:     ImpactHigh,
		Permission: "pricing.delete",
		Scope:      ScopePlatform,
		Input: ObjectSchema{Fields: []Field{
			{Name: "provider_id", Kind: KindString, Required: true},
			{Name: "model", Kind: KindString, Required: true},
		}},
		Handle: handlePricingDelete,
	})
	Register(Definition{
		Name:       "pricing.list",
		Impact:     ImpactRead,
		Permission: "pricing.list",
		Scope:      ScopePlatform,
		Input:      nil,
		Handle:     handlePricingList,
	})
	Register(Definition{
		Name:       "org.cap.set",
		Impact:     ImpactHigh,
		Permission: "org.cap.set",
		Scope:      ScopeOrg,
		Input: ObjectSchema{Fields: []Field{
			{Name: "monthly_cap_usd", Kind: KindNumber, Required: true},
			{Name: "cap_alert_pct", Kind: KindNumber, Required: false},
		}},
		Handle: handleOrgCapSet,
	})
	Register(Definition{
		Name:       "usage.read",
		Impact:     ImpactRead,
		Permission: "usage.read",
		Scope:      ScopeOrg,
		Input: ObjectSchema{Fields: []Field{
			{Name: "month", Kind: KindString, Required: false},
		}},
		Handle: handleUsageRead,
	})
}
