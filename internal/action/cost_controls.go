package action

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
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

// usageInput is the input to usage.read (WU-505): an arbitrary timeframe
// (from/to RFC3339, default current UTC month) and optional agent/project
// filters. csv=true returns RFC 4180 rows for the by-agent and by-project
// aggregates.
type usageInput struct {
	From      string `json:"from,omitempty"`
	To        string `json:"to,omitempty"`
	AgentID   string `json:"agent_id,omitempty"`
	ProjectID string `json:"project_id,omitempty"`
	Limit     int64  `json:"limit,omitempty"` // drill-down run rows (default 100)
	CSV       bool   `json:"csv,omitempty"`
}

// handleUsageRead returns the org's usage summary for a timeframe (WU-310 +
// WU-505): totals + per-agent + per-project rows (with action counts) and an
// optional drill-down run list.
func handleUsageRead(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input usageInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("usage.read: bad input: %w", err)
	}
	from, to := usageWindow(input.From, input.To)
	if from == "" || to == "" {
		return nil, fmt.Errorf("usage.read: bad timeframe")
	}
	if _, err := ac.Tx.FindOrgByID(ctx, ac.Org); err != nil {
		return nil, fmt.Errorf("usage.read: find org: %w", err)
	}
	fromN := sql.NullString{String: from, Valid: true}
	toN := sql.NullString{String: to, Valid: true}

	orgUsage, err := ac.Tx.OrgUsageInWindow(ctx, sqlc.OrgUsageInWindowParams{OrgID: ac.Org, FinishedAt: fromN, FinishedAt_2: toN})
	if err != nil {
		return nil, fmt.Errorf("usage.read: totals: %w", err)
	}
	byAgent, err := ac.Tx.AgentUsageInWindow(ctx, sqlc.AgentUsageInWindowParams{OrgID: ac.Org, FinishedAt: fromN, FinishedAt_2: toN})
	if err != nil {
		return nil, fmt.Errorf("usage.read: by agent: %w", err)
	}
	byProject, err := ac.Tx.ProjectUsageInWindow(ctx, sqlc.ProjectUsageInWindowParams{OrgID: ac.Org, FinishedAt: fromN, FinishedAt_2: toN})
	if err != nil {
		return nil, fmt.Errorf("usage.read: by project: %w", err)
	}

	// Optional drill-down run list filtered by agent/project.
	var runs []sqlc.Run
	if input.AgentID != "" || input.ProjectID != "" || input.Limit > 0 {
		limit := input.Limit
		if limit == 0 {
			limit = 100
		}
		agentF := input.AgentID
		projF := input.ProjectID
		runs, err = ac.Tx.ListRunsInWindow(ctx, sqlc.ListRunsInWindowParams{
			OrgID: ac.Org, FinishedAt: fromN, FinishedAt_2: toN,
			Column4: agentF, AgentID: agentF, Column6: projF,
			ProjectID: sql.NullString{String: projF, Valid: projF != ""}, Limit: limit,
		})
		if err != nil {
			return nil, fmt.Errorf("usage.read: runs: %w", err)
		}
	}

	if input.CSV {
		return map[string]any{
			"csv_agents":   csvUsageAgents(byAgent),
			"csv_projects": csvUsageProjects(byProject),
			"csv_runs":     csvUsageRuns(runs),
		}, nil
	}

	resp := map[string]any{
		"org_id":       ac.Org,
		"from":         from,
		"to":           to,
		"total_usd":    orgUsage.TotalUsd,
		"total_tokens": orgUsage.TotalTokens,
		"runs":         orgUsage.Runs,
		"actions":      orgUsage.Actions,
		"by_agent":     byAgent,
		"by_project":   byProject,
	}
	if len(runs) > 0 {
		resp["runs_list"] = runs
	}
	return resp, nil
}

// usageWindow returns the inclusive [from, to) UTC window, defaulting to the
// current UTC month when either bound is empty.
func usageWindow(from, to string) (string, string) {
	if from == "" && to == "" {
		m := monthStart("")
		return m, monthEnd(m)
	}
	// Both bounds must parse; fall back to month on failure.
	f, ferr := time.Parse("2006-01-02T15:04:05.000Z", from)
	t, terr := time.Parse("2006-01-02T15:04:05.000Z", to)
	if ferr != nil || terr != nil || !t.After(f) {
		m := monthStart("")
		return m, monthEnd(m)
	}
	return f.UTC().Format("2006-01-02T15:04:05.000Z"), t.UTC().Format("2006-01-02T15:04:05.000Z")
}

// monthEnd returns the UTC start of the month following m.
func monthEnd(m string) string {
	t, _ := time.Parse("2006-01-02T15:04:05.000Z", m)
	next := time.Date(t.Year(), t.Month()+1, 1, 0, 0, 0, 0, time.UTC)
	return next.Format("2006-01-02T15:04:05.000Z")
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

// csvQuote quotes a field per RFC 4180 when it contains a comma, quote, or
// newline, doubling embedded quotes.
func csvQuote(s string) string {
	if strings.ContainsAny(s, ",\"\n") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

// csvUsageAgents serializes per-agent usage rows as RFC 4180 CSV.
func csvUsageAgents(rows []sqlc.AgentUsageInWindowRow) string {
	var b strings.Builder
	b.WriteString("agent_id,agent_name,runs,tokens,cost_usd,actions\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "%s,%s,%d,%d,%.2f,%d\n",
			csvQuote(r.AgentID), csvQuote(r.AgentName), r.Runs, r.Tokens, r.TotalUsd, r.Actions)
	}
	return b.String()
}

// csvUsageProjects serializes per-project usage rows as RFC 4180 CSV.
func csvUsageProjects(rows []sqlc.ProjectUsageInWindowRow) string {
	var b strings.Builder
	b.WriteString("project_id,runs,tokens,cost_usd,actions\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "%s,%d,%d,%.2f,%d\n",
			csvQuote(r.ProjectID), r.Runs, r.Tokens, r.TotalUsd, r.Actions)
	}
	return b.String()
}

// csvUsageRuns serializes the drill-down run list as RFC 4180 CSV.
func csvUsageRuns(rows []sqlc.Run) string {
	var b strings.Builder
	b.WriteString("id,agent_id,trigger,status,task_id,project_id,prompt_tokens,completion_tokens,created_at,finished_at\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "%s,%s,%s,%s,%s,%s,%d,%d,%s,%s\n",
			csvQuote(r.ID), csvQuote(r.AgentID), csvQuote(r.Trigger), csvQuote(r.Status),
			csvQuote(r.TaskID.String), csvQuote(r.ProjectID.String),
			r.PromptTokens, r.CompletionTokens, csvQuote(r.CreatedAt), csvQuote(r.FinishedAt.String))
	}
	return b.String()
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
			{Name: "from", Kind: KindString, Required: false},
			{Name: "to", Kind: KindString, Required: false},
			{Name: "agent_id", Kind: KindString, Required: false},
			{Name: "project_id", Kind: KindString, Required: false},
			{Name: "limit", Kind: KindNumber, Required: false},
			{Name: "csv", Kind: KindBool, Required: false},
		}},
		Handle: handleUsageRead,
	})
}
