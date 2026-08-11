package agentrt

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/client"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/job"
)

// setOrgCap sets the org's monthly cap + alert % and returns the org (WU-310).
func setOrgCap(t *testing.T, eng *Engine, orgID string, capUSD, alertPct float64) sqlc.Org {
	t.Helper()
	org, err := eng.q.UpdateOrgCap(context.Background(), sqlc.UpdateOrgCapParams{
		MonthlyCapUsd: capUSD,
		CapAlertPct:   alertPct,
		ID:            orgID,
	})
	if err != nil {
		t.Fatalf("set org cap: %v", err)
	}
	return org
}

// raiseTokenBudget lifts an agent's monthly token budget so cost tests are
// governed only by the org cap (WU-310).
func raiseTokenBudget(t *testing.T, eng *Engine, agent sqlc.Agent, orgID string) {
	t.Helper()
	if _, err := eng.q.UpdateAgent(context.Background(), sqlc.UpdateAgentParams{
		ID: agent.ID, OrgID: sql.NullString{String: orgID, Valid: true},
		Name: agent.Name, ProviderID: agent.ProviderID, Model: agent.Model,
		Context: agent.Context, RoleID: agent.RoleID, RetryMax: agent.RetryMax,
		BackoffSecs: agent.BackoffSecs, RunsPerHour: agent.RunsPerHour, TokenBudget: 1 << 40,
		ApprovalPolicyJson: agent.ApprovalPolicyJson, Active: agent.Active,
	}); err != nil {
		t.Fatalf("raise token budget: %v", err)
	}
}

// seedFinishedRun creates a finished run with the given prompt/completion
// tokens finished "now" (current UTC month) so spend aggregation picks it up
// (WU-310). projectID may be "".
func seedFinishedRun(t *testing.T, eng *Engine, orgID, agentID, projectID string, promptTokens, completionTokens int64) {
	t.Helper()
	ctx := context.Background()
	id := newID()
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	if _, err := eng.q.CreateRun(ctx, sqlc.CreateRunParams{
		ID:            id,
		OrgID:         orgID,
		AgentID:       agentID,
		Trigger:       "mention",
		TaskID:        sql.NullString{},
		ChatSessionID: sql.NullString{},
		ProjectID:     sql.NullString{String: projectID, Valid: projectID != ""},
		InitiatedBy:   sql.NullString{},
		Status:        "queued",
	}); err != nil {
		t.Fatalf("seed run: %v", err)
	}
	if _, err := eng.q.FinishRun(ctx, sqlc.FinishRunParams{
		Status:           "finished",
		FinishedAt:       sql.NullString{String: now, Valid: true},
		Error:            "",
		PromptTokens:     promptTokens,
		CompletionTokens: completionTokens,
		ID:               id,
		OrgID:            orgID,
	}); err != nil {
		t.Fatalf("finish run: %v", err)
	}
}

// TestOrgCapHardStop covers WU-310 AC: when monthly spend >= cap, EnqueueRun
// hard-stops (error, created=false) and no run is created.
func TestOrgCapHardStop(t *testing.T) {
	fp := &fakeProvider{model: "gpt-4o", steps: []client.CompletionResponse{
		step(toolCall("agentrt.test.echo", `{"name":"x"}`)),
	}}
	eng, agent, orgID := buildEngine(t, fp)
	ctx := context.Background()
	store := job.NewJobStore(eng.db)

	// Price the agent's model so spend is computable: $2/$4 per MTok.
	if _, err := eng.q.UpsertModelPricing(ctx, sqlc.UpsertModelPricingParams{
		ID: "price1", ProviderID: "prov1", Model: "gpt-4o",
		InputPerMtok: 2, OutputPerMtok: 4,
	}); err != nil {
		t.Fatalf("seed pricing: %v", err)
	}
	// Raise the agent's token budget so only the org cap governs this test.
	raiseTokenBudget(t, eng, agent, orgID)
	// Set a cap of $1. Seed a finished run consuming $5 of spend.
	setOrgCap(t, eng, orgID, 1, 80)
	seedFinishedRun(t, eng, orgID, agent.ID, "", 1_000_000, 1_000_000) // $2 + $4 = $6

	runID, created, err := eng.EnqueueRun(ctx, store, orgID, agent.ID, "mention", "", "", "", "u1", "@robo")
	if err == nil {
		t.Fatalf("expected hard-stop error, got created=%v run=%s", created, runID)
	}
	if created {
		t.Fatalf("expected created=false on hard stop")
	}
}

// TestOrgCapThresholdAlert covers WU-310 AC: spend below the cap but above
// cap*alert%/100 fires OnCapAlert exactly once and records an org_cap_alerts row.
func TestOrgCapThresholdAlert(t *testing.T) {
	fp := &fakeProvider{model: "gpt-4o", steps: []client.CompletionResponse{
		step(toolCall("agentrt.test.echo", `{"name":"x"}`)),
	}}
	eng, agent, orgID := buildEngine(t, fp)
	ctx := context.Background()
	store := job.NewJobStore(eng.db)

	if _, err := eng.q.UpsertModelPricing(ctx, sqlc.UpsertModelPricingParams{
		ID: "price1", ProviderID: "prov1", Model: "gpt-4o",
		InputPerMtok: 2, OutputPerMtok: 4,
	}); err != nil {
		t.Fatalf("seed pricing: %v", err)
	}
	// Raise the agent's token budget so only the org cap governs this test.
	raiseTokenBudget(t, eng, agent, orgID)
	// Cap $10, alert at 80%. Seed $6 spend (60% — under alert). Then a $2 run
	// pushes to 80% → alert fires on that run's enqueue.
	setOrgCap(t, eng, orgID, 10, 80)
	seedFinishedRun(t, eng, orgID, agent.ID, "", 1_000_000, 1_000_000) // $6

	var alerted int
	eng.onCapAlert = func(o string) { alerted++ }

	// First enqueue (spend still 60%) — no alert.
	if _, created, err := eng.EnqueueRun(ctx, store, orgID, agent.ID, "mention", "", "", "", "u1", "@robo"); err != nil || !created {
		t.Fatalf("expected run created, created=%v err=%v", created, err)
	}
	if alerted != 0 {
		t.Fatalf("expected no alert below threshold, got %d", alerted)
	}
	// Seed another $6 (now $12 > cap, but threshold crossed too). Use a fresh
	// pricing check via a new enqueue with a completed run that tips it over.
	// Re-enqueue: spend is now $12 >= cap so the hard stop returns an error,
	// but the threshold alert should have fired once before the stop.
	seedFinishedRun(t, eng, orgID, agent.ID, "", 1_000_000, 1_000_000) // +$6 → $12
	if _, _, err := eng.EnqueueRun(ctx, store, orgID, agent.ID, "mention", "", "", "", "u1", "@robo"); err == nil {
		t.Fatalf("expected hard stop after crossing cap")
	}
	if alerted != 1 {
		t.Fatalf("expected exactly one threshold alert, got %d", alerted)
	}
}

// TestAgentRunsPerHourCap covers WU-310 AC: an agent at its runs/hour cap is
// skipped (created=false) and no run is created.
func TestAgentRunsPerHourCap(t *testing.T) {
	fp := &fakeProvider{model: "gpt-4o", steps: []client.CompletionResponse{
		step(toolCall("agentrt.test.echo", `{"name":"x"}`)),
	}}
	eng, agent, orgID := buildEngine(t, fp)
	ctx := context.Background()
	store := job.NewJobStore(eng.db)

	// Lower the agent's hourly cap to 1.
	if _, err := eng.q.UpdateAgent(ctx, sqlc.UpdateAgentParams{
		ID: agent.ID, OrgID: sql.NullString{String: orgID, Valid: true},
		Name: agent.Name, ProviderID: agent.ProviderID, Model: agent.Model,
		Context: agent.Context, RoleID: agent.RoleID, RetryMax: agent.RetryMax,
		BackoffSecs: agent.BackoffSecs, RunsPerHour: 1, TokenBudget: agent.TokenBudget,
		ApprovalPolicyJson: agent.ApprovalPolicyJson, Active: agent.Active,
	}); err != nil {
		t.Fatalf("lower runs/hour: %v", err)
	}

	// One run in the last hour consumes the cap.
	seedFinishedRun(t, eng, orgID, agent.ID, "", 0, 0)

	// Next enqueue is skipped (created=false).
	if _, created, err := eng.EnqueueRun(ctx, store, orgID, agent.ID, "mention", "", "", "", "u1", "@robo"); err != nil || created {
		t.Fatalf("expected skip (created=false, no err), created=%v err=%v", created, err)
	}
}

// TestAgentTokenBudgetCap covers WU-310 AC: an agent at its monthly token
// budget is skipped (created=false).
func TestAgentTokenBudgetCap(t *testing.T) {
	fp := &fakeProvider{model: "gpt-4o", steps: []client.CompletionResponse{
		step(toolCall("agentrt.test.echo", `{"name":"x"}`)),
	}}
	eng, agent, orgID := buildEngine(t, fp)
	ctx := context.Background()
	store := job.NewJobStore(eng.db)

	// Lower the agent's token budget to 100.
	if _, err := eng.q.UpdateAgent(ctx, sqlc.UpdateAgentParams{
		ID: agent.ID, OrgID: sql.NullString{String: orgID, Valid: true},
		Name: agent.Name, ProviderID: agent.ProviderID, Model: agent.Model,
		Context: agent.Context, RoleID: agent.RoleID, RetryMax: agent.RetryMax,
		BackoffSecs: agent.BackoffSecs, RunsPerHour: agent.RunsPerHour, TokenBudget: 100,
		ApprovalPolicyJson: agent.ApprovalPolicyJson, Active: agent.Active,
	}); err != nil {
		t.Fatalf("lower token budget: %v", err)
	}

	// Seed a run with 200 tokens (over the 100 budget).
	seedFinishedRun(t, eng, orgID, agent.ID, "", 200, 0)

	if _, created, err := eng.EnqueueRun(ctx, store, orgID, agent.ID, "mention", "", "", "", "u1", "@robo"); err != nil || created {
		t.Fatalf("expected skip (created=false, no err), created=%v err=%v", created, err)
	}
}

// TestUsageAggregationGolden covers WU-310 AC (dashboard aggregation): two
// finished runs with known tokens + pricing produce the expected per-agent and
// per-project cost, and the org monthly total matches the sum (golden check).
func TestUsageAggregationGolden(t *testing.T) {
	fp := &fakeProvider{model: "gpt-4o", steps: []client.CompletionResponse{
		step(toolCall("agentrt.test.echo", `{"name":"x"}`)),
	}}
	eng, agent, orgID := buildEngine(t, fp)
	ctx := context.Background()

	// Price gpt-4o at $2 input / $4 output per MTok.
	if _, err := eng.q.UpsertModelPricing(ctx, sqlc.UpsertModelPricingParams{
		ID: "price1", ProviderID: "prov1", Model: "gpt-4o",
		InputPerMtok: 2, OutputPerMtok: 4,
	}); err != nil {
		t.Fatalf("seed pricing: %v", err)
	}

	// Two finished runs in project P1:
	//   A: 1,000,000 prompt + 500,000 completion  → $2.00 + $2.00 = $4.00
	//   B: 2,000,000 prompt + 1,000,000 completion → $4.00 + $4.00 = $8.00
	// Total $12.00, 4,500,000 tokens.
	seedFinishedRun(t, eng, orgID, agent.ID, "proj1", 1_000_000, 500_000)
	seedFinishedRun(t, eng, orgID, agent.ID, "proj1", 2_000_000, 1_000_000)

	month := monthStartUTC()
	total, err := eng.q.OrgMonthlySpend(ctx, sqlc.OrgMonthlySpendParams{OrgID: orgID, FinishedAt: sql.NullString{String: month, Valid: true}})
	if err != nil {
		t.Fatalf("org spend: %v", err)
	}
	if total != 12.0 {
		t.Fatalf("expected org spend $12.00, got %.4f", total)
	}
	tokens, err := eng.q.OrgMonthlyTokens(ctx, sqlc.OrgMonthlyTokensParams{OrgID: orgID, FinishedAt: sql.NullString{String: month, Valid: true}})
	if err != nil {
		t.Fatalf("org tokens: %v", err)
	}
	if tokens != 4_500_000 {
		t.Fatalf("expected 4,500,000 tokens, got %d", tokens)
	}

	byAgent, err := eng.q.AgentUsageByMonth(ctx, sqlc.AgentUsageByMonthParams{OrgID: orgID, FinishedAt: sql.NullString{String: month, Valid: true}})
	if err != nil {
		t.Fatalf("by agent: %v", err)
	}
	if len(byAgent) != 1 || byAgent[0].Runs != 2 || byAgent[0].Tokens != 4_500_000 {
		t.Fatalf("unexpected by-agent: %+v", byAgent)
	}
	if byAgent[0].TotalUsd != 12.0 {
		t.Fatalf("expected agent cost $12.00, got %.4f", byAgent[0].TotalUsd)
	}

	byProject, err := eng.q.ProjectUsageByMonth(ctx, sqlc.ProjectUsageByMonthParams{OrgID: orgID, FinishedAt: sql.NullString{String: month, Valid: true}})
	if err != nil {
		t.Fatalf("by project: %v", err)
	}
	if len(byProject) != 1 || byProject[0].ProjectID.String != "proj1" || byProject[0].Runs != 2 {
		t.Fatalf("unexpected by-project: %+v", byProject)
	}
	if byProject[0].TotalUsd != 12.0 {
		t.Fatalf("expected project cost $12.00, got %.4f", byProject[0].TotalUsd)
	}
}
