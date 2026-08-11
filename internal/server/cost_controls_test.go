package server

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/agentrt"
	"github.com/thomasteoh/boardchestrator/internal/config"
	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/job"
)

// TestOrgCapAlertRecordsRow covers WU-310 AC: when EnqueueRun crosses the
// org's threshold % AND the engine's OnCapAlert is wired to the server sink,
// an org_cap_alerts row is recorded and the alert publishes on the bus.
func TestOrgCapAlertRecordsRow(t *testing.T) {
	db := dbtest.New(t)
	ctx := context.Background()
	q := sqlc.New(db)

	org, err := q.CreateOrg(ctx, sqlc.CreateOrgParams{ID: "org1", Name: "Acme", Slug: "acme", Context: "", Visibility: "private"})
	if err != nil {
		t.Fatalf("seed org: %v", err)
	}
	if _, err := q.CreateProvider(ctx, sqlc.CreateProviderParams{ID: "prov1", Kind: "openai-compatible", Name: "Test", BaseUrl: "https://test/v1", KeyEnc: nil, ModelsJson: `["gpt-4o"]`}); err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	if _, err := q.CreateRole(ctx, sqlc.CreateRoleParams{ID: "role1", OrgID: org.ID, Name: "Editor", IsSystem: 0, GrantsJson: `["task.list"]`}); err != nil {
		t.Fatalf("seed role: %v", err)
	}
	agent, err := q.CreateAgent(ctx, sqlc.CreateAgentParams{
		ID: "agt1", OrgID: sql.NullString{String: org.ID, Valid: true},
		Name: "robo", ProviderID: "prov1", Model: "gpt-4o",
		Context: "You are Acme's assistant.", RoleID: sql.NullString{String: "role1", Valid: true},
		RetryMax: 3, BackoffSecs: 30, RunsPerHour: 100, TokenBudget: 1 << 40,
		ApprovalPolicyJson: `{"low":"auto","read":"auto","high":"require"}`,
		Active:             1,
	})
	if err != nil {
		t.Fatalf("seed agent: %v", err)
	}

	// Price the model $2/$4 per MTok, cap $10 at 80% alert.
	if _, err := q.UpsertModelPricing(ctx, sqlc.UpsertModelPricingParams{ID: "p1", ProviderID: "prov1", Model: "gpt-4o", InputPerMtok: 2, OutputPerMtok: 4}); err != nil {
		t.Fatalf("seed pricing: %v", err)
	}
	if _, err := q.UpdateOrgCap(ctx, sqlc.UpdateOrgCapParams{MonthlyCapUsd: 10, CapAlertPct: 80, ID: org.ID}); err != nil {
		t.Fatalf("set cap: %v", err)
	}

	s := NewWithDB(&config.Config{
		Bind: "127.0.0.1:0", LogLevelStr: "debug", SecretKey: "test-secret-key",
		SessionSecret: "test-session-secret", AgentWorkers: 1,
	}, db)
	s.eng = agentrt.New(agentrt.Config{
		DB: db, Secret: "test-secret-key", EventSink: nil, OnCapAlert: s.orgCapAlertSink(),
	})
	s.trigq = sqlc.New(db)

	store := job.NewJobStore(db)

	// Seed a finished run consuming $6 (60% of cap — no alert yet).
	seedCapRun(t, q, org.ID, agent.ID, 1_000_000, 1_000_000)

	// Enqueue 1: spend 60%, under alert → created, no alert row.
	if _, created, err := s.eng.EnqueueRun(ctx, store, org.ID, agent.ID, "mention", "", "", "", "u1", "@robo"); err != nil || !created {
		t.Fatalf("expected run created below threshold, created=%v err=%v", created, err)
	}
	if n := capAlerts(t, q, org.ID); n != 0 {
		t.Fatalf("expected 0 alert rows below threshold, got %d", n)
	}

	// Seed another $6 run → spend $12 (120%, over cap + threshold).
	seedCapRun(t, q, org.ID, agent.ID, 1_000_000, 1_000_000)

	// Enqueue 2: crosses cap → hard stop error, but alert row recorded.
	if _, _, err := s.eng.EnqueueRun(ctx, store, org.ID, agent.ID, "mention", "", "", "", "u1", "@robo"); err == nil {
		t.Fatalf("expected hard-stop error after crossing cap")
	}
	if n := capAlerts(t, q, org.ID); n != 1 {
		t.Fatalf("expected 1 alert row after crossing cap, got %d", n)
	}
}

// seedCapRun creates a finished run with tokens finished now (WU-310).
func seedCapRun(t *testing.T, q *sqlc.Queries, orgID, agentID string, promptTokens, completionTokens int64) {
	t.Helper()
	ctx := context.Background()
	id := capAlertID()
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	if _, err := q.CreateRun(ctx, sqlc.CreateRunParams{
		ID: id, OrgID: orgID, AgentID: agentID, Trigger: "mention",
		TaskID: sql.NullString{}, ChatSessionID: sql.NullString{},
		ProjectID: sql.NullString{}, InitiatedBy: sql.NullString{}, Status: "queued",
	}); err != nil {
		t.Fatalf("seed run: %v", err)
	}
	if _, err := q.FinishRun(ctx, sqlc.FinishRunParams{
		Status: "finished", FinishedAt: sql.NullString{String: now, Valid: true},
		Error: "", PromptTokens: promptTokens, CompletionTokens: completionTokens,
		ID: id, OrgID: orgID,
	}); err != nil {
		t.Fatalf("finish run: %v", err)
	}
}

// capAlerts counts org_cap_alerts rows for an org (WU-310).
func capAlerts(t *testing.T, q *sqlc.Queries, orgID string) int {
	t.Helper()
	rows, err := q.ListOrgCapAlerts(context.Background(), orgID)
	if err != nil {
		t.Fatalf("list cap alerts: %v", err)
	}
	return len(rows)
}
