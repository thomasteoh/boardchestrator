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
	"github.com/thomasteoh/boardchestrator/internal/schedule"
)

// seedScheduleFixture seeds org, provider, role, agent, project, and one
// scheduled trigger, returning a Server with eng+trigq over the same DB plus
// the trigger id and project id.
func seedScheduleFixture(t *testing.T) (*Server, string, string) {
	t.Helper()
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
		RetryMax: 3, BackoffSecs: 30, RunsPerHour: 20, TokenBudget: 50000,
		ApprovalPolicyJson: `{"low":"auto","read":"auto","high":"require"}`,
		Active:             1,
	})
	if err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	proj, err := q.CreateProject(ctx, sqlc.CreateProjectParams{ID: "proj1", OrgID: org.ID, Name: "P", Key: "P1", Visibility: "private"})
	if err != nil {
		t.Fatalf("seed project: %v", err)
	}
	// A due trigger: every hour at 09:00 UTC, agent robo runs with a prompt.
	if _, err := q.CreateScheduledTrigger(ctx, sqlc.CreateScheduledTriggerParams{
		ID: "trig1", OrgID: org.ID, ProjectID: proj.ID, AgentID: agent.ID,
		CronExpr: "0 9 * * *", Prompt: "Triage the inbox", NextAt: "2026-08-11T09:00:00Z", Enabled: 1,
	}); err != nil {
		t.Fatalf("seed trigger: %v", err)
	}

	s := NewWithDB(&config.Config{
		Bind: "127.0.0.1:0", LogLevelStr: "debug", SecretKey: "test-secret-key",
		SessionSecret: "test-session-secret", AgentWorkers: 1,
	}, db)
	s.eng = agentrt.New(agentrt.Config{DB: db, Secret: "test-secret-key", EventSink: nil})
	s.trigq = sqlc.New(db)
	return s, proj.ID, "trig1"
}

// runsByProject lists runs for a project (WU-309 overlap guard assertions).
func runsByProject(t *testing.T, q *sqlc.Queries, projectID, orgID string) []sqlc.Run {
	t.Helper()
	// ListRunsByOrg then filter by project_id in Go (runs has project_id now).
	runs, err := q.ListRunsByOrg(ctxBG(), sqlc.ListRunsByOrgParams{OrgID: orgID, Limit: 50})
	if err != nil {
		t.Fatalf("list runs: %v", err)
	}
	var out []sqlc.Run
	for _, r := range runs {
		if r.ProjectID.Valid && r.ProjectID.String == projectID {
			out = append(out, r)
		}
	}
	return out
}

// TestSchedulerFiresDueTrigger covers WU-309 AC: a trigger whose next_at is due
// (fake clock) enqueues a run with trigger='schedule' and the prompt, and
// advances next_at to the next cron slot (UTC).
func TestSchedulerFiresDueTrigger(t *testing.T) {
	s, projID, trigID := seedScheduleFixture(t)
	ctx := context.Background()
	store := job.NewJobStore(s.db)
	q := sqlc.New(s.db)

	// Fake clock: 2026-08-11T09:30:00Z — trigger next_at 09:00 is due.
	now := time.Date(2026, 8, 11, 9, 30, 0, 0, time.UTC)
	s.fireDueTriggers(ctx, store, now)

	runs := runsByProject(t, q, projID, "org1")
	if len(runs) != 1 {
		t.Fatalf("expected 1 run fired, got %d", len(runs))
	}
	if runs[0].Trigger != "schedule" || runs[0].AgentID != "agt1" {
		t.Fatalf("unexpected run: trigger=%s agent=%s", runs[0].Trigger, runs[0].AgentID)
	}
	// next_at advanced to the next 09:00 slot (Aug 12).
	trig, err := q.FindScheduledTriggerByID(ctx, sqlc.FindScheduledTriggerByIDParams{ID: trigID, OrgID: "org1"})
	if err != nil {
		t.Fatalf("find trigger: %v", err)
	}
	nextAt, err := schedule.NextAt("0 9 * * *", now)
	if err != nil {
		t.Fatalf("compute next_at: %v", err)
	}
	if trig.NextAt != nextAt {
		t.Fatalf("expected next_at %s, got %s", nextAt, trig.NextAt)
	}
}

// TestSchedulerOverlapSkip covers WU-309 AC: when the project already has an
// active (non-terminal) run, a due trigger fires but EnqueueRun's per-project
// guard skips creating a run — no pile-up. next_at still advances.
func TestSchedulerOverlapSkip(t *testing.T) {
	s, projID, trigID := seedScheduleFixture(t)
	ctx := context.Background()
	store := job.NewJobStore(s.db)
	q := sqlc.New(s.db)

	// Seed an active run for the project (queued) so the overlap guard trips.
	if _, err := q.CreateRun(ctx, sqlc.CreateRunParams{
		ID: "run-active", OrgID: "org1", AgentID: "agt1", Trigger: "schedule",
		TaskID: sql.NullString{}, ChatSessionID: sql.NullString{},
		ProjectID:  sql.NullString{String: projID, Valid: true},
		InitiatedBy: sql.NullString{}, Status: "queued",
	}); err != nil {
		t.Fatalf("seed active run: %v", err)
	}

	now := time.Date(2026, 8, 11, 9, 30, 0, 0, time.UTC)
	s.fireDueTriggers(ctx, store, now)

	// The pre-seeded active run is the only one — the fire was skipped.
	runs := runsByProject(t, q, projID, "org1")
	if len(runs) != 1 {
		t.Fatalf("expected overlap to skip the fire (1 run total), got %d", len(runs))
	}
	// next_at still advanced.
	trig, err := q.FindScheduledTriggerByID(ctx, sqlc.FindScheduledTriggerByIDParams{ID: trigID, OrgID: "org1"})
	if err != nil {
		t.Fatalf("find trigger: %v", err)
	}
	nextAt, err := schedule.NextAt("0 9 * * *", now)
	if err != nil {
		t.Fatalf("compute next_at: %v", err)
	}
	if trig.NextAt != nextAt {
		t.Fatalf("expected next_at %s, got %s", nextAt, trig.NextAt)
	}
}

// TestSchedulerTimezone covers WU-309 AC: cron evaluation is in UTC. A trigger
// whose next_at is in a future UTC slot is not due yet, so no run fires.
func TestSchedulerTimezone(t *testing.T) {
	s, projID, _ := seedScheduleFixture(t)
	ctx := context.Background()
	store := job.NewJobStore(s.db)
	q := sqlc.New(s.db)

	// next_at 09:00, clock 08:00 UTC — not due.
	now := time.Date(2026, 8, 11, 8, 0, 0, 0, time.UTC)
	s.fireDueTriggers(ctx, store, now)

	runs := runsByProject(t, q, projID, "org1")
	if len(runs) != 0 {
		t.Fatalf("expected no run fired before next_at, got %d", len(runs))
	}
}
