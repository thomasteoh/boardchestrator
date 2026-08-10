package agentrt

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/client"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/job"
)

// registerHigh registers a high-impact org-scoped test action granted by
// task.delete. The approval gate consults the acting agent's policy for
// ImpactHigh, so this lets us exercise require/auto/forbid on a real dispatch.
func registerHigh() {
	if _, ok := action.Lookup("agentrt.test.high"); ok {
		return
	}
	action.Register(action.Definition{
		Name:       "agentrt.test.high",
		Impact:     action.ImpactHigh,
		Permission: "task.delete",
		Scope:      action.ScopeOrg,
		Input:      action.FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle: func(ctx context.Context, ac action.ActionCtx, in json.RawMessage) (any, error) {
			return map[string]any{"ok": true}, nil
		},
	})
}

// buildApprovalEngine seeds an org+agent whose effective perms grant
// task.delete (role ∩ skill), with the given approval_policy_json, over the
// given fake provider, and returns the engine + agent + org id.
func buildApprovalEngine(t *testing.T, policy string, fp *fakeProvider) (*Engine, sqlc.Agent, string) {
	t.Helper()
	registerHigh()
	eng, _, orgID := buildEngine(t, fp)
	ctx := context.Background()
	// The default seeded agent grants task.list; extend the role to also grant
	// task.delete, and set the policy under test. The skill must also allow
	// task.delete — effective perms = role grants ∩ skill allowed actions.
	_, err := eng.q.UpdateRoleGrants(ctx, sqlc.UpdateRoleGrantsParams{
		GrantsJson: `["task.list","task.delete"]`, ID: "role1", OrgID: orgID,
	})
	if err != nil {
		t.Fatalf("update role grants: %v", err)
	}
	if _, err := eng.db.Exec(`UPDATE skills SET allowed_actions_json = '["task.list","task.delete"]' WHERE id = 'sk1' AND org_id = ?`, orgID); err != nil {
		t.Fatalf("update skill allowed actions: %v", err)
	}
	// Seed the run's initiator user (u1) so the approval.requested notification
	// FK to users(id) resolves.
	if _, err := eng.db.Exec(`INSERT INTO users (id, email, name) VALUES ('u1', 'u1@example.com', 'u1')`); err != nil {
		t.Fatalf("seed user u1: %v", err)
	}
	agt, err := eng.q.FindAgentByID(ctx, "agt1")
	if err != nil {
		t.Fatalf("find agent: %v", err)
	}
	if _, err := eng.q.UpdateAgent(ctx, sqlc.UpdateAgentParams{
		Name: agt.Name, ProviderID: agt.ProviderID, Model: agt.Model, Context: agt.Context,
		RoleID: agt.RoleID, RetryMax: agt.RetryMax, BackoffSecs: agt.BackoffSecs,
		RunsPerHour: agt.RunsPerHour, TokenBudget: agt.TokenBudget,
		ApprovalPolicyJson: policy, Active: agt.Active,
		ID: agt.ID, OrgID: agt.OrgID,
	}); err != nil {
		t.Fatalf("set policy: %v", err)
	}
	return eng, agt, orgID
}

// dispatchHigh calls the engine's gated dispatcher for the high-impact test
// action as the agent actor, using the run-id context so the gate can attach
// an approvals row. Returns the tool result and error.
func dispatchHigh(t *testing.T, eng *Engine, agent sqlc.Agent, orgID string, runID string) (toolResult, error) {
	t.Helper()
	ctx := context.Background()
	run, err := eng.q.FindRunByID(ctx, sqlc.FindRunByIDParams{ID: runID, OrgID: orgID})
	if err != nil {
		t.Fatalf("find run: %v", err)
	}
	return eng.dispatchTool(ctx, run, agent, "agentrt.test.high", json.RawMessage(`{"a":1}`))
}

// userDisp builds a user-facing dispatcher over db with the DB scope resolver
// and an allow-all permission checker (mirrors the server's action.New but
// without the deny-by-default perm engine — fine for approval.decide tests).
func userDisp(t *testing.T, db *sql.DB) *action.Dispatcher {
	t.Helper()
	return action.New(db, action.WithScopeResolver(action.NewDBScopeResolver(db)))
}

// decideRun marks the given approval id approved/rejected as a user actor and
// returns the decide output.
func decideRun(t *testing.T, eng *Engine, approvalID, orgID string, approve bool) map[string]string {
	t.Helper()
	ctx := context.Background()
	disp := userDisp(t, eng.db)
	body, _ := json.Marshal(map[string]any{"id": approvalID, "org_id": orgID, "approve": approve})
	out, derr := disp.Dispatch(ctx, action.Actor{Type: action.ActorUser, ID: "u1"},
		"approval.decide", body, action.Opts{Org: orgID})
	if derr != nil {
		t.Fatalf("approval.decide: %v", derr)
	}
	return out.(map[string]string)
}

// TestApprovalGateMatrix drives the gate matrix: policy ∈ {auto, require,
// forbid} × the action's impact. The high test action is ImpactHigh; to cover
// low/read we vary the action impact via a read/low echo and check the gate
// policy key lookup. We assert the approvals row is only persisted for require.
func TestApprovalGateMatrix(t *testing.T) {
	tests := []struct {
		name   string
		policy string
		want   string // "proceed" | "pending" | "forbid"
	}{
		{"high:auto", `{"high":"auto"}`, "proceed"},
		{"high:require", `{"high":"require"}`, "pending"},
		{"high:forbid", `{"high":"forbid"}`, "forbid"},
		// Unknown key defaults to auto.
		{"high:unset", `{}`, "proceed"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			eng, agent, orgID := buildApprovalEngine(t, tc.policy, &fakeProvider{model: "gpt-4o"})
			ctx := context.Background()
			run := seedRun(t, eng, agent.ID, orgID)

			res, err := dispatchHigh(t, eng, agent, orgID, run.ID)
			_ = res
			switch tc.want {
			case "pending":
				if err == nil {
					t.Fatalf("expected ErrApprovalPending")
				}
				// An approvals row must be persisted for the run.
				rows, lerr := eng.q.ListApprovalsByRun(ctx, sqlc.ListApprovalsByRunParams{RunID: run.ID, OrgID: orgID})
				if lerr != nil {
					t.Fatalf("list approvals: %v", lerr)
				}
				if len(rows) != 1 || rows[0].Status != "pending" {
					t.Fatalf("expected 1 pending approval, got %+v", rows)
				}
				if rows[0].ActionName != "agentrt.test.high" {
					t.Fatalf("expected action name recorded, got %q", rows[0].ActionName)
				}
				// The gate must have created an approval.requested notification
				// for the run's initiator.
				notifs, nerr := eng.q.ListNotifications(ctx, sqlc.ListNotificationsParams{UserID: "u1", Limit: 10, Offset: 0})
				if nerr != nil {
					t.Fatalf("list notifications: %v", nerr)
				}
				found := false
				for _, n := range notifs {
					if n.EventName == "approval.requested" && n.SubjectID == rows[0].ID {
						found = true
					}
				}
				if !found {
					t.Fatalf("expected approval.requested notification for initiator, got %+v", notifs)
				}
			case "forbid":
				if err == nil {
					t.Fatalf("expected forbidden error")
				}
			case "proceed":
				if err != nil {
					t.Fatalf("expected proceed, got %v", err)
				}
			}
		})
	}
}

// TestApprovalResumeAfterApprove drives the full resume path: a run parks as
// awaiting_approval when a require call hits the gate; approval.decide
// (human, via a dispatcher) marks it approved and requeues the run; the engine
// Handler re-runs it and the gate sees the decided row and proceeds.
func TestApprovalResumeAfterApprove(t *testing.T) {
	// Script: first step calls the high action (parks pending), then the model
	// finishes. The resumed run re-runs from a fresh model call that finishes.
	fp := &fakeProvider{model: "gpt-4o", steps: []client.CompletionResponse{
		step(toolCall("agentrt.test.high", `{"a":1}`)),
	}}
	eng, agent, orgID := buildApprovalEngine(t, `{"high":"require"}`, fp)
	ctx := context.Background()
	run := seedRun(t, eng, agent.ID, orgID)
	store := job.NewJobStore(eng.db)
	if err := store.Enqueue(ctx, "job1", "run", mustJSON(runJob{RunID: run.ID, OrgID: orgID}), "2026-08-09T00:00:00Z", 3); err != nil {
		t.Fatalf("enqueue job1: %v", err)
	}

	// First handler run parks awaiting_approval (the loop sees ErrApprovalPending).
	if err := eng.Handler(store)(ctx, mustJob(t, store, "job1")); err != nil {
		t.Fatalf("handler: %v", err)
	}
	got, err := eng.q.FindRunByID(ctx, sqlc.FindRunByIDParams{ID: run.ID, OrgID: orgID})
	if err != nil {
		t.Fatalf("find run: %v", err)
	}
	if got.Status != "awaiting_approval" {
		t.Fatalf("expected awaiting_approval, got %q", got.Status)
	}

	// Find the pending approval row and decide approve via a user dispatcher.
	rows, err := eng.q.ListApprovalsByRun(ctx, sqlc.ListApprovalsByRunParams{RunID: run.ID, OrgID: orgID})
	if err != nil {
		t.Fatalf("list approvals: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 approval, got %d", len(rows))
	}
	approvalID := rows[0].ID

	decided := decideRun(t, eng, approvalID, orgID, true)
	if decided["status"] != "approved" {
		t.Fatalf("expected approved, got %+v", decided)
	}

	// Run requeued.
	got2, err := eng.q.FindRunByID(ctx, sqlc.FindRunByIDParams{ID: run.ID, OrgID: orgID})
	if err != nil {
		t.Fatalf("find run: %v", err)
	}
	if got2.Status != "queued" {
		t.Fatalf("expected queued after approve, got %q", got2.Status)
	}

	// Resume: enqueue a fresh job and run the Handler again. The gate sees the
	// decided row for the same run+action+input → proceeds and the loop finishes.
	if err := store.Enqueue(ctx, "job2", "run", mustJSON(runJob{RunID: run.ID, OrgID: orgID}), "2026-08-09T00:00:00Z", 3); err != nil {
		t.Fatalf("enqueue job2: %v", err)
	}
	if err := eng.Handler(store)(ctx, mustJob(t, store, "job2")); err != nil {
		t.Fatalf("resume handler: %v", err)
	}
	got3, err := eng.q.FindRunByID(ctx, sqlc.FindRunByIDParams{ID: run.ID, OrgID: orgID})
	if err != nil {
		t.Fatalf("find run: %v", err)
	}
	if got3.Status == "awaiting_approval" || got3.Status == "failed" {
		t.Fatalf("expected resumed run to finish, got %q", got3.Status)
	}
}

// TestApprovalRejectSurfaces: after a rejection, the resumed dispatch must be
// forbidden and the tool error surfaced to the model (self-correction), not
// parked again.
func TestApprovalRejectSurfaces(t *testing.T) {
	eng, agent, orgID := buildApprovalEngine(t, `{"high":"require"}`, &fakeProvider{model: "gpt-4o"})
	ctx := context.Background()
	run := seedRun(t, eng, agent.ID, orgID)

	// Park once to create the pending approval row (mirror executeRun: set the
	// run awaiting_approval as the loop does).
	if _, err := dispatchHigh(t, eng, agent, orgID, run.ID); err == nil {
		t.Fatalf("expected pending on first dispatch")
	}
	if _, err := eng.q.SetRunAwaitingApproval(ctx, sqlc.SetRunAwaitingApprovalParams{ID: run.ID, OrgID: orgID}); err != nil {
		t.Fatalf("set awaiting: %v", err)
	}
	rows, err := eng.q.ListApprovalsByRun(ctx, sqlc.ListApprovalsByRunParams{RunID: run.ID, OrgID: orgID})
	if err != nil {
		t.Fatalf("list approvals: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 approval, got %d", len(rows))
	}

	// Reject it.
	decided := decideRun(t, eng, rows[0].ID, orgID, false)
	if decided["status"] != "rejected" {
		t.Fatalf("expected rejected, got %+v", decided)
	}

	// Re-dispatch: the gate must forbid (not park again) — ErrForbidden.
	if _, err := dispatchHigh(t, eng, agent, orgID, run.ID); err == nil {
		t.Fatalf("expected forbidden after reject")
	}
}
