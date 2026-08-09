package agentrt

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/client"
	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/job"
)

// fakeProvider is a scripted client.ProviderClient for the tool-loop tests.
// It replays the scripted responses in order; when exhausted it returns a
// plain-text finish. The script lets us drive tool_calls, hallucinations, and
// runaway loops without a real LLM.
type fakeProvider struct {
	model  string
	steps  []client.CompletionResponse
	seen   []client.CompletionRequest // requests captured for assertions
	repeat client.CompletionResponse  // when set, always returned (runaway-loop tests)
	fail   error                      // when set, every call returns this error
}

func (f *fakeProvider) Model() string { return f.model }

func (f *fakeProvider) ChatCompletion(ctx context.Context, req client.CompletionRequest) (*client.CompletionResponse, error) {
	f.seen = append(f.seen, req)
	if f.fail != nil {
		return nil, f.fail
	}
	if f.repeat.Model != "" {
		r := f.repeat
		return &r, nil
	}
	if len(f.steps) == 0 {
		return &client.CompletionResponse{
			ID: "done", Object: "chat.completion", Model: f.model,
			Choices: []client.CompletionChoice{{Index: 0, Message: client.Message{Role: "assistant", Content: "done"}, FinishReason: "stop"}},
			Usage:   client.Usage{PromptTokens: 1, CompletionTokens: 1},
		}, nil
	}
	next := f.steps[0]
	f.steps = f.steps[1:]
	return &next, nil
}

func (f *fakeProvider) ChatCompletionStream(ctx context.Context, req client.CompletionRequest, onDelta func(client.StreamDelta) error) (*client.StreamResult, error) {
	return nil, nil
}

func toolCall(name, args string) client.ToolCall {
	return client.ToolCall{
		ID: name, Type: "function",
		Function: struct {
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
		}{Name: name, Arguments: args},
	}
}

func step(toolCalls ...client.ToolCall) client.CompletionResponse {
	msg := client.Message{Role: "assistant"}
	if len(toolCalls) == 0 {
		msg.Content = "done"
	}
	return client.CompletionResponse{
		ID: "c", Object: "chat.completion", Model: "test",
		Choices: []client.CompletionChoice{{Index: 0, Message: msg, FinishReason: "tool_calls", ToolCalls: toolCalls}},
		Usage:   client.Usage{PromptTokens: 5, CompletionTokens: 5},
	}
}

// registerEcho registers a minimal org-scoped test action the agent's
// effective perms can grant. It returns input verbatim so the happy-path test
// can assert the dispatched output round-trips through the loop. Idempotent:
// the global registry persists across tests in a process.
func registerEcho() {
	if _, ok := action.Lookup("agentrt.test.echo"); ok {
		return
	}
	action.Register(action.Definition{
		Name:       "agentrt.test.echo",
		Impact:     action.ImpactRead,
		Permission: "task.list",
		Scope:      action.ScopeOrg,
		Input:      action.FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle: func(ctx context.Context, ac action.ActionCtx, in json.RawMessage) (any, error) {
			return map[string]any{"echo": string(in)}, nil
		},
	})
}

// buildEngine seeds an org+agent whose effective perms grant task.list
// (role grant ∩ skill allowed_actions), then constructs an engine over the
// fake provider. Returns the engine, the agent, and the org id.
func buildEngine(t *testing.T, fp *fakeProvider) (*Engine, sqlc.Agent, string) {
	t.Helper()
	registerEcho()
	db := dbtest.New(t)
	q := sqlc.New(db)
	ctx := context.Background()

	org, err := q.CreateOrg(ctx, sqlc.CreateOrgParams{ID: "org1", Name: "Acme", Slug: "acme", Context: "", Visibility: "private"})
	if err != nil {
		t.Fatalf("seed org: %v", err)
	}
	_, err = q.CreateProvider(ctx, sqlc.CreateProviderParams{ID: "prov1", Kind: "openai-compatible", Name: "Test", BaseUrl: "https://test/v1", KeyEnc: nil, ModelsJson: `["gpt-4o"]`})
	if err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	// Role grants task.list; skill allows task.list → effective grant.
	_, err = q.CreateRole(ctx, sqlc.CreateRoleParams{ID: "role1", OrgID: org.ID, Name: "Editor", IsSystem: 0, GrantsJson: `["task.list"]`})
	if err != nil {
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
	seedSkillRaw(t, db, "sk1", org.ID, "reader", "Read tasks.", `["task.list"]`)
	if err := q.CreateAgentSkill(ctx, sqlc.CreateAgentSkillParams{AgentID: agent.ID, SkillID: "sk1", ID: agent.ID, OrgID: sql.NullString{String: org.ID, Valid: true}}); err != nil {
		t.Fatalf("attach skill: %v", err)
	}

	eng := New(Config{DB: db, Client: fp, Secret: "test-secret", EventSink: nil})
	return eng, agent, org.ID
}

// seedRun inserts a queued run row for the engine.
func seedRun(t *testing.T, eng *Engine, agentID, orgID string) sqlc.Run {
	t.Helper()
	ctx := context.Background()
	run, err := eng.q.CreateRun(ctx, sqlc.CreateRunParams{
		ID: "run1", OrgID: orgID, AgentID: agentID, Trigger: "manual",
		TaskID:        sql.NullString{},
		ChatSessionID: sql.NullString{},
		InitiatedBy:   sql.NullString{String: "u1", Valid: true},
		Status:        "queued",
	})
	if err != nil {
		t.Fatalf("seed run: %v", err)
	}
	return run
}

// TestToolLoopHappyMultiTool drives a two-step loop: the model calls the echo
// tool, receives the result, then finishes. It asserts the tool result was fed
// back (second request carries a tool message) and the loop finished cleanly.
func TestToolLoopHappyMultiTool(t *testing.T) {
	fp := &fakeProvider{model: "gpt-4o", steps: []client.CompletionResponse{
		step(toolCall("agentrt.test.echo", `{"a":1}`)),
	}}
	eng, agent, orgID := buildEngine(t, fp)
	ctx := context.Background()

	run := seedRun(t, eng, agent.ID, orgID)
	out, err := runToolLoop(ctx, eng, run, agent, "hello", nil)
	if err != nil {
		t.Fatalf("tool loop: %v", err)
	}
	if out.cancelled || out.stepCapped || out.approvalPending {
		t.Fatalf("unexpected outcome: %+v", out)
	}
	// Second request must include the tool result message.
	got := fp.seen
	if len(got) < 2 {
		t.Fatalf("expected 2 model calls, got %d", len(got))
	}
	var hasToolMsg bool
	for _, m := range got[1].Messages {
		if m.Role == "tool" && m.Content != "" {
			hasToolMsg = true
			break
		}
	}
	if !hasToolMsg {
		t.Fatalf("second request lacks tool result message: %+v", got[1].Messages)
	}
	// run_steps recorded (model + tool kinds).
	steps, err := eng.q.ListRunSteps(ctx, sqlc.ListRunStepsParams{RunID: run.ID, OrgID: orgID})
	if err != nil {
		t.Fatalf("list steps: %v", err)
	}
	if len(steps) < 2 {
		t.Fatalf("expected >=2 run_steps, got %d", len(steps))
	}
}

// TestToolLoopPermDenied: the agent has NO effective perms (role grant
// revoked), so no tools are exposed. A hallucinated tool call to the echo
// action is gated by the dispatcher's agent perm checker → forbidden →
// surfaced to the model as a tool error, and the loop continues.
func TestToolLoopPermDenied(t *testing.T) {
	fp := &fakeProvider{model: "gpt-4o", steps: []client.CompletionResponse{
		step(toolCall("agentrt.test.echo", `{"a":1}`)),
	}}
	// Revoke the role grant: empty grants → effective perms empty.
	eng, agent, orgID := buildEngine(t, fp)
	ctx := context.Background()
	_, err := eng.q.UpdateRoleGrants(ctx, sqlc.UpdateRoleGrantsParams{
		GrantsJson: "[]", ID: "role1", OrgID: orgID,
	})
	if err != nil {
		t.Fatalf("revoke role grants: %v", err)
	}

	run := seedRun(t, eng, agent.ID, orgID)
	out, err := runToolLoop(ctx, eng, run, agent, "hi", nil)
	if err != nil {
		t.Fatalf("tool loop: %v", err)
	}
	if out.approvalPending {
		t.Fatalf("perm-denied must not be approval-pending")
	}
	// The hallucinated call must have produced a tool error surfaced to the
	// model (second request carries a tool message with an error).
	var sawErr bool
	for _, req := range fp.seen[1:] {
		for _, m := range req.Messages {
			if m.Role == "tool" && m.Content != "" {
				sawErr = true
			}
		}
	}
	if !sawErr {
		t.Fatalf("no tool error surfaced to the model")
	}
}

// TestToolLoopStepCap: the fake keeps returning tool_calls forever; the loop
// must stop at MaxStepsPerRun and report stepCapped.
func TestToolLoopStepCap(t *testing.T) {
	fp := &fakeProvider{
		model:  "gpt-4o",
		repeat: step(toolCall("nonexistent.tool", `{}`)),
	}
	eng, agent, orgID := buildEngine(t, fp)
	ctx := context.Background()
	run := seedRun(t, eng, agent.ID, orgID)

	out, err := runToolLoop(ctx, eng, run, agent, "loop", nil)
	if err != nil {
		t.Fatalf("tool loop: %v", err)
	}
	if !out.stepCapped {
		t.Fatalf("expected step cap, got %+v", out)
	}
	// The nonexistent tool errors fast, so the loop burned exactly its
	// step budget of model calls.
	if len(fp.seen) != MaxStepsPerRun {
		t.Fatalf("expected %d model calls, got %d", MaxStepsPerRun, len(fp.seen))
	}
}

// TestToolLoopCancel: a pre-set cancel flag must abort before any step.
func TestToolLoopCancel(t *testing.T) {
	fp := &fakeProvider{model: "gpt-4o"}
	eng, agent, orgID := buildEngine(t, fp)
	ctx := context.Background()
	run := seedRun(t, eng, agent.ID, orgID)

	cancel := newCancelFlag()
	cancel.cancel()
	out, err := runToolLoop(ctx, eng, run, agent, "hi", cancel)
	if err != nil {
		t.Fatalf("tool loop: %v", err)
	}
	if !out.cancelled {
		t.Fatalf("expected cancelled outcome")
	}
}

// TestRunHandlerRetryNotify exercises the full job-pool Handler: a provider
// failure on an agent with RetryMax=0 (no retries) must mark the run failed,
// mark the job dead, and create a run.failed notification (SPEC §10
// failure→retry→notify). The notification is addressed to the initiating user.
func TestRunHandlerRetryNotify(t *testing.T) {
	fp := &fakeProvider{model: "gpt-4o", fail: errors.New("upstream down")}
	eng, agent, orgID := buildEngine(t, fp)
	ctx := context.Background()

	// No retries: RetryMax 0.
	if _, err := eng.q.UpdateAgent(ctx, sqlc.UpdateAgentParams{
		Name: agent.Name, ProviderID: agent.ProviderID, Model: agent.Model, Context: agent.Context,
		RoleID: agent.RoleID, RetryMax: 0, BackoffSecs: agent.BackoffSecs,
		RunsPerHour: agent.RunsPerHour, TokenBudget: agent.TokenBudget,
		ApprovalPolicyJson: agent.ApprovalPolicyJson, Active: agent.Active,
		ID: agent.ID, OrgID: agent.OrgID,
	}); err != nil {
		t.Fatalf("set retry 0: %v", err)
	}

	// Seed a user + run initiated by that user (so notify has an addressee).
	if _, err := eng.db.Exec(`INSERT INTO users (id, email, name) VALUES ('u1','u1@acme.test','U1')`); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	run := seedRun(t, eng, agent.ID, orgID)

	// Enqueue a run job; maxAttempts must be >=1 so the job row is valid.
	store := job.NewJobStore(eng.db)
	if err := store.Enqueue(ctx, "job1", "run", mustJSON(runJob{RunID: run.ID, OrgID: orgID}), "2026-08-09T00:00:00Z", 1); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	queued, err := store.ListQueued(ctx)
	if err != nil {
		t.Fatalf("list queued: %v", err)
	}
	if len(queued) != 1 || queued[0].ID != "job1" {
		t.Fatalf("expected job1 queued, got %+v", queued)
	}
	job := queued[0]

	if err := eng.Handler(store)(ctx, job); err != nil {
		t.Fatalf("handler: %v", err)
	}

	// Run must be failed.
	gotRun, err := eng.q.FindRunByID(ctx, sqlc.FindRunByIDParams{ID: run.ID, OrgID: orgID})
	if err != nil {
		t.Fatalf("find run: %v", err)
	}
	if gotRun.Status != "failed" {
		t.Fatalf("expected run failed, got %q", gotRun.Status)
	}
	// Job must be dead (retries exhausted).
	dead, err := store.ListDead(ctx)
	if err != nil {
		t.Fatalf("list dead: %v", err)
	}
	if len(dead) != 1 || dead[0].ID != "job1" {
		t.Fatalf("expected job1 dead, got %+v", dead)
	}
	// Notification created for the initiating user.
	notifs, err := eng.q.ListNotifications(ctx, sqlc.ListNotificationsParams{UserID: "u1", Limit: 10, Offset: 0})
	if err != nil {
		t.Fatalf("list notifs: %v", err)
	}
	if len(notifs) != 1 || notifs[0].EventName != "run.failed" {
		t.Fatalf("expected 1 run.failed notification, got %+v", notifs)
	}
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}
