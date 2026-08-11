package agentrt

import (
	"context"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/client"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/job"
)

// TestEnqueueRunPerTaskCap asserts the concurrent-run cap: a task with an
// active run is skipped, a task with only terminal runs accepts a new run.
func TestEnqueueRunPerTaskCap(t *testing.T) {
	fp := &fakeProvider{model: "gpt-4o", steps: []client.CompletionResponse{
		step(toolCall("agentrt.test.echo", `{"name":"x"}`)),
	}}
	eng, agent, orgID := buildEngine(t, fp)
	ctx := context.Background()

	// Seed a task so the cap query has a real task_id to filter on.
	proj, err := eng.q.CreateProject(ctx, sqlc.CreateProjectParams{
		ID: "proj1", OrgID: orgID, Name: "P", Key: "P1", Visibility: "private",
	})
	if err != nil {
		t.Fatalf("seed project: %v", err)
	}
	task, err := eng.q.CreateTask(ctx, sqlc.CreateTaskParams{
		ID: "task1", ProjectID: proj.ID, Title: "T", Description: "", Key: "P1-1",
		KeyNum: 1, Points: 0, Priority: 0, Status: "todo", DueAt: "", SortOrder: 0,
	})
	if err != nil {
		t.Fatalf("seed task: %v", err)
	}

	store := job.NewJobStore(eng.db)

	// First trigger creates a run + enqueues a job.
	runID1, created1, err := eng.EnqueueRun(ctx, store, orgID, agent.ID, "mention", task.ID, "", proj.ID, "u1", "@robo")
	if err != nil {
		t.Fatalf("enqueue run 1: %v", err)
	}
	if !created1 || runID1 == "" {
		t.Fatalf("expected first trigger to create a run, created=%v", created1)
	}

	// Second trigger for the same task is skipped (cap 1).
	runID2, created2, err := eng.EnqueueRun(ctx, store, orgID, agent.ID, "mention", task.ID, "", proj.ID, "u1", "@robo")
	if err != nil {
		t.Fatalf("enqueue run 2: %v", err)
	}
	if created2 {
		t.Fatalf("expected second trigger to be skipped, run=%s", runID2)
	}

	// A different task accepts a new run (cap is per-task, not per-agent).
	// It lives in a different project so the per-project overlap guard (WU-309)
	// doesn't also block it.
	store2 := job.NewJobStore(eng.db)
	proj2, err := eng.q.CreateProject(ctx, sqlc.CreateProjectParams{
		ID: "proj2", OrgID: orgID, Name: "P2", Key: "P2", Visibility: "private",
	})
	if err != nil {
		t.Fatalf("seed project2: %v", err)
	}
	task2, err := eng.q.CreateTask(ctx, sqlc.CreateTaskParams{
		ID: "task2", ProjectID: proj2.ID, Title: "T2", Description: "", Key: "P2-1",
		KeyNum: 1, Points: 0, Priority: 0, Status: "todo", DueAt: "", SortOrder: 0,
	})
	if err != nil {
		t.Fatalf("seed task2: %v", err)
	}
	if _, created, err := eng.EnqueueRun(ctx, store2, orgID, agent.ID, "mention", task2.ID, "", proj2.ID, "u1", "@robo"); err != nil || !created {
		t.Fatalf("expected task2 trigger to create, created=%v err=%v", created, err)
	}

	// Mark task1's run terminal, then a new trigger is accepted.
	store3 := job.NewJobStore(eng.db)
	if _, err := eng.q.FinishRun(ctx, sqlc.FinishRunParams{
		ID: runID1, OrgID: orgID, Status: "succeeded", Error: "",
	}); err != nil {
		t.Fatalf("finish run1: %v", err)
	}
	if _, created, err := eng.EnqueueRun(ctx, store3, orgID, agent.ID, "column", task.ID, "", proj.ID, "", "prompt"); err != nil || !created {
		t.Fatalf("expected re-trigger after terminal to create, created=%v err=%v", created, err)
	}
}

// TestEnqueueRunInstructionThreads asserts the trigger instruction is carried
// in the job payload and passed into the run loop (Handler → executeRun).
func TestEnqueueRunInstructionThreads(t *testing.T) {
	fp := &fakeProvider{model: "gpt-4o", steps: []client.CompletionResponse{
		step(toolCall("agentrt.test.echo", `{"name":"x"}`)),
	}}
	eng, agent, orgID := buildEngine(t, fp)
	ctx := context.Background()

	store := job.NewJobStore(eng.db)
	runID, created, err := eng.EnqueueRun(ctx, store, orgID, agent.ID, "column", "", "", "", "", "Triage {title}")
	if err != nil || !created {
		t.Fatalf("enqueue run: %v created=%v", err, created)
	}

	// Drive the Handler on the enqueued job (its id == runID). It must not fail
	// on the instruction path.
	if err := eng.Handler(store)(ctx, mustJob(t, store, runID)); err != nil {
		t.Fatalf("handler: %v", err)
	}
	got, err := eng.q.FindRunByID(ctx, sqlc.FindRunByIDParams{ID: runID, OrgID: orgID})
	if err != nil {
		t.Fatalf("find run: %v", err)
	}
	if got.Status == "failed" || got.Status == "awaiting_approval" {
		t.Fatalf("run ended %q, want clean finish", got.Status)
	}
}
