package action

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

type sprintCreateInput struct {
	ProjectID string `json:"project_id"`
	Name      string `json:"name"`
	StartsOn  string `json:"starts_on"`
	EndsOn    string `json:"ends_on"`
}

type sprintUpdateInput struct {
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`
	Name      string `json:"name"`
	StartsOn  string `json:"starts_on"`
	EndsOn    string `json:"ends_on"`
}

type sprintCloseInput struct {
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`
}

type sprintAddTaskInput struct {
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`
	TaskID    string `json:"task_id"`
}

type sprintRemoveTaskInput struct {
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`
	TaskID    string `json:"task_id"`
}

func init() {
	Register(Definition{
		Name:       "sprint.create",
		Impact:     ImpactLow,
		Permission: "sprint.create",
		Scope:      ScopeProject,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleSprintCreate,
	})
	Register(Definition{
		Name:       "sprint.update",
		Impact:     ImpactLow,
		Permission: "sprint.update",
		Scope:      ScopeProject,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleSprintUpdate,
	})
	Register(Definition{
		Name:       "sprint.close",
		Impact:     ImpactHigh,
		Permission: "sprint.close",
		Scope:      ScopeProject,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleSprintClose,
	})
	Register(Definition{
		Name:       "sprint.add_task",
		Impact:     ImpactLow,
		Permission: "sprint.add_task",
		Scope:      ScopeProject,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleSprintAddTask,
	})
	Register(Definition{
		Name:       "sprint.remove_task",
		Impact:     ImpactLow,
		Permission: "sprint.remove_task",
		Scope:      ScopeProject,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleSprintRemoveTask,
	})
}

func RegisterSprintActions() {}

func handleSprintCreate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input sprintCreateInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("sprint.create: %w", err)
	}
	sprint, err := ac.Tx.CreateSprint(ctx, sqlc.CreateSprintParams{
		ID:        newID(),
		OrgID:     ac.Org,
		ProjectID: input.ProjectID,
		Name:      input.Name,
		StartsOn:  input.StartsOn,
		EndsOn:    input.EndsOn,
		State:     "active",
	})
	if err != nil {
		return nil, fmt.Errorf("sprint.create: %w", err)
	}
	return sprint, nil
}

func handleSprintUpdate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input sprintUpdateInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("sprint.update: %w", err)
	}
	sprint, err := ac.Tx.UpdateSprint(ctx, sqlc.UpdateSprintParams{
		Name:      input.Name,
		StartsOn:  input.StartsOn,
		EndsOn:    input.EndsOn,
		State:     "active",
		ID:        input.ID,
		ProjectID: input.ProjectID,
	})
	if err != nil {
		return nil, fmt.Errorf("sprint.update: %w", err)
	}
	return sprint, nil
}

func handleSprintClose(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input sprintCloseInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("sprint.close: %w", err)
	}

	// Close the sprint.
	if _, err := ac.Tx.CloseSprint(ctx, sqlc.CloseSprintParams{
		ID:        input.ID,
		ProjectID: input.ProjectID,
	}); err != nil {
		return nil, fmt.Errorf("sprint.close: %w", err)
	}

	// Find tasks still in sprint — move them to backlog.
	openTasks, err := ac.Tx.ListTasksByProject(ctx, input.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("sprint.close: list tasks: %w", err)
	}
	moved := 0
	for _, t := range openTasks {
		if t.SprintID.Valid && t.SprintID.String == input.ID {
			if err := ac.Tx.SetTaskSprint(ctx, sqlc.SetTaskSprintParams{
				SprintID: sql.NullString{Valid: false},
				ID:       t.ID,
				ProjectID: input.ProjectID,
			}); err != nil {
				return nil, fmt.Errorf("sprint.close: clear task %s sprint: %w", t.ID, err)
			}
			logActivity(ctx, ac, t.ID, input.ProjectID, "sprint.clear",
				map[string]any{"sprint_id": input.ID})
			moved++
		}
	}

	return map[string]any{"id": input.ID, "moved": moved}, nil
}

func handleSprintAddTask(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input sprintAddTaskInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("sprint.add_task: %w", err)
	}
	if err := ac.Tx.SetTaskSprint(ctx, sqlc.SetTaskSprintParams{
		SprintID: sql.NullString{String: input.ID, Valid: true},
		ID:       input.TaskID,
		ProjectID: input.ProjectID,
	}); err != nil {
		return nil, fmt.Errorf("sprint.add_task: %w", err)
	}
	logActivity(ctx, ac, input.TaskID, input.ProjectID, "sprint.add",
		map[string]any{"sprint_id": input.ID})
	return map[string]string{"id": input.ID}, nil
}

func handleSprintRemoveTask(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input sprintRemoveTaskInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("sprint.remove_task: %w", err)
	}
	if err := ac.Tx.SetTaskSprint(ctx, sqlc.SetTaskSprintParams{
		SprintID: sql.NullString{Valid: false},
		ID:       input.TaskID,
		ProjectID: input.ProjectID,
	}); err != nil {
		return nil, fmt.Errorf("sprint.remove_task: %w", err)
	}
	logActivity(ctx, ac, input.TaskID, input.ProjectID, "sprint.remove",
		map[string]any{"sprint_id": input.ID})
	return map[string]string{"id": input.ID}, nil
}
