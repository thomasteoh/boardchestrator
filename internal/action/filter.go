package action

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

type savedFilterCreateInput struct {
	ProjectID string `json:"project_id"`
	Name      string `json:"name"`
	QueryJSON string `json:"query_json"`
	Pinned    bool   `json:"pinned"`
}

type savedFilterUpdateInput struct {
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`
	Name      string `json:"name"`
	QueryJSON string `json:"query_json"`
	Pinned    bool   `json:"pinned"`
}

type savedFilterDeleteInput struct {
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`
}

type taskBulkAssignInput struct {
	ProjectID string   `json:"project_id"`
	TaskIDs   []string `json:"task_ids"`
	UserIDs   []string `json:"user_ids"`
}

type taskBulkLabelInput struct {
	ProjectID string   `json:"project_id"`
	TaskIDs   []string `json:"task_ids"`
	LabelIDs  []string `json:"label_ids"`
}

type taskBulkMoveInput struct {
	ProjectID string   `json:"project_id"`
	TaskIDs   []string `json:"task_ids"`
	ToStatus  string   `json:"to_status"`
}

func init() {
	Register(Definition{
		Name:       "saved_filter.create",
		Impact:     ImpactLow,
		Permission: "saved_filter.create",
		Scope:      ScopeProject,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleSavedFilterCreate,
	})
	Register(Definition{
		Name:       "saved_filter.update",
		Impact:     ImpactLow,
		Permission: "saved_filter.update",
		Scope:      ScopeProject,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleSavedFilterUpdate,
	})
	Register(Definition{
		Name:       "saved_filter.delete",
		Impact:     ImpactLow,
		Permission: "saved_filter.delete",
		Scope:      ScopeProject,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleSavedFilterDelete,
	})
	Register(Definition{
		Name:       "task.bulk_assign",
		Impact:     ImpactLow,
		Permission: "task.assign",
		Scope:      ScopeProject,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleTaskBulkAssign,
	})
	Register(Definition{
		Name:       "task.bulk_label",
		Impact:     ImpactLow,
		Permission: "task.label",
		Scope:      ScopeProject,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleTaskBulkLabel,
	})
	Register(Definition{
		Name:       "task.bulk_move",
		Impact:     ImpactLow,
		Permission: "task.move",
		Scope:      ScopeProject,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleTaskBulkMove,
	})
}

func handleSavedFilterCreate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input savedFilterCreateInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("saved_filter.create: %w", err)
	}
	filter, err := ac.Tx.CreateSavedFilter(ctx, sqlc.CreateSavedFilterParams{
		ID:        newID(),
		ProjectID: input.ProjectID,
		Name:      input.Name,
		QueryJson: input.QueryJSON,
		Pinned:    boolToInt(input.Pinned),
		CreatedBy: ac.Actor.ref(),
	})
	if err != nil {
		return nil, fmt.Errorf("saved_filter.create: %w", err)
	}
	return filter, nil
}

func handleSavedFilterUpdate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input savedFilterUpdateInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("saved_filter.update: %w", err)
	}
	filter, err := ac.Tx.UpdateSavedFilter(ctx, sqlc.UpdateSavedFilterParams{
		ID:        input.ID,
		ProjectID: input.ProjectID,
		Name:      input.Name,
		QueryJson: input.QueryJSON,
		Pinned:    boolToInt(input.Pinned),
		UpdatedAt: timestamp(),
	})
	if err != nil {
		return nil, fmt.Errorf("saved_filter.update: %w", err)
	}
	return filter, nil
}

func handleSavedFilterDelete(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input savedFilterDeleteInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("saved_filter.delete: %w", err)
	}
	if err := ac.Tx.DeleteSavedFilter(ctx, sqlc.DeleteSavedFilterParams{
		ID:        input.ID,
		ProjectID: input.ProjectID,
	}); err != nil {
		return nil, fmt.Errorf("saved_filter.delete: %w", err)
	}
	return map[string]string{"id": input.ID}, nil
}

func handleTaskBulkAssign(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input taskBulkAssignInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("task.bulk_assign: %w", err)
	}
	for _, tid := range input.TaskIDs {
		if err := ac.Tx.ClearTaskAssignees(ctx, sqlc.ClearTaskAssigneesParams{
			TaskID:    tid,
			ProjectID: input.ProjectID,
		}); err != nil {
			return nil, fmt.Errorf("task.bulk_assign clear: %w", err)
		}
		for _, uid := range input.UserIDs {
			if err := ac.Tx.AddTaskAssignee(ctx, sqlc.AddTaskAssigneeParams{
				TaskID:    tid,
				ProjectID: input.ProjectID,
				UserID:    uid,
			}); err != nil {
				return nil, fmt.Errorf("task.bulk_assign add: %w", err)
			}
		}
		logActivity(ctx, ac, tid, input.ProjectID, "task.assign",
			map[string]any{"user_ids": input.UserIDs})
	}
	return map[string]any{"count": len(input.TaskIDs)}, nil
}

func handleTaskBulkLabel(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input taskBulkLabelInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("task.bulk_label: %w", err)
	}
	for _, tid := range input.TaskIDs {
		if err := ac.Tx.ClearTaskLabels(ctx, sqlc.ClearTaskLabelsParams{
			TaskID:    tid,
			ProjectID: input.ProjectID,
		}); err != nil {
			return nil, fmt.Errorf("task.bulk_label clear: %w", err)
		}
		for _, lid := range input.LabelIDs {
			if err := ac.Tx.AddTaskLabel(ctx, sqlc.AddTaskLabelParams{
				TaskID:    tid,
				ProjectID: input.ProjectID,
				LabelID:   lid,
			}); err != nil {
				return nil, fmt.Errorf("task.bulk_label add: %w", err)
			}
		}
		logActivity(ctx, ac, tid, input.ProjectID, "task.label",
			map[string]any{"label_ids": input.LabelIDs})
	}
	return map[string]any{"count": len(input.TaskIDs)}, nil
}

func handleTaskBulkMove(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input taskBulkMoveInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("task.bulk_move: %w", err)
	}
	count := 0
	for _, tid := range input.TaskIDs {
		_, err := ac.Tx.MoveTask(ctx, sqlc.MoveTaskParams{
			ID:        tid,
			ProjectID: input.ProjectID,
			Status:    input.ToStatus,
			SortOrder: 0,
			UpdatedAt: timestamp(),
		})
		if err != nil {
			return nil, fmt.Errorf("task.bulk_move: %w", err)
		}
		logActivity(ctx, ac, tid, input.ProjectID, "task.move",
			map[string]any{"to_status": input.ToStatus})
		count++
	}
	return map[string]any{"count": count}, nil
}

// boolToInt converts bool to int for sqlite storage.
func boolToInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// logActivity writes an activity row without failing on error.
func logActivity(ctx context.Context, ac ActionCtx, taskID, projectID, action string, detail map[string]any) {
	d, _ := json.Marshal(detail)
	ac.Tx.CreateTaskActivity(ctx, sqlc.CreateTaskActivityParams{
		ID:         newID(),
		TaskID:     taskID,
		ProjectID:  projectID,
		ActorID:    ac.Actor.ref(),
		ActorType:  string(ac.Actor.Type),
		Action:     action,
		DetailJson: string(d),
	})
}
