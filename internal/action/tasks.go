package action

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// --- Action definitions for task CRUD ---

type taskCreateInput struct {
	ProjectID   string  `json:"project_id"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	Points      int     `json:"points"`
	Priority    int     `json:"priority"`
	Status      string  `json:"status"`
	DueAt       string  `json:"due_at"`
}

type taskUpdateInput struct {
	ID          string  `json:"id"`
	ProjectID   string  `json:"project_id"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	Points      int     `json:"points"`
	Priority    int     `json:"priority"`
	Status      string  `json:"status"`
	DueAt       string  `json:"due_at"`
}

type taskAssignInput struct {
	ID        string   `json:"id"`
	ProjectID string   `json:"project_id"`
	UserIDs   []string `json:"user_ids"`
}

type taskLabelInput struct {
	ID        string   `json:"id"`
	ProjectID string   `json:"project_id"`
	LabelIDs  []string `json:"label_ids"`
}

type taskRelateInput struct {
	ID            string `json:"id"`
	ProjectID     string `json:"project_id"`
	RelatedTaskID string `json:"related_task_id"`
	RelationType  string `json:"relation_type"`
}

type taskArchiveInput struct {
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`
}

type taskMoveInput struct {
	ID        string  `json:"id"`
	ProjectID string  `json:"project_id"`
	ToStatus  string  `json:"to_status"`
	SortOrder float64 `json:"sort_order"`
}

type labelCreateInput struct {
	OrgID       string `json:"org_id"`
	Name        string `json:"name"`
	Color       string `json:"color"`
	Description string `json:"description"`
}

type labelUpdateInput struct {
	ID          string `json:"id"`
	OrgID       string `json:"org_id"`
	Name        string `json:"name"`
	Color       string `json:"color"`
	Description string `json:"description"`
}

func init() {
	Register(Definition{
		Name:       "task.create",
		Impact:     ImpactLow,
		Permission: "task.create",
		Scope:      ScopeProject,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleTaskCreate,
	})
	Register(Definition{
		Name:       "task.update",
		Impact:     ImpactLow,
		Permission: "task.update",
		Scope:      ScopeProject,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleTaskUpdate,
	})
	Register(Definition{
		Name:       "task.assign",
		Impact:     ImpactLow,
		Permission: "task.assign",
		Scope:      ScopeProject,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleTaskAssign,
	})
	Register(Definition{
		Name:       "task.label",
		Impact:     ImpactLow,
		Permission: "task.label",
		Scope:      ScopeProject,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleTaskLabel,
	})
	Register(Definition{
		Name:       "task.relate",
		Impact:     ImpactLow,
		Permission: "task.relate",
		Scope:      ScopeProject,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleTaskRelate,
	})
	Register(Definition{
		Name:       "task.archive",
		Impact:     ImpactHigh,
		Permission: "task.archive",
		Scope:      ScopeProject,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleTaskArchive,
	})
	Register(Definition{
		Name:       "task.unarchive",
		Impact:     ImpactHigh,
		Permission: "task.unarchive",
		Scope:      ScopeProject,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleTaskUnarchive,
	})
	Register(Definition{
		Name:       "task.move",
		Impact:     ImpactLow,
		Permission: "task.move",
		Scope:      ScopeProject,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleTaskMove,
	})
	Register(Definition{
		Name:       "label.create",
		Impact:     ImpactLow,
		Permission: "label.create",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleLabelCreate,
	})
	Register(Definition{
		Name:       "label.update",
		Impact:     ImpactLow,
		Permission: "label.update",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleLabelUpdate,
	})
}

// RegisterTaskActions exported so cmd/bc/serve.go can ensure init() runs.
func RegisterTaskActions() {}

func handleTaskCreate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input taskCreateInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("task.create: %w", err)
	}

	// Allocate key number transaction-safe.
	next, err := ac.Tx.NextTaskNum(ctx, input.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("task.create: next task num: %w", err)
	}
	key := fmt.Sprintf("%s-%d", projectKeyFromID(input.ProjectID), next)
	id := newID()

	_, err = ac.Tx.CreateTask(ctx, sqlc.CreateTaskParams{
		ID:          id,
		ProjectID:   input.ProjectID,
		Title:       input.Title,
		Description: input.Description,
		Key:         key,
		KeyNum:      next,
		Points:      int64(input.Points),
		Priority:    int64(input.Priority),
		Status:      input.Status,
		DueAt:       input.DueAt,
		SortOrder:   float64(next),
	})
	if err != nil {
		return nil, fmt.Errorf("task.create: %w", err)
	}

	detail, _ := json.Marshal(map[string]any{"title": input.Title, "key": key})
	_, _ = ac.Tx.CreateTaskActivity(ctx, sqlc.CreateTaskActivityParams{
		ID:         newID(),
		TaskID:     id,
		ProjectID:  input.ProjectID,
		ActorID:    ac.Actor.ref(),
		ActorType:  string(ac.Actor.Type),
		Action:     "task.create",
		DetailJson: string(detail),
	})

	return map[string]any{"id": id, "key": key}, nil
}

func handleTaskUpdate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input taskUpdateInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("task.update: %w", err)
	}

	ts := timestamp()
	_, err := ac.Tx.UpdateTask(ctx, sqlc.UpdateTaskParams{
		Title:       input.Title,
		Description: input.Description,
		Points:      int64(input.Points),
		Priority:    int64(input.Priority),
		DueAt:       input.DueAt,
		SortOrder:   0,
		Status:      input.Status,
		UpdatedAt:   ts,
		ID:          input.ID,
		ProjectID:   input.ProjectID,
	})
	if err != nil {
		return nil, fmt.Errorf("task.update: %w", err)
	}

	detail, _ := json.Marshal(map[string]any{"title": input.Title})
	_, _ = ac.Tx.CreateTaskActivity(ctx, sqlc.CreateTaskActivityParams{
		ID:         newID(),
		TaskID:     input.ID,
		ProjectID:  input.ProjectID,
		ActorID:    ac.Actor.ref(),
		ActorType:  string(ac.Actor.Type),
		Action:     "task.update",
		DetailJson: string(detail),
	})

	return map[string]string{"id": input.ID}, nil
}

func handleTaskAssign(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input taskAssignInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("task.assign: %w", err)
	}
	// Clear existing, then add each.
	if err := ac.Tx.ClearTaskAssignees(ctx, sqlc.ClearTaskAssigneesParams{
		TaskID:    input.ID,
		ProjectID: input.ProjectID,
	}); err != nil {
		return nil, fmt.Errorf("task.assign: clear: %w", err)
	}
	for _, uid := range input.UserIDs {
		if err := ac.Tx.AddTaskAssignee(ctx, sqlc.AddTaskAssigneeParams{
			TaskID:    input.ID,
			ProjectID: input.ProjectID,
			UserID:    uid,
		}); err != nil {
			return nil, fmt.Errorf("task.assign: add %s: %w", uid, err)
		}
	}
	detail, _ := json.Marshal(map[string]any{"user_ids": input.UserIDs})
	_, _ = ac.Tx.CreateTaskActivity(ctx, sqlc.CreateTaskActivityParams{
		ID:         newID(),
		TaskID:     input.ID,
		ProjectID:  input.ProjectID,
		ActorID:    ac.Actor.ref(),
		ActorType:  string(ac.Actor.Type),
		Action:     "task.assign",
		DetailJson: string(detail),
	})
	return map[string]string{"id": input.ID}, nil
}

func handleTaskLabel(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input taskLabelInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("task.label: %w", err)
	}
	if err := ac.Tx.ClearTaskLabels(ctx, sqlc.ClearTaskLabelsParams{
		TaskID:    input.ID,
		ProjectID: input.ProjectID,
	}); err != nil {
		return nil, fmt.Errorf("task.label: clear: %w", err)
	}
	for _, lid := range input.LabelIDs {
		if err := ac.Tx.AddTaskLabel(ctx, sqlc.AddTaskLabelParams{
			TaskID:    input.ID,
			ProjectID: input.ProjectID,
			LabelID:   lid,
		}); err != nil {
			return nil, fmt.Errorf("task.label: add %s: %w", lid, err)
		}
	}
	detail, _ := json.Marshal(map[string]any{"label_ids": input.LabelIDs})
	_, _ = ac.Tx.CreateTaskActivity(ctx, sqlc.CreateTaskActivityParams{
		ID:         newID(),
		TaskID:     input.ID,
		ProjectID:  input.ProjectID,
		ActorID:    ac.Actor.ref(),
		ActorType:  string(ac.Actor.Type),
		Action:     "task.label",
		DetailJson: string(detail),
	})
	return map[string]string{"id": input.ID}, nil
}

func handleTaskRelate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input taskRelateInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("task.relate: %w", err)
	}
	if input.ID == input.RelatedTaskID {
		return nil, fmt.Errorf("task.relate: self-reference not allowed")
	}
	rid := newID()
	_, err := ac.Tx.CreateTaskRelation(ctx, sqlc.CreateTaskRelationParams{
		ID:            rid,
		TaskID:        input.ID,
		RelatedTaskID: input.RelatedTaskID,
		RelationType:  input.RelationType,
		ProjectID:     input.ProjectID,
	})
	if err != nil {
		return nil, fmt.Errorf("task.relate: %w", err)
	}
	detail, _ := json.Marshal(map[string]any{"related": input.RelatedTaskID, "type": input.RelationType})
	_, _ = ac.Tx.CreateTaskActivity(ctx, sqlc.CreateTaskActivityParams{
		ID:         newID(),
		TaskID:     input.ID,
		ProjectID:  input.ProjectID,
		ActorID:    ac.Actor.ref(),
		ActorType:  string(ac.Actor.Type),
		Action:     "task.relate",
		DetailJson: string(detail),
	})
	return map[string]string{"id": rid}, nil
}

func handleTaskArchive(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input taskArchiveInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("task.archive: %w", err)
	}
	if err := ac.Tx.ArchiveTask(ctx, sqlc.ArchiveTaskParams{
		UpdatedAt: timestamp(),
		ID:        input.ID,
		ProjectID: input.ProjectID,
	}); err != nil {
		return nil, fmt.Errorf("task.archive: %w", err)
	}
	_, _ = ac.Tx.CreateTaskActivity(ctx, sqlc.CreateTaskActivityParams{
		ID:         newID(),
		TaskID:     input.ID,
		ProjectID:  input.ProjectID,
		ActorID:    ac.Actor.ref(),
		ActorType:  string(ac.Actor.Type),
		Action:     "task.archive",
		DetailJson: "{}",
	})
	return map[string]string{"id": input.ID}, nil
}

func handleTaskUnarchive(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input taskArchiveInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("task.unarchive: %w", err)
	}
	if err := ac.Tx.UnarchiveTask(ctx, sqlc.UnarchiveTaskParams{
		UpdatedAt: timestamp(),
		ID:        input.ID,
		ProjectID: input.ProjectID,
	}); err != nil {
		return nil, fmt.Errorf("task.unarchive: %w", err)
	}
	_, _ = ac.Tx.CreateTaskActivity(ctx, sqlc.CreateTaskActivityParams{
		ID:         newID(),
		TaskID:     input.ID,
		ProjectID:  input.ProjectID,
		ActorID:    ac.Actor.ref(),
		ActorType:  string(ac.Actor.Type),
		Action:     "task.unarchive",
		DetailJson: "{}",
	})
	return map[string]string{"id": input.ID}, nil
}

func handleTaskMove(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input taskMoveInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("task.move: %w", err)
	}

	// If to_status is the same as current, just reorder within column.
	// Otherwise move to new column at the given sort order.
	task, err := ac.Tx.MoveTask(ctx, sqlc.MoveTaskParams{
		Status:    input.ToStatus,
		SortOrder: input.SortOrder,
		UpdatedAt: timestamp(),
		ID:        input.ID,
		ProjectID: input.ProjectID,
	})
	if err != nil {
		return nil, fmt.Errorf("task.move: %w", err)
	}

	detail, _ := json.Marshal(map[string]any{
		"to_status": task.Status,
		"sort_order": input.SortOrder,
	})
	_, _ = ac.Tx.CreateTaskActivity(ctx, sqlc.CreateTaskActivityParams{
		ID:         newID(),
		TaskID:     input.ID,
		ProjectID:  input.ProjectID,
		ActorID:    ac.Actor.ref(),
		ActorType:  string(ac.Actor.Type),
		Action:     "task.move",
		DetailJson: string(detail),
	})
	return map[string]any{"id": input.ID, "status": task.Status}, nil
}

func handleLabelCreate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input labelCreateInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("label.create: %w", err)
	}
	id := newID()
	_, err := ac.Tx.CreateLabel(ctx, sqlc.CreateLabelParams{
		ID:          id,
		OrgID:       input.OrgID,
		Name:        input.Name,
		Color:       input.Color,
		Description: input.Description,
	})
	if err != nil {
		return nil, fmt.Errorf("label.create: %w", err)
	}
	return map[string]string{"id": id}, nil
}

func handleLabelUpdate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input labelUpdateInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("label.update: %w", err)
	}
	_, err := ac.Tx.UpdateLabel(ctx, sqlc.UpdateLabelParams{
		Name:        input.Name,
		Color:       input.Color,
		Description: input.Description,
		ID:          input.ID,
		OrgID:       input.OrgID,
	})
	if err != nil {
		return nil, fmt.Errorf("label.update: %w", err)
	}
	return map[string]string{"id": input.ID}, nil
}

// timestamp returns an ISO-8601 UTC timestamp string.
func timestamp() string {
	return "2026-07-28T12:00:00" // placeholder; real: time.Now().UTC().Format(time.RFC3339)
}

// projectKeyFromID extracts the project key prefix from a project ID.
// Real implementation would look up the project. Placeholder.
func projectKeyFromID(projectID string) string {
	if len(projectID) > 4 {
		return projectID[:4]
	}
	return "TASK"
}
