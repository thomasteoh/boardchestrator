package action

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

type commentCreateInput struct {
	TaskID    string `json:"task_id"`
	ProjectID string `json:"project_id"`
	Body      string `json:"body"`
}

type commentUpdateInput struct {
	ID        string `json:"id"`
	TaskID    string `json:"task_id"`
	ProjectID string `json:"project_id"`
	Body      string `json:"body"`
}

type commentDeleteInput struct {
	ID        string `json:"id"`
	TaskID    string `json:"task_id"`
	ProjectID string `json:"project_id"`
}

func init() {
	Register(Definition{
		Name:       "comment.create",
		Impact:     ImpactLow,
		Permission: "comment.create",
		Scope:      ScopeProject,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleCommentCreate,
	})
	Register(Definition{
		Name:       "comment.update",
		Impact:     ImpactLow,
		Permission: "comment.update",
		Scope:      ScopeProject,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleCommentUpdate,
	})
	Register(Definition{
		Name:       "comment.delete",
		Impact:     ImpactLow,
		Permission: "comment.delete",
		Scope:      ScopeProject,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleCommentDelete,
	})
}

// commentActivity records a comment mutation in task activity (SPEC §5).
func commentActivity(ctx context.Context, ac ActionCtx, taskID, projectID, action, detail string) {
	_, _ = ac.Tx.CreateTaskActivity(ctx, sqlc.CreateTaskActivityParams{
		ID:         newID(),
		TaskID:     taskID,
		ProjectID:  projectID,
		ActorID:    ac.Actor.ref(),
		ActorType:  string(ac.Actor.Type),
		Action:     action,
		DetailJson: detail,
	})
}

func handleCommentCreate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input commentCreateInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("comment.create: %w", err)
	}
	// author_id is a users(id) FK, so only user actors may create comments.
	if ac.Actor.Type != ActorUser {
		return nil, fmt.Errorf("comment.create: only user actors may comment")
	}
	c, err := ac.Tx.CreateComment(ctx, sqlc.CreateCommentParams{
		ID:        newID(),
		TaskID:    input.TaskID,
		ProjectID: input.ProjectID,
		AuthorID:  ac.Actor.ID,
		Body:      input.Body,
	})
	if err != nil {
		return nil, fmt.Errorf("comment.create: %w", err)
	}
	d, _ := json.Marshal(map[string]any{"id": c.ID})
	commentActivity(ctx, ac, input.TaskID, input.ProjectID, "comment.create", string(d))
	return map[string]any{"id": c.ID, "task_id": input.TaskID, "body": c.Body}, nil
}

func handleCommentUpdate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input commentUpdateInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("comment.update: %w", err)
	}
	c, err := ac.Tx.UpdateComment(ctx, sqlc.UpdateCommentParams{
		Body:      input.Body,
		UpdatedAt: timestamp(),
		ID:        input.ID,
		TaskID:    input.TaskID,
		ProjectID: input.ProjectID,
	})
	if err != nil {
		return nil, fmt.Errorf("comment.update: %w", err)
	}
	d, _ := json.Marshal(map[string]any{"id": c.ID})
	commentActivity(ctx, ac, input.TaskID, input.ProjectID, "comment.update", string(d))
	return map[string]any{"id": c.ID, "body": c.Body}, nil
}

func handleCommentDelete(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input commentDeleteInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("comment.delete: %w", err)
	}
	if err := ac.Tx.DeleteComment(ctx, sqlc.DeleteCommentParams{
		ID:        input.ID,
		TaskID:    input.TaskID,
		ProjectID: input.ProjectID,
	}); err != nil {
		return nil, fmt.Errorf("comment.delete: %w", err)
	}
	d, _ := json.Marshal(map[string]any{"id": input.ID})
	commentActivity(ctx, ac, input.TaskID, input.ProjectID, "comment.delete", string(d))
	return map[string]string{"id": input.ID}, nil
}

// RegisterCommentActions exported so cmd/bc/serve.go can ensure init() runs.
func RegisterCommentActions() {}
