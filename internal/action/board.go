package action

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

type boardColCreateInput struct {
	ProjectID string `json:"project_id"`
	Name      string `json:"name"`
	Color     string `json:"color"`
	WIPLimit  int    `json:"wip_limit"`
	Status    string `json:"status"`
}

type boardColUpdateInput struct {
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`
	Name      string `json:"name"`
	Color     string `json:"color"`
	WIPLimit  int    `json:"wip_limit"`
	Status    string `json:"status"`
}

type boardColReorderInput struct {
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`
	Position  int    `json:"position"`
}

func init() {
	Register(Definition{
		Name:       "board.column.create",
		Impact:     ImpactLow,
		Permission: "board.column.create",
		Scope:      ScopeProject,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleBoardColCreate,
	})
	Register(Definition{
		Name:       "board.column.update",
		Impact:     ImpactLow,
		Permission: "board.column.update",
		Scope:      ScopeProject,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleBoardColUpdate,
	})
	Register(Definition{
		Name:       "board.column.delete",
		Impact:     ImpactHigh,
		Permission: "board.column.delete",
		Scope:      ScopeProject,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleBoardColDelete,
	})
	Register(Definition{
		Name:       "board.column.reorder",
		Impact:     ImpactLow,
		Permission: "board.column.reorder",
		Scope:      ScopeProject,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleBoardColReorder,
	})
}

func RegisterBoardActions() {}

func handleBoardColCreate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input boardColCreateInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("board.column.create: %w", err)
	}
	pos, err := ac.Tx.MaxBoardColumnPosition(ctx, input.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("board.column.create: position: %w", err)
	}
	id := newID()
	_, err = ac.Tx.CreateBoardColumn(ctx, sqlc.CreateBoardColumnParams{
		ID:        id,
		ProjectID: input.ProjectID,
		Name:      input.Name,
		Color:     input.Color,
		Position:  float64(pos),
		WipLimit:  int64(input.WIPLimit),
		Status:    input.Status,
	})
	if err != nil {
		return nil, fmt.Errorf("board.column.create: %w", err)
	}
	return map[string]string{"id": id}, nil
}

func handleBoardColUpdate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input boardColUpdateInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("board.column.update: %w", err)
	}
	_, err := ac.Tx.UpdateBoardColumn(ctx, sqlc.UpdateBoardColumnParams{
		Name:      input.Name,
		Color:     input.Color,
		Position:  0,
		WipLimit:  int64(input.WIPLimit),
		Status:    input.Status,
		ID:        input.ID,
		ProjectID: input.ProjectID,
	})
	if err != nil {
		return nil, fmt.Errorf("board.column.update: %w", err)
	}
	return map[string]string{"id": input.ID}, nil
}

func handleBoardColDelete(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input struct {
		ID        string `json:"id"`
		ProjectID string `json:"project_id"`
	}
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("board.column.delete: %w", err)
	}
	if err := ac.Tx.DeleteBoardColumn(ctx, sqlc.DeleteBoardColumnParams{
		ID:        input.ID,
		ProjectID: input.ProjectID,
	}); err != nil {
		return nil, fmt.Errorf("board.column.delete: %w", err)
	}
	return map[string]string{"id": input.ID}, nil
}

func handleBoardColReorder(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input boardColReorderInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("board.column.reorder: %w", err)
	}
	if err := ac.Tx.ReorderBoardColumns(ctx, sqlc.ReorderBoardColumnsParams{
		Position:  float64(input.Position),
		ID:        input.ID,
		ProjectID: input.ProjectID,
	}); err != nil {
		return nil, fmt.Errorf("board.column.reorder: %w", err)
	}
	return map[string]string{"id": input.ID}, nil
}
