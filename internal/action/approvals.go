package action

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// approvalDecideInput is the input to approval.decide.
type approvalDecideInput struct {
	ID      string `json:"id"`
	OrgID   string `json:"org_id"`
	Approve bool   `json:"approve"`
}

// handleApprovalDecide resolves a pending agent approval (SPEC §4/§10). It is
// an ImpactHigh action callable by a human user (or admin) on behalf of the
// org. On approve or reject it marks the approvals row decided and requeues the
// owning run so the engine resumes the tool loop — the gate sees the decided
// row for the same run+action+input and proceeds (approved) or forbids
// (rejected, surfaced to the model as a tool error).
func handleApprovalDecide(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input approvalDecideInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("approval.decide: %w", err)
	}
	if input.ID == "" || input.OrgID == "" {
		return nil, fmt.Errorf("approval.decide: id and org_id are required")
	}

	ts := timestamp()
	status := "rejected"
	if input.Approve {
		status = "approved"
	}
	decidedBy := sql.NullString{String: ac.Actor.ref(), Valid: true}

	// Org-scoped update: a cross-org attempt on a :one update returns
	// sql.ErrNoRows → 404 semantics for the caller.
	decided, err := ac.Tx.DecideApproval(ctx, sqlc.DecideApprovalParams{
		Status:    status,
		DecidedBy: decidedBy,
		DecidedAt: sql.NullString{String: ts, Valid: true},
		ID:        input.ID,
		OrgID:     input.OrgID,
	})
	if err != nil {
		return nil, fmt.Errorf("approval.decide: %w", err)
	}
	// Idempotent: a second decide on the same row is a no-op that reports the
	// stored decision.
	if decided.Status != status || decided.DecidedBy != decidedBy {
		return map[string]string{
			"id":     decided.ID,
			"status": decided.Status,
			"run_id": decided.RunID,
		}, nil
	}

	// Requeue the owning run so the engine resumes it with the decided gate.
	if _, err := ac.Tx.RequeueRun(ctx, sqlc.RequeueRunParams{
		ID:    decided.RunID,
		OrgID: input.OrgID,
	}); err != nil {
		return nil, fmt.Errorf("approval.decide: requeue run: %w", err)
	}

	// The dispatch pipeline emits approval.decided (event name == action name)
	// with this payload; a server-side engine subscriber enqueues a resume job
	// for the run.
	return map[string]string{
		"id":     decided.ID,
		"status": decided.Status,
		"run_id": decided.RunID,
	}, nil
}

func init() {
	Register(Definition{
		Name:       "approval.decide",
		Impact:     ImpactHigh,
		Permission: "approval.decide",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleApprovalDecide,
	})
}
