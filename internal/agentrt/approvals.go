package agentrt

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// runIDCtxKey carries the current run id from the engine into the approval
// gate. dispatchTool sets it on the dispatch context so the gate can attach a
// new approvals row to the owning run without scanning for it.
type runIDCtxKey struct{}

// withRunID returns a context carrying the run id.
func withRunID(ctx context.Context, runID string) context.Context {
	return context.WithValue(ctx, runIDCtxKey{}, runID)
}

// runIDFrom returns the run id carried on ctx ("" when absent).
func runIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(runIDCtxKey{}).(string)
	return id
}

// approvalPolicy is the agent's approval_policy_json: per-impact-class policy
// in {"read": auto|require|forbid, "low": ..., "high": ...} form (SPEC §4/§10).
// Missing keys default to "auto".
type approvalPolicy map[string]string

// policyFor returns the agent's approval policy for the given impact class,
// defaulting to "auto" when the key is absent or the policy is unparseable.
func (p approvalPolicy) policyFor(impact action.Impact) string {
	if v, ok := p[impact.String()]; ok {
		return v
	}
	return "auto"
}

// decisionFor maps a policy value to an ApprovalDecision.
func decisionFor(policy string) action.ApprovalDecision {
	switch policy {
	case "require":
		return action.ApprovalPending
	case "forbid":
		return action.ApprovalForbid
	default: // "auto" and anything unknown proceed
		return action.ApprovalProceed
	}
}

// agentApprovalGate implements action.ApprovalGate for agent actors (SPEC
// §4/§10): it reads the acting agent's approval_policy_json per impact class.
//
//	require → persist an approvals row + notify the run's initiator, return
//	          ApprovalPending (Dispatch returns ErrApprovalPending)
//	forbid  → return ApprovalForbid (Dispatch returns ErrForbidden)
//	auto    → proceed
//
// The gate is only consulted for agent actors (Dispatch gates agents only), so
// the acting agent id is ac.Actor.ID. It uses the raw *sql.DB (not the dispatch
// tx) because the approvals row lives outside the action's transaction, and
// reads the run id from the dispatch context (set by the engine).
type agentApprovalGate struct {
	q *sqlc.Queries
}

// newAgentApprovalGate builds a gate over db.
func newAgentApprovalGate(db *sql.DB) *agentApprovalGate {
	return &agentApprovalGate{q: sqlc.New(db)}
}

// Gate implements action.ApprovalGate.
func (g *agentApprovalGate) Gate(ctx context.Context, ac action.ActionCtx, def action.Definition, input json.RawMessage) (action.ApprovalDecision, string, error) {
	// The acting agent is the actor for agent dispatches (SPEC §10).
	agent, err := g.q.FindAgentByID(ctx, ac.Actor.ID)
	if err != nil {
		return action.ApprovalProceed, "", fmt.Errorf("gate: find agent: %w", err)
	}

	var pol approvalPolicy
	_ = json.Unmarshal([]byte(agent.ApprovalPolicyJson), &pol)
	decision := decisionFor(pol.policyFor(def.Impact))
	if decision == action.ApprovalProceed {
		return action.ApprovalProceed, "", nil
	}
	if decision == action.ApprovalForbid {
		return action.ApprovalForbid, "", nil
	}

	// require → check for an existing decision for this exact run+action+input
	// (resume path: approval.decide re-dispatches the stored call with the same
	// run context; a decided row satisfies the gate instead of re-parking).
	runID := runIDFrom(ctx)
	existing, err := g.q.FindApprovalForRun(ctx, sqlc.FindApprovalForRunParams{
		RunID:      runID,
		OrgID:      ac.Org,
		ActionName: def.Name,
		InputJson:  string(input),
	})
	if err == nil {
		switch existing.Status {
		case "approved":
			return action.ApprovalProceed, "", nil
		case "rejected":
			return action.ApprovalForbid, "", nil
		default: // pending — fall through to re-park below
		}
	}

	// Persist a new pending approvals row (org-scoped), attached to the owning
	// run via the dispatch context. Return ApprovalPending so Dispatch parks.
	approvalID := newID()
	if _, err := g.q.CreateApproval(ctx, sqlc.CreateApprovalParams{
		ID:         approvalID,
		OrgID:      ac.Org,
		RunID:      runID,
		ActionName: def.Name,
		InputJson:  string(input),
		Status:     "pending",
	}); err != nil {
		return action.ApprovalProceed, "", fmt.Errorf("gate: create approval: %w", err)
	}

	// Notify the run's initiator that approval is requested (SPEC §10).
	if runID != "" {
		if r, ferr := g.q.FindRunByID(ctx, sqlc.FindRunByIDParams{ID: runID, OrgID: ac.Org}); ferr == nil && r.InitiatedBy.Valid && r.InitiatedBy.String != "" {
			if _, nerr := g.q.CreateNotification(ctx, sqlc.CreateNotificationParams{
				ID:          newID(),
				OrgID:       ac.Org,
				UserID:      r.InitiatedBy.String,
				EventName:   "approval.requested",
				SubjectID:   approvalID,
				Title:       "Approval requested",
				Body:        fmt.Sprintf("Agent %s requests approval for %s.", agent.Name, def.Name),
				GroupingKey: "approval.requested:" + approvalID,
			}); nerr != nil {
				return action.ApprovalProceed, "", fmt.Errorf("gate: notify: %w", nerr)
			}
		}
	}
	return action.ApprovalPending, approvalID, nil
}
