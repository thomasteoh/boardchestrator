package action

import (
	"context"
	"encoding/json"
	"time"
)

// The hook interfaces below are the seams later WUs plug into. Every one has a
// default implementation wired by New so `bc serve` runs today; each default
// is deliberately conservative for the current phase and is replaced (not
// weakened) when its owning WU lands. The plug-in map:
//
//   PermissionChecker  → real engine in WU-105 (internal/perm)
//   ApprovalGate       → real gate in WU-306 (agentrt approvals)
//   ScopeResolver      → real membership/existence checks in WU-104 (tenancy)
//   EventSink          → subscribed by the event bus in WU-007 (internal/event)
//   AuditSink          → default is DB-backed here; WU-110 adds the org UI
//   IdempotencyStore   → default is DB-backed here
//   Clock              → injectable for deterministic tests

// Event is the minimal event value emitted after a successful dispatch. The
// full typed pub/sub bus is WU-007 (internal/event); until it exists this
// package owns the shape and a no-op sink. When the bus lands it implements
// EventSink and subscribers (SSE, notify, webhooks, search, activity) fan out
// from here. Kept intentionally small and stable.
type Event struct {
	Name    string          // action name, e.g. "task.create"
	Org     string          // org scope id ("" for platform actions)
	Actor   Actor           // who acted (SPEC §1 rule 3: polymorphic)
	Subject string          // primary affected entity id, best-effort
	Payload json.RawMessage // the action's JSON-serialised output
}

// EventSink receives an Event after a successful (non-dry-run) dispatch.
// Implementations must be non-blocking or fast; the bus (WU-007) buffers.
type EventSink interface {
	Emit(ctx context.Context, ev Event)
}

// noopEventSink drops events. Default until WU-007 subscribes the real bus.
type noopEventSink struct{}

func (noopEventSink) Emit(context.Context, Event) {}

// AuditEntry is one audit_log row (SPEC §5). Written for every ImpactHigh
// action (all actors) and for every agent action, regardless of impact.
type AuditEntry struct {
	Org       string // "" ⇒ platform action; stored as NULL
	ActorType ActorType
	ActorID   string
	Action    string
	Subject   string
	Detail    json.RawMessage
	IP        string
}

// AuditSink appends audit rows. The default is DB-backed (see store.go);
// WU-110 builds the org audit page and CSV export on top of the same table.
type AuditSink interface {
	Append(ctx context.Context, e AuditEntry) error
}

// PermissionChecker decides whether an actor may perform def within a scope.
// The default allows everything (Phase 0 has no roles yet); WU-105 wires the
// real deny-by-default engine. It returns (allowed, error) — error is for
// infrastructure failures, not denials.
type PermissionChecker interface {
	Allow(ctx context.Context, ac ActionCtx, def Definition) (bool, error)
}

// allowAllPermissions is the Phase 0 default. It must be replaced by WU-105
// before any real tenant data exists.
type allowAllPermissions struct{}

func (allowAllPermissions) Allow(context.Context, ActionCtx, Definition) (bool, error) {
	return true, nil
}

// ApprovalDecision is the outcome of the approval gate for an agent action.
type ApprovalDecision int

const (
	// ApprovalProceed lets the action continue immediately.
	ApprovalProceed ApprovalDecision = iota
	// ApprovalPending parks the action: Dispatch persists nothing further and
	// returns ErrApprovalPending with the id the gate supplies.
	ApprovalPending
	// ApprovalForbid blocks the action: Dispatch returns ErrForbidden.
	ApprovalForbid
)

// ApprovalGate applies the agent approval policy for def.Impact. It is only
// consulted for agent actors (SPEC §4). On ApprovalPending it returns the
// approvals row id to embed in ErrApprovalPending.
type ApprovalGate interface {
	Gate(ctx context.Context, ac ActionCtx, def Definition) (decision ApprovalDecision, approvalID string, err error)
}

// noopApprovalGate always proceeds. This is the Phase 0 default; WU-306
// implements the real gate (policy per impact class from agent config,
// persisting approvals rows and setting run state awaiting_approval).
type noopApprovalGate struct{}

func (noopApprovalGate) Gate(context.Context, ActionCtx, Definition) (ApprovalDecision, string, error) {
	return ApprovalProceed, "", nil
}

// ScopeResolver verifies that the ids carried in ac exist and that the actor
// is a member of the scope. The default is a no-op that accepts whatever
// Dispatch already parsed from the input; WU-104 replaces it with real
// existence + membership checks once orgs/teams/projects exist.
type ScopeResolver interface {
	Resolve(ctx context.Context, ac ActionCtx, def Definition) error
}

// noopScopeResolver accepts any scope. Default until WU-104.
type noopScopeResolver struct{}

func (noopScopeResolver) Resolve(context.Context, ActionCtx, Definition) error { return nil }

// IdempotencyStore records and replays action results keyed by idempotency
// key (SPEC §4, §5 idempotency_keys). The default is DB-backed (store.go).
type IdempotencyStore interface {
	// Get returns the stored result JSON for key and whether a hit exists.
	Get(ctx context.Context, key string) (result json.RawMessage, hit bool, err error)
	// Put stores result under key for the given actor/action.
	Put(ctx context.Context, key, actorRef, action string, result json.RawMessage, at time.Time) error
}

// Clock supplies the current time; injectable so tests are deterministic.
type Clock func() time.Time
