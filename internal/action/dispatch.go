package action

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// Dispatcher runs the action pipeline (SPEC §4). All policy is injected via
// the hook fields so tests can drive every branch and later WUs can replace
// the Phase 0 defaults. Construct with New; override individual hooks with the
// With* options.
type Dispatcher struct {
	db *sql.DB

	perm     PermissionChecker
	approval ApprovalGate
	scope    ScopeResolver
	events   EventSink
	audit    AuditSink
	idem     IdempotencyStore
	now      Clock
}

// Option customises a Dispatcher at construction; used by both later WUs
// (to swap in real engines) and tests (to force a branch).
type Option func(*Dispatcher)

// WithPermissionChecker overrides the permission hook (WU-105).
func WithPermissionChecker(p PermissionChecker) Option { return func(d *Dispatcher) { d.perm = p } }

// WithApprovalGate overrides the approval hook (WU-306).
func WithApprovalGate(g ApprovalGate) Option { return func(d *Dispatcher) { d.approval = g } }

// WithScopeResolver overrides the scope/membership hook (WU-104).
func WithScopeResolver(r ScopeResolver) Option { return func(d *Dispatcher) { d.scope = r } }

// WithEventSink overrides the event sink (WU-007 bus).
func WithEventSink(s EventSink) Option { return func(d *Dispatcher) { d.events = s } }

// WithAuditSink overrides the audit sink.
func WithAuditSink(s AuditSink) Option { return func(d *Dispatcher) { d.audit = s } }

// WithIdempotencyStore overrides the idempotency store.
func WithIdempotencyStore(s IdempotencyStore) Option { return func(d *Dispatcher) { d.idem = s } }

// WithClock overrides the clock; test-only.
func WithClock(c Clock) Option { return func(d *Dispatcher) { d.now = c } }

// New builds a Dispatcher over db with Phase 0 defaults: allow-all
// permissions, no-op approval gate, no-op scope resolver, no-op event sink,
// and DB-backed audit + idempotency stores. Options replace any default. db
// may be nil only if every DB-using hook (audit, idempotency) is overridden
// and no action executes — practical for narrow unit tests.
func New(db *sql.DB, opts ...Option) *Dispatcher {
	d := &Dispatcher{
		db:       db,
		perm:     allowAllPermissions{},
		approval: noopApprovalGate{},
		scope:    noopScopeResolver{},
		events:   noopEventSink{},
		now:      time.Now,
	}
	d.idem = dbIdempotencyStore{db: db}
	d.audit = dbAuditSink{db: db, now: func() time.Time { return d.now() }}
	for _, o := range opts {
		o(d)
	}
	return d
}

// Opts are the per-call dispatch options.
type Opts struct {
	// Org/Team/Proj are the scope ids for the call. Handlers that carry the id
	// in their input may leave these blank and let the handler read it, but
	// scope-verified actions expect them populated by the caller (handler
	// layer) so the ScopeResolver (WU-104) and PermissionChecker (WU-105) can
	// operate on resolved ids.
	Org, Team, Proj string
	// DryRun runs validation + permission + scope, then Preview (or an input
	// echo) instead of Handle; nothing is executed or mutated.
	DryRun bool
	// Idem is the idempotency key ("" = none).
	Idem string
}

// Dispatch runs the full pipeline for action name on behalf of actor with the
// given raw JSON input. The order is fixed by SPEC §4:
//
//	resolve actor → validate input → resolve+verify scope → permission →
//	approval gate → idempotency check → execute in a tx → store idempotent
//	result → emit event → audit (ImpactHigh for all actors; all agent actions).
//
// It returns the handler's output value (or the dry-run preview/echo) and an
// error. Sentinel errors (ErrUnknownAction, ErrInvalidInput, ErrForbidden,
// ErrScope, ErrApprovalPending) let callers map to HTTP/MCP responses.
func (d *Dispatcher) Dispatch(ctx context.Context, actor Actor, name string, input json.RawMessage, opts Opts) (any, error) {
	// 1. Resolve actor. (Actor is already resolved by the caller — the
	// handler/API layer turns a session or API key into an Actor. Here we
	// validate its shape; nothing downstream may assume a human, SPEC §1.)
	if !actor.Type.Valid() {
		return nil, fmt.Errorf("%w: invalid actor type %q", ErrForbidden, actor.Type)
	}
	if actor.ID == "" {
		return nil, fmt.Errorf("%w: empty actor id", ErrForbidden)
	}

	// 2. Look up the action.
	def, ok := Lookup(name)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownAction, name)
	}

	ac := ActionCtx{
		Actor:  actor,
		Org:    opts.Org,
		Team:   opts.Team,
		Proj:   opts.Proj,
		DryRun: opts.DryRun,
		Idem:   opts.Idem,
	}

	// 3. Validate input schema.
	if def.Input != nil {
		if err := def.Input.Validate(input); err != nil {
			return nil, err // already wraps ErrInvalidInput
		}
	}

	// 4. Resolve + verify scope (ids exist / actor is member). No-op default;
	// WU-104 enforces existence and membership.
	if err := d.scope.Resolve(ctx, ac, def); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrScope, err)
	}

	// 5. Permission check. Default allow-all; WU-105 wires deny-by-default.
	allowed, err := d.perm.Allow(ctx, ac, def)
	if err != nil {
		return nil, fmt.Errorf("action: permission check: %w", err)
	}
	if !allowed {
		return nil, ErrForbidden
	}

	// 6. Approval gate — agents only (SPEC §4). No-op default proceeds; WU-306
	// implements per-impact policy.
	if actor.Type == ActorAgent {
		decision, approvalID, gerr := d.approval.Gate(ctx, ac, def)
		if gerr != nil {
			return nil, fmt.Errorf("action: approval gate: %w", gerr)
		}
		switch decision {
		case ApprovalForbid:
			return nil, ErrForbidden
		case ApprovalPending:
			return nil, ErrApprovalPending{ID: approvalID}
		case ApprovalProceed:
			// fall through
		}
	}

	// Dry-run: run everything above (validate + scope + perm), then Preview or
	// echo. No execution, no idempotency store, no event, no audit, no mutation.
	if ac.DryRun {
		if def.Preview != nil {
			return def.Preview(ctx, ac, input)
		}
		// No preview defined: echo the validated input (SPEC §4).
		return input, nil
	}

	// 7. Idempotency check — return the stored result on a hit, without
	// re-executing Handle.
	if ac.Idem != "" {
		stored, hit, ierr := d.idem.Get(ctx, ac.Idem)
		if ierr != nil {
			return nil, ierr
		}
		if hit {
			return stored, nil
		}
	}

	// 8. Execute Handle inside a DB transaction. Dispatch owns the tx boundary
	// so a handler error rolls back the whole action (SPEC §4).
	out, err := d.execute(ctx, ac, def, input)
	if err != nil {
		return nil, err
	}

	// Serialise output once for idempotent storage and the event payload.
	payload, err := marshalResult(out)
	if err != nil {
		return nil, fmt.Errorf("action: marshal result of %q: %w", name, err)
	}

	// 9. Store idempotent result (best-effort keyed by Idem).
	if ac.Idem != "" {
		if err := d.idem.Put(ctx, ac.Idem, actor.ref(), name, payload, d.now()); err != nil {
			return nil, err
		}
	}

	// 10. Emit event carrying the actor (SPEC §4). Subject best-effort.
	d.events.Emit(ctx, Event{
		Name:    name,
		Org:     ac.Org,
		Actor:   actor,
		Subject: subjectOf(out),
		Payload: payload,
	})

	// 11. Audit: every ImpactHigh action (all actors) and every agent action.
	if def.Impact == ImpactHigh || actor.Type == ActorAgent {
		if err := d.audit.Append(ctx, AuditEntry{
			Org:       ac.Org,
			ActorType: actor.Type,
			ActorID:   actor.ID,
			Action:    name,
			Subject:   subjectOf(out),
			Detail:    payload,
			IP:        actor.IP,
		}); err != nil {
			return nil, err
		}
	}

	return out, nil
}

// execute runs the handler in a transaction, committing on success and rolling
// back on error. If the dispatcher has no DB (nil), it runs the handler with a
// nil Tx — valid only for actions that do not touch the DB (narrow tests).
func (d *Dispatcher) execute(ctx context.Context, ac ActionCtx, def Definition, input json.RawMessage) (any, error) {
	if d.db == nil {
		ac.Tx = nil
		return def.Handle(ctx, ac, input)
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("action: begin tx for %q: %w", def.Name, err)
	}
	ac.Tx = &Queries{sqlc.New(tx)}
	out, herr := def.Handle(ctx, ac, input)
	if herr != nil {
		if rberr := tx.Rollback(); rberr != nil {
			return nil, fmt.Errorf("action: handler %q failed (%v) and rollback failed: %w", def.Name, herr, rberr)
		}
		return nil, herr
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("action: commit tx for %q: %w", def.Name, err)
	}
	return out, nil
}

// marshalResult serialises a handler result. A json.RawMessage passes through;
// nil becomes JSON null.
func marshalResult(out any) (json.RawMessage, error) {
	if out == nil {
		return json.RawMessage("null"), nil
	}
	if raw, ok := out.(json.RawMessage); ok {
		if len(raw) == 0 {
			return json.RawMessage("null"), nil
		}
		return raw, nil
	}
	b, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// subjectOf best-effort extracts a subject id from a handler result: an "id"
// field on a struct/map. Empty when none is discoverable; the event/audit
// still carry the action name and actor.
func subjectOf(out any) string {
	raw, err := marshalResult(out)
	if err != nil {
		return ""
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return ""
	}
	for _, k := range []string{"id", "ID", "Id"} {
		if v, ok := m[k]; ok {
			var s string
			if json.Unmarshal(v, &s) == nil {
				return s
			}
		}
	}
	return ""
}
