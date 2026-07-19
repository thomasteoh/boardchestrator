// Package action is the architectural spine of Boardchestrator (SPEC §1, §4):
// every mutation in the system flows through Dispatch, which resolves the
// actor, validates input, verifies tenant scope, checks permission, applies
// the agent approval gate, enforces idempotency, executes the handler inside a
// DB transaction, emits an event, and audits high-impact and agent actions.
//
// Handlers register Definitions at init via Register; the REST, MCP, and
// agent-tool surfaces (SPEC §11–§12, §10) are all derived from the registry
// rather than hand-written, so the abstractions here must match SPEC §4
// exactly. Downstream policy — permission engine (WU-105), approval gate
// (WU-306), scope/membership checks (WU-104), and the event bus (WU-007) —
// plug in through the hook interfaces on Dispatcher; sensible no-op or
// default-allow implementations ship now so `bc serve` runs before those WUs
// land. See the package-level Notes in BACKLOG WU-006 for the plug-in map.
package action

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
)

// Impact classifies how consequential an action is. It drives the approval
// gate (agent policy is keyed per impact class) and auditing (ImpactHigh is
// always audited, for every actor).
type Impact int

const (
	// ImpactRead is a non-mutating read (e.g. search.query).
	ImpactRead Impact = iota
	// ImpactLow is a routine mutation (e.g. task.update, comment.create).
	ImpactLow
	// ImpactHigh is a consequential mutation (e.g. member.invite,
	// project.archive); always audited and eligible for approval gating.
	ImpactHigh
)

// String renders an Impact for logs and audit detail.
func (i Impact) String() string {
	switch i {
	case ImpactRead:
		return "read"
	case ImpactLow:
		return "low"
	case ImpactHigh:
		return "high"
	default:
		return fmt.Sprintf("impact(%d)", int(i))
	}
}

// ScopeKind is the tenant scope an action's input must carry. Dispatch uses it
// to know which id (org/team/project) to resolve and verify membership for.
type ScopeKind int

const (
	// ScopePlatform is a platform-level action with no tenant id.
	ScopePlatform ScopeKind = iota
	// ScopeOrg requires an org id.
	ScopeOrg
	// ScopeTeam requires org + team ids.
	ScopeTeam
	// ScopeProject requires org + project ids.
	ScopeProject
)

// String renders a ScopeKind.
func (s ScopeKind) String() string {
	switch s {
	case ScopePlatform:
		return "platform"
	case ScopeOrg:
		return "org"
	case ScopeTeam:
		return "team"
	case ScopeProject:
		return "project"
	default:
		return fmt.Sprintf("scope(%d)", int(s))
	}
}

// ActorType is the polymorphic kind of an actor (SPEC §1 rule 3: nothing
// downstream may assume a human).
type ActorType string

const (
	// ActorUser is an end user acting via the browser.
	ActorUser ActorType = "user"
	// ActorAgent is an AI agent acting in its own right (with an owning org).
	ActorAgent ActorType = "agent"
	// ActorAPIKey is an API key acting on behalf of its owning user.
	ActorAPIKey ActorType = "apikey"
)

// Valid reports whether t is a known actor type.
func (t ActorType) Valid() bool {
	switch t {
	case ActorUser, ActorAgent, ActorAPIKey:
		return true
	default:
		return false
	}
}

// Actor is the resolved principal for a dispatch. For an API key, OwnerUserID
// is the user the key belongs to (its permissions are intersected with the
// key's scope at request time — WU-109).
type Actor struct {
	Type        ActorType
	ID          string
	OwnerUserID string // set when Type == ActorAPIKey; the owning user
	IP          string // client IP, recorded in audit rows
}

// ref returns a stable string identifying the actor for idempotency and audit
// storage.
func (a Actor) ref() string {
	return string(a.Type) + ":" + a.ID
}

// ActionCtx is the resolved execution context handed to a Handle/Preview
// function. Scope ids are populated by Dispatch after scope resolution; "" for
// scopes an action does not use.
type ActionCtx struct {
	Actor           Actor
	Org, Team, Proj string // resolved scope ids ("" where n/a)
	DryRun          bool
	Idem            string // idempotency key ("" = none)

	// Tx is the transaction the handler must use for all writes. Handlers
	// never open their own transaction; Dispatch owns the boundary so that a
	// handler error rolls back the whole action (SPEC §4).
	Tx *Queries
}

// HandlerFunc executes an action against its input, returning the output
// value (serialised to JSON for idempotent storage and events) or an error.
type HandlerFunc func(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error)

// Definition is a single registered action (SPEC §4). Name is stable and
// never renamed once shipped.
type Definition struct {
	Name       string
	Impact     Impact
	Permission string    // perm key checked against the actor's effective grants
	Scope      ScopeKind // which tenant id the input must carry
	Input      Schema    // validated before Handle; nil ⇒ no validation
	Output     Schema    // documentation/derivation only; not enforced here
	Handle     HandlerFunc
	Preview    HandlerFunc // optional; nil ⇒ dry-run echoes validated input
}

var (
	registryMu sync.RWMutex
	registry   = map[string]Definition{}
)

// Register adds def to the global registry. It is intended to be called from
// package init blocks. A duplicate name or an obviously malformed definition
// panics at startup — a programming error, caught before the server serves.
func Register(def Definition) {
	if def.Name == "" {
		panic("action.Register: empty action name")
	}
	if def.Handle == nil {
		panic(fmt.Sprintf("action.Register: %q has nil Handle", def.Name))
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, dup := registry[def.Name]; dup {
		panic(fmt.Sprintf("action.Register: duplicate action name %q", def.Name))
	}
	registry[def.Name] = def
}

// Lookup returns the definition for name and whether it exists.
func Lookup(name string) (Definition, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	def, ok := registry[name]
	return def, ok
}

// All returns every registered definition sorted by name. The REST, MCP, and
// agent-tool surfaces iterate this rather than hand-registering endpoints
// (SPEC §4 derivation surfaces).
func All() []Definition {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]Definition, 0, len(registry))
	for _, d := range registry {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// reset clears the registry; test-only, exported to the package's tests.
func reset() {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry = map[string]Definition{}
}

// Sentinel errors surfaced by Dispatch.
var (
	// ErrUnknownAction is returned when Dispatch is called with a name that is
	// not registered.
	ErrUnknownAction = errors.New("action: unknown action")
	// ErrForbidden is returned when the permission hook denies the actor, or
	// when the agent approval policy for the action's impact class is
	// "forbid".
	ErrForbidden = errors.New("action: forbidden")
	// ErrInvalidInput is returned when input fails schema validation.
	ErrInvalidInput = errors.New("action: invalid input")
	// ErrScope is returned when a required scope id is missing or fails
	// membership verification.
	ErrScope = errors.New("action: scope resolution failed")
)

// ErrApprovalPending is returned when an agent action is gated behind a
// pending approval. The owning run parks on this until approval.decide
// (WU-306) re-dispatches the stored call.
type ErrApprovalPending struct {
	ID string // approvals row id
}

func (e ErrApprovalPending) Error() string {
	return fmt.Sprintf("action: approval pending (id=%s)", e.ID)
}

// newID returns a 16-byte random, hex-encoded id (SPEC §3 ID convention).
func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand.Read is documented never to fail on supported
		// platforms; a failure here means the platform CSPRNG is broken and
		// we cannot safely continue.
		panic(fmt.Sprintf("action: crypto/rand failed: %v", err))
	}
	return hex.EncodeToString(b[:])
}
