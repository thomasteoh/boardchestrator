package action

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
)

// TestAuditCoverage covers WU-407 AC: every ImpactHigh action is audited when
// dispatched. Dispatch audits unconditionally for ImpactHigh (and agent
// actors); this test proves the contract live: dispatching an ImpactHigh
// action through a recording audit sink appends an entry, and an ImpactLow
// mutation does not (audit is reserved for consequential actions).
func TestAuditCoverage(t *testing.T) {
	reset()
	t.Cleanup(reset)

	// Register one ImpactHigh and one ImpactLow action, both succeeding.
	Register(Definition{
		Name: "audit.high", Impact: ImpactHigh, Scope: ScopePlatform, Permission: "audit.high",
		Input: FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle: func(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
			return map[string]any{"ok": true}, nil
		},
	})
	Register(Definition{
		Name: "audit.low", Impact: ImpactLow, Scope: ScopePlatform,
		Input: FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle: func(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
			return map[string]any{"ok": true}, nil
		},
	})

	// Prove the audit branch is keyed on ImpactHigh: a high-impact dispatch
	// appends an audit entry; a low-impact mutation does not.
	sink := &recordingAudit{}
	d := New(dbtest.New(t), WithAuditSink(sink))
	ctx := context.Background()

	if _, err := d.Dispatch(ctx, userActor(), "audit.high", json.RawMessage(`{}`), Opts{}); err != nil {
		t.Fatalf("audit.high dispatch: %v", err)
	}
	if len(sink.entries) != 1 {
		t.Fatalf("ImpactHigh dispatch not audited: got %d audit entries, want 1", len(sink.entries))
	}
	if sink.entries[0].Action != "audit.high" {
		t.Fatalf("audit entry action = %q, want audit.high", sink.entries[0].Action)
	}

	if _, err := d.Dispatch(ctx, userActor(), "audit.low", json.RawMessage(`{}`), Opts{}); err != nil {
		t.Fatalf("audit.low dispatch: %v", err)
	}
	if len(sink.entries) != 1 {
		t.Fatalf("ImpactLow mutation was audited (%d entries) — audit is for ImpactHigh", len(sink.entries))
	}

	// Structural coverage: every registered ImpactHigh action carries a
	// permission string (so it is permission-gated, auditable, and not an
	// accidental ImpactHigh echo handler).
	for _, def := range All() {
		if def.Impact == ImpactHigh && def.Permission == "" {
			t.Fatalf("ImpactHigh action %q has no permission — it is audited but ungated", def.Name)
		}
	}
}
