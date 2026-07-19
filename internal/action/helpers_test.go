package action

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// nopHandle is a handler that succeeds with no output.
func nopHandle(context.Context, ActionCtx, json.RawMessage) (any, error) { return nil, nil }

// --- test hook implementations ---------------------------------------------

type denyPerm struct{}

func (denyPerm) Allow(context.Context, ActionCtx, Definition) (bool, error) { return false, nil }

type denyScope struct{}

func (denyScope) Resolve(context.Context, ActionCtx, Definition) error {
	return fmt.Errorf("scope denied")
}

type pendingGate struct{ id string }

func (g pendingGate) Gate(context.Context, ActionCtx, Definition) (ApprovalDecision, string, error) {
	return ApprovalPending, g.id, nil
}

type forbidGate struct{}

func (forbidGate) Gate(context.Context, ActionCtx, Definition) (ApprovalDecision, string, error) {
	return ApprovalForbid, "", nil
}

type recordingAudit struct{ entries []AuditEntry }

func (r *recordingAudit) Append(_ context.Context, e AuditEntry) error {
	r.entries = append(r.entries, e)
	return nil
}

type recordingEvents struct{ events []Event }

func (r *recordingEvents) Emit(_ context.Context, ev Event) { r.events = append(r.events, ev) }

// --- misc helpers ----------------------------------------------------------

func mustPanic(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	fn()
}

func errString(v any) string {
	if err, ok := v.(error); ok {
		return err.Error()
	}
	return fmt.Sprint(v)
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	if raw, ok := v.(json.RawMessage); ok {
		return string(raw)
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// txProbeParams builds an idempotency_keys insert used to prove tx
// commit/rollback behaviour (the table has no FK constraints).
func txProbeParams(key string) sqlc.CreateIdempotencyKeyParams {
	return sqlc.CreateIdempotencyKeyParams{
		Key:        key,
		Actor:      "user:probe",
		Action:     "probe",
		ResultJson: "null",
		CreatedAt:  time.Now().UTC().Format(timeFormat),
	}
}

func probeCount(t *testing.T, d *sql.DB, key string) int {
	t.Helper()
	var n int
	if err := d.QueryRow(`SELECT count(*) FROM idempotency_keys WHERE key = ?`, key).Scan(&n); err != nil {
		t.Fatalf("probe count: %v", err)
	}
	return n
}
