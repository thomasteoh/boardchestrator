package action

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
)

// userActor / agentActor are convenient test principals.
func userActor() Actor  { return Actor{Type: ActorUser, ID: "u1", IP: "203.0.113.5"} }
func agentActor() Actor { return Actor{Type: ActorAgent, ID: "a1", IP: "203.0.113.9"} }

// echoInput is a schema requiring a single string field "name".
var echoSchema = ObjectSchema{Fields: []Field{{Name: "name", Kind: KindString, Required: true}}}

// resultWithID is a handler result carrying an id, to exercise subjectOf.
type resultWithID struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// --- Registry ---------------------------------------------------------------

func TestRegisterAndLookup(t *testing.T) {
	reset()
	t.Cleanup(reset)
	Register(Definition{Name: "test.x", Impact: ImpactLow, Handle: nopHandle})
	if _, ok := Lookup("test.x"); !ok {
		t.Fatal("expected test.x registered")
	}
	if _, ok := Lookup("test.missing"); ok {
		t.Fatal("did not expect test.missing")
	}
	if got := All(); len(got) != 1 || got[0].Name != "test.x" {
		t.Fatalf("All() = %+v", got)
	}
}

func TestRegisterDuplicatePanics(t *testing.T) {
	reset()
	t.Cleanup(reset)
	Register(Definition{Name: "dup.x", Handle: nopHandle})
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic on duplicate Register")
		}
		if !strings.Contains(errString(r), "duplicate") {
			t.Fatalf("panic message = %v, want mention of duplicate", r)
		}
	}()
	Register(Definition{Name: "dup.x", Handle: nopHandle})
}

func TestRegisterRejectsEmptyNameAndNilHandle(t *testing.T) {
	reset()
	t.Cleanup(reset)
	mustPanic(t, func() { Register(Definition{Name: "", Handle: nopHandle}) })
	mustPanic(t, func() { Register(Definition{Name: "no.handle", Handle: nil}) })
}

// --- Input validation -------------------------------------------------------

func TestDispatchInvalidInputRejected(t *testing.T) {
	reset()
	t.Cleanup(reset)
	var called int32
	Register(Definition{
		Name:   "val.x",
		Impact: ImpactLow,
		Input:  echoSchema,
		Handle: func(context.Context, ActionCtx, json.RawMessage) (any, error) {
			atomic.AddInt32(&called, 1)
			return nil, nil
		},
	})
	d := New(dbtest.New(t))

	cases := map[string]json.RawMessage{
		"empty":         json.RawMessage(``),
		"not object":    json.RawMessage(`42`),
		"missing field": json.RawMessage(`{}`),
		"wrong type":    json.RawMessage(`{"name":123}`),
		"unknown field": json.RawMessage(`{"name":"a","extra":1}`),
		"null field":    json.RawMessage(`{"name":null}`),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := d.Dispatch(context.Background(), userActor(), "val.x", in, Opts{})
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("err = %v, want ErrInvalidInput", err)
			}
		})
	}
	if atomic.LoadInt32(&called) != 0 {
		t.Fatalf("handler ran %d times on invalid input", called)
	}
}

func TestDispatchValidInputRuns(t *testing.T) {
	reset()
	t.Cleanup(reset)
	Register(Definition{
		Name:   "ok.x",
		Impact: ImpactLow,
		Input:  echoSchema,
		Handle: func(_ context.Context, _ ActionCtx, in json.RawMessage) (any, error) {
			return in, nil
		},
	})
	d := New(dbtest.New(t))
	out, err := d.Dispatch(context.Background(), userActor(), "ok.x", json.RawMessage(`{"name":"z"}`), Opts{})
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if string(out.(json.RawMessage)) != `{"name":"z"}` {
		t.Fatalf("out = %s", out.(json.RawMessage))
	}
}

// --- Unknown action ---------------------------------------------------------

func TestDispatchUnknownAction(t *testing.T) {
	reset()
	t.Cleanup(reset)
	d := New(dbtest.New(t))
	_, err := d.Dispatch(context.Background(), userActor(), "nope.x", json.RawMessage(`{}`), Opts{})
	if !errors.Is(err, ErrUnknownAction) {
		t.Fatalf("err = %v, want ErrUnknownAction", err)
	}
}

// --- Actor validation -------------------------------------------------------

func TestDispatchRejectsBadActor(t *testing.T) {
	reset()
	t.Cleanup(reset)
	Register(Definition{Name: "actor.x", Handle: nopHandle})
	d := New(dbtest.New(t))
	for _, a := range []Actor{
		{Type: "martian", ID: "x"},
		{Type: ActorUser, ID: ""},
	} {
		if _, err := d.Dispatch(context.Background(), a, "actor.x", nil, Opts{}); !errors.Is(err, ErrForbidden) {
			t.Fatalf("actor %+v: err = %v, want ErrForbidden", a, err)
		}
	}
}

// --- Idempotent replay ------------------------------------------------------

func TestDispatchIdempotentReplay(t *testing.T) {
	reset()
	t.Cleanup(reset)
	var runs int32
	Register(Definition{
		Name:   "idem.x",
		Impact: ImpactLow,
		Handle: func(context.Context, ActionCtx, json.RawMessage) (any, error) {
			atomic.AddInt32(&runs, 1)
			return resultWithID{ID: "id-1", Name: "first"}, nil
		},
	})
	d := New(dbtest.New(t))
	ctx := context.Background()

	out1, err := d.Dispatch(ctx, userActor(), "idem.x", nil, Opts{Idem: "k1"})
	if err != nil {
		t.Fatalf("first dispatch: %v", err)
	}
	out2, err := d.Dispatch(ctx, userActor(), "idem.x", nil, Opts{Idem: "k1"})
	if err != nil {
		t.Fatalf("replay dispatch: %v", err)
	}
	if atomic.LoadInt32(&runs) != 1 {
		t.Fatalf("handle ran %d times, want 1 (replay must not re-execute)", runs)
	}
	// Replay returns the STORED result JSON.
	got := mustJSON(t, out2)
	if !strings.Contains(got, `"id-1"`) || !strings.Contains(got, `"first"`) {
		t.Fatalf("replay result = %s, want stored result", got)
	}
	// First result and replay carry the same id.
	if !strings.Contains(mustJSON(t, out1), `"id-1"`) {
		t.Fatalf("first result = %s", mustJSON(t, out1))
	}
}

// --- Dry run ----------------------------------------------------------------

func TestDispatchDryRunDoesNotExecute(t *testing.T) {
	reset()
	t.Cleanup(reset)
	var handled, previewed int32
	Register(Definition{
		Name:   "dry.x",
		Impact: ImpactHigh,
		Input:  echoSchema,
		Handle: func(context.Context, ActionCtx, json.RawMessage) (any, error) {
			atomic.AddInt32(&handled, 1)
			return nil, nil
		},
		Preview: func(_ context.Context, _ ActionCtx, in json.RawMessage) (any, error) {
			atomic.AddInt32(&previewed, 1)
			return map[string]string{"preview": "yes"}, nil
		},
	})
	audit := &recordingAudit{}
	d := New(dbtest.New(t), WithAuditSink(audit))
	out, err := d.Dispatch(context.Background(), userActor(), "dry.x",
		json.RawMessage(`{"name":"z"}`), Opts{DryRun: true, Idem: "should-not-store"})
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if handled != 0 {
		t.Fatal("Handle ran during dry run")
	}
	if previewed != 1 {
		t.Fatalf("Preview ran %d times, want 1", previewed)
	}
	if !strings.Contains(mustJSON(t, out), "preview") {
		t.Fatalf("dry run out = %s", mustJSON(t, out))
	}
	if len(audit.entries) != 0 {
		t.Fatal("dry run must not audit")
	}
}

func TestDispatchDryRunNilPreviewEchoesInput(t *testing.T) {
	reset()
	t.Cleanup(reset)
	Register(Definition{
		Name:   "dryecho.x",
		Impact: ImpactLow,
		Input:  echoSchema,
		Handle: nopHandle,
		// Preview intentionally nil.
	})
	d := New(dbtest.New(t))
	in := json.RawMessage(`{"name":"echo"}`)
	out, err := d.Dispatch(context.Background(), userActor(), "dryecho.x", in, Opts{DryRun: true})
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if string(out.(json.RawMessage)) != string(in) {
		t.Fatalf("echo out = %s, want %s", out.(json.RawMessage), in)
	}
}

// --- Audit ------------------------------------------------------------------

func TestDispatchImpactHighEmitsAudit(t *testing.T) {
	reset()
	t.Cleanup(reset)
	Register(Definition{
		Name:   "high.x",
		Impact: ImpactHigh,
		Handle: func(context.Context, ActionCtx, json.RawMessage) (any, error) {
			return resultWithID{ID: "subj-1"}, nil
		},
	})
	Register(Definition{
		Name:   "low.x",
		Impact: ImpactLow,
		Handle: nopHandle,
	})
	audit := &recordingAudit{}
	d := New(dbtest.New(t), WithAuditSink(audit))
	ctx := context.Background()

	if _, err := d.Dispatch(ctx, userActor(), "high.x", nil, Opts{Org: "org-1"}); err != nil {
		t.Fatalf("high dispatch: %v", err)
	}
	// A low-impact user action must NOT audit.
	if _, err := d.Dispatch(ctx, userActor(), "low.x", nil, Opts{Org: "org-1"}); err != nil {
		t.Fatalf("low dispatch: %v", err)
	}
	if len(audit.entries) != 1 {
		t.Fatalf("audit rows = %d, want 1 (only ImpactHigh)", len(audit.entries))
	}
	e := audit.entries[0]
	if e.Action != "high.x" || e.ActorType != ActorUser || e.Subject != "subj-1" || e.Org != "org-1" || e.IP != "203.0.113.5" {
		t.Fatalf("audit entry = %+v", e)
	}
}

func TestDispatchAgentActionAlwaysAudited(t *testing.T) {
	reset()
	t.Cleanup(reset)
	Register(Definition{Name: "agentlow.x", Impact: ImpactLow, Handle: nopHandle})
	audit := &recordingAudit{}
	d := New(dbtest.New(t), WithAuditSink(audit))
	// Low-impact but by an agent → audited.
	if _, err := d.Dispatch(context.Background(), agentActor(), "agentlow.x", nil, Opts{Org: "org-1"}); err != nil {
		t.Fatalf("agent dispatch: %v", err)
	}
	if len(audit.entries) != 1 || audit.entries[0].ActorType != ActorAgent {
		t.Fatalf("expected one agent audit row, got %+v", audit.entries)
	}
}

// The default DB-backed audit sink actually writes a row.
func TestDefaultAuditSinkWritesRow(t *testing.T) {
	reset()
	t.Cleanup(reset)
	Register(Definition{Name: "dbaudit.x", Impact: ImpactHigh, Handle: nopHandle})
	sqldb := dbtest.New(t)
	d := New(sqldb)
	if _, err := d.Dispatch(context.Background(), userActor(), "dbaudit.x", nil, Opts{Org: "org-9"}); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	var n int
	if err := sqldb.QueryRow(`SELECT count(*) FROM audit_log WHERE action = ? AND org_id = ?`, "dbaudit.x", "org-9").Scan(&n); err != nil {
		t.Fatalf("query audit_log: %v", err)
	}
	if n != 1 {
		t.Fatalf("audit_log rows = %d, want 1", n)
	}
}

// --- Events -----------------------------------------------------------------

func TestDispatchEmitsEventWithActor(t *testing.T) {
	reset()
	t.Cleanup(reset)
	Register(Definition{
		Name:   "ev.x",
		Impact: ImpactLow,
		Handle: func(context.Context, ActionCtx, json.RawMessage) (any, error) {
			return resultWithID{ID: "ev-subj"}, nil
		},
	})
	sink := &recordingEvents{}
	d := New(dbtest.New(t), WithEventSink(sink))
	if _, err := d.Dispatch(context.Background(), agentActor(), "ev.x", nil, Opts{Org: "org-1"}); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if len(sink.events) != 1 {
		t.Fatalf("events = %d, want 1", len(sink.events))
	}
	ev := sink.events[0]
	if ev.Name != "ev.x" || ev.Org != "org-1" || ev.Actor.Type != ActorAgent || ev.Actor.ID != "a1" {
		t.Fatalf("event = %+v", ev)
	}
	if ev.Subject != "ev-subj" {
		t.Fatalf("event subject = %q, want ev-subj", ev.Subject)
	}
	if !strings.Contains(string(ev.Payload), "ev-subj") {
		t.Fatalf("event payload = %s", ev.Payload)
	}
}

func TestDryRunEmitsNoEvent(t *testing.T) {
	reset()
	t.Cleanup(reset)
	Register(Definition{Name: "evdry.x", Impact: ImpactLow, Handle: nopHandle})
	sink := &recordingEvents{}
	d := New(dbtest.New(t), WithEventSink(sink))
	if _, err := d.Dispatch(context.Background(), userActor(), "evdry.x", nil, Opts{DryRun: true}); err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if len(sink.events) != 0 {
		t.Fatal("dry run must emit no event")
	}
}

// --- Permission hook --------------------------------------------------------

func TestDispatchForbiddenWhenPermDenies(t *testing.T) {
	reset()
	t.Cleanup(reset)
	var ran int32
	Register(Definition{
		Name:   "perm.x",
		Impact: ImpactLow,
		Handle: func(context.Context, ActionCtx, json.RawMessage) (any, error) {
			atomic.AddInt32(&ran, 1)
			return nil, nil
		},
	})
	d := New(dbtest.New(t), WithPermissionChecker(denyPerm{}))
	_, err := d.Dispatch(context.Background(), userActor(), "perm.x", nil, Opts{})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
	if ran != 0 {
		t.Fatal("handler ran despite permission denial")
	}
}

// --- Approval gate ----------------------------------------------------------

func TestDispatchApprovalPending(t *testing.T) {
	reset()
	t.Cleanup(reset)
	var ran int32
	Register(Definition{
		Name:   "appr.x",
		Impact: ImpactHigh,
		Handle: func(context.Context, ActionCtx, json.RawMessage) (any, error) {
			atomic.AddInt32(&ran, 1)
			return nil, nil
		},
	})
	d := New(dbtest.New(t), WithApprovalGate(pendingGate{id: "appr-77"}))
	// Approval gate only applies to agents.
	_, err := d.Dispatch(context.Background(), agentActor(), "appr.x", nil, Opts{})
	var pending ErrApprovalPending
	if !errors.As(err, &pending) {
		t.Fatalf("err = %v, want ErrApprovalPending", err)
	}
	if pending.ID != "appr-77" {
		t.Fatalf("approval id = %q, want appr-77", pending.ID)
	}
	if ran != 0 {
		t.Fatal("handler ran despite pending approval")
	}
}

func TestApprovalGateSkippedForNonAgent(t *testing.T) {
	reset()
	t.Cleanup(reset)
	Register(Definition{Name: "apprskip.x", Impact: ImpactHigh, Handle: nopHandle})
	// Even a forbidding gate is ignored for a user actor.
	d := New(dbtest.New(t), WithApprovalGate(forbidGate{}))
	if _, err := d.Dispatch(context.Background(), userActor(), "apprskip.x", nil, Opts{}); err != nil {
		t.Fatalf("user should bypass approval gate, got %v", err)
	}
}

func TestDispatchApprovalForbid(t *testing.T) {
	reset()
	t.Cleanup(reset)
	Register(Definition{Name: "apprforbid.x", Impact: ImpactHigh, Handle: nopHandle})
	d := New(dbtest.New(t), WithApprovalGate(forbidGate{}))
	if _, err := d.Dispatch(context.Background(), agentActor(), "apprforbid.x", nil, Opts{}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
}

// --- Scope hook -------------------------------------------------------------

func TestDispatchScopeFailure(t *testing.T) {
	reset()
	t.Cleanup(reset)
	Register(Definition{Name: "scope.x", Impact: ImpactLow, Scope: ScopeOrg, Handle: nopHandle})
	d := New(dbtest.New(t), WithScopeResolver(denyScope{}))
	if _, err := d.Dispatch(context.Background(), userActor(), "scope.x", nil, Opts{Org: "nope"}); !errors.Is(err, ErrScope) {
		t.Fatalf("err = %v, want ErrScope", err)
	}
}

// --- Transaction rollback ---------------------------------------------------

// A handler that writes through ac.Tx then errors must leave no row committed.
func TestHandlerErrorRollsBackTx(t *testing.T) {
	reset()
	t.Cleanup(reset)
	Register(Definition{
		Name:   "rollback.x",
		Impact: ImpactLow,
		Handle: func(ctx context.Context, ac ActionCtx, _ json.RawMessage) (any, error) {
			// Write a row through the dispatch tx (idempotency_keys has no FK),
			// then fail — the write must not survive.
			if err := ac.Tx.CreateIdempotencyKey(ctx, txProbeParams("rollback-probe")); err != nil {
				return nil, err
			}
			return nil, errors.New("boom")
		},
	})
	sqldb := dbtest.New(t)
	d := New(sqldb)
	_, err := d.Dispatch(context.Background(), userActor(), "rollback.x", nil, Opts{})
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("err = %v, want boom", err)
	}
	if n := probeCount(t, sqldb, "rollback-probe"); n != 0 {
		t.Fatalf("probe rows = %d, want 0 (tx should have rolled back)", n)
	}
}

// A successful handler commits its writes through ac.Tx.
func TestHandlerSuccessCommitsTx(t *testing.T) {
	reset()
	t.Cleanup(reset)
	Register(Definition{
		Name:   "commit.x",
		Impact: ImpactLow,
		Handle: func(ctx context.Context, ac ActionCtx, _ json.RawMessage) (any, error) {
			return nil, ac.Tx.CreateIdempotencyKey(ctx, txProbeParams("commit-probe"))
		},
	})
	sqldb := dbtest.New(t)
	d := New(sqldb)
	if _, err := d.Dispatch(context.Background(), userActor(), "commit.x", nil, Opts{}); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if n := probeCount(t, sqldb, "commit-probe"); n != 1 {
		t.Fatalf("probe rows = %d, want 1", n)
	}
}

// --- Clock injection --------------------------------------------------------

func TestClockInjectable(t *testing.T) {
	reset()
	t.Cleanup(reset)
	Register(Definition{Name: "clock.x", Impact: ImpactHigh, Handle: nopHandle})
	fixed := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	sqldb := dbtest.New(t)
	d := New(sqldb, WithClock(func() time.Time { return fixed }))
	if _, err := d.Dispatch(context.Background(), userActor(), "clock.x", nil, Opts{Org: "o"}); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	var ts string
	if err := sqldb.QueryRow(`SELECT created_at FROM audit_log WHERE action = ?`, "clock.x").Scan(&ts); err != nil {
		t.Fatalf("query: %v", err)
	}
	if !strings.HasPrefix(ts, "2030-01-02T03:04:05") {
		t.Fatalf("audit created_at = %q, want fixed clock time", ts)
	}
}
