package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/event"
	"github.com/thomasteoh/boardchestrator/internal/job"
)

func seedOrg(t *testing.T, db *sql.DB, orgID string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO orgs (id, name, slug, visibility, context, monthly_cap_usd, cap_alert_pct) VALUES (?, 'Acme', 'acme', 'private', '', 0, 80)`, orgID); err != nil {
		t.Fatalf("seed org: %v", err)
	}
}

func seedWebhook(t *testing.T, db *sql.DB, orgID, url, secret, filter string) sqlc.Webhook {
	t.Helper()
	q := sqlc.New(db)
	wh, err := q.CreateWebhook(context.Background(), sqlc.CreateWebhookParams{
		ID: "wh1", OrgID: orgID, Name: "hook", Url: url, Secret: secret, EventFilter: filter, Enabled: 1,
	})
	if err != nil {
		t.Fatalf("seed webhook: %v", err)
	}
	return wh
}

// newDeliverer returns a Deliverer with an injectable client + resolver.
func newDeliverer(t *testing.T, db *sql.DB, client *http.Client, resolve func(ctx context.Context, network, addr string) ([]net.IP, error)) *Deliverer {
	t.Helper()
	d := New(db, job.NewJobStore(db))
	d.client = client
	if resolve != nil {
		d.resolve = resolve
	} else {
		// Default for httptest hosts (loopback): report a public IP so the SSRF
		// guard approves; the client connects to the real loopback address.
		d.resolve = publicResolver
	}
	return d
}

// publicResolver reports a public IP for any host, satisfying the SSRF guard
// while the HTTP client still connects to the real (loopback) test address.
func publicResolver(ctx context.Context, network, addr string) ([]net.IP, error) {
	return []net.IP{net.ParseIP("203.0.113.10")}, nil
}

// TestSignatureGolden covers AC: the HMAC-SHA256 signature header matches a
// golden value computed over the exact body bytes.
func TestSignatureGolden(t *testing.T) {
	db := dbtest.New(t)
	seedOrg(t, db, "org1")
	// Capture the delivered body + signature header on a local server.
	var gotBody, gotSig string
	var gotEvent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		gotSig = r.Header.Get(SignatureHeader)
		gotEvent = r.Header.Get("X-Event-Name")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wh := seedWebhook(t, db, "org1", srv.URL, "s3cret", "[]")
	d := newDeliverer(t, db, srv.Client(), nil)
	ev := event.Event{Name: "task.create", Org: "org1", ActorType: "user", ActorID: "u1", Subject: "t1", Payload: json.RawMessage(`{"id":"t1"}`)}
	if err := d.HandleEvent(context.Background(), ev); err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}

	// Run the queued delivery job.
	dlv := findDelivery(t, db, wh.ID)
	job := findJob(t, db, "wd-"+dlv.ID)
	t.Logf("job payload: %s", job.PayloadJson)
	if err := d.RunJob(context.Background(), job); err != nil {
		t.Fatalf("RunJob: %v", err)
	}

	// Golden check: recompute HMAC over the captured body and compare to the
	// received signature header.
	mac := hmac.New(sha256.New, []byte(wh.Secret))
	mac.Write([]byte(gotBody))
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if gotSig != want {
		t.Fatalf("signature mismatch: got %q want %q", gotSig, want)
	}
	if gotEvent != "task.create" {
		t.Fatalf("event header %q", gotEvent)
	}
	// Body envelope must carry the event payload.
	if !strings.Contains(gotBody, `"event":"task.create"`) || !strings.Contains(gotBody, `"id":"t1"`) {
		t.Fatalf("body missing envelope: %s", gotBody)
	}
}

// TestDeliveryRetryAndDeadLetter covers AC: a failing endpoint is retried with
// backoff then dead-lettered on exhaustion (delivery status → dead).
func TestDeliveryRetryAndDeadLetter(t *testing.T) {
	db := dbtest.New(t)
	seedOrg(t, db, "org1")
	// Always-500 endpoint.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	wh := seedWebhook(t, db, "org1", srv.URL, "", "[]")

	// Inject a delivery row + job directly, then run the job maxAttempts times.
	q := sqlc.New(db)
	body := `{"event":"task.create"}`
	dlv, err := q.CreateWebhookDelivery(context.Background(), sqlc.CreateWebhookDeliveryParams{
		ID: "d1", WebhookID: wh.ID, EventName: "task.create", EventJson: body, Status: "queued", MaxAttempts: 3,
	})
	if err != nil {
		t.Fatalf("seed delivery: %v", err)
	}
	d := newDeliverer(t, db, srv.Client(), nil)

	// First attempt: 500 → retry (failed, attempts 1).
	j := sqlc.Job{ID: "wd-d1", Kind: "webhook.deliver", PayloadJson: fmt.Sprintf(`{"webhook_id":%q,"delivery_id":%q,"url":%q,"secret":""}`, wh.ID, dlv.ID, srv.URL), Attempts: 0, MaxAttempts: 3}
	if err := d.RunJob(context.Background(), j); err != nil {
		t.Fatalf("RunJob: %v", err)
	}
	// The store.Fail path — check the job was marked failed-with-retry.
	state := findDeliveryState(t, db, "d1")
	if state.status != "failed" || state.attempts != 1 {
		t.Fatalf("after attempt 1: status=%s attempts=%d, want failed/1", state.status, state.attempts)
	}

	// Attempt 2 + 3 exhaust max_attempts → dead.
	for _, a := range []int64{1, 2} {
		j.Attempts = a
		if err := d.RunJob(context.Background(), j); err != nil {
			t.Fatalf("RunJob: %v", err)
		}
	}
	state = findDeliveryState(t, db, "d1")
	if state.status != "dead" {
		t.Fatalf("after exhaustion: status=%s, want dead", state.status)
	}
}

// TestSSRFPinning covers AC: a private/loopback resolved address is rejected
// (DNS-rebind simulation) — resolve returns a private IP, delivery is blocked.
func TestSSRFPinning(t *testing.T) {
	db := dbtest.New(t)
	seedOrg(t, db, "org1")
	wh := seedWebhook(t, db, "org1", "http://rebind.example/hook", "", "[]")

	// Simulate a DNS rebind: public hostname resolving to a private address.
	resolve := func(ctx context.Context, network, addr string) ([]net.IP, error) {
		if addr == "rebind.example" {
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		}
		return nil, fmt.Errorf("no such host")
	}
	d := newDeliverer(t, db, http.DefaultClient, resolve)
	ev := event.Event{Name: "task.create", Org: "org1", ActorType: "user", ActorID: "u1", Subject: "t1", Payload: json.RawMessage(`{}`)}
	if err := d.HandleEvent(context.Background(), ev); err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	dlv := findDelivery(t, db, wh.ID)
	j := findJob(t, db, "wd-"+dlv.ID)
	// The delivery must fail (SSRF blocked), not reach the endpoint.
	if err := d.RunJob(context.Background(), j); err != nil {
		t.Fatalf("RunJob returned error (expected nil, delivery marked failed): %v", err)
	}
	state := findDeliveryState(t, db, dlv.ID)
	if state.status == "delivered" {
		t.Fatalf("private address delivered — SSRF guard bypassed")
	}
	if !strings.Contains(state.err, "ssrf") {
		t.Fatalf("expected ssrf error, got %q", state.err)
	}
}

// TestEventFilter covers AC: a webhook with an event filter only receives
// matching events.
func TestEventFilter(t *testing.T) {
	db := dbtest.New(t)
	seedOrg(t, db, "org1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	// Filter on task.update only.
	seedWebhook(t, db, "org1", srv.URL, "", `["task.update"]`)

	d := newDeliverer(t, db, srv.Client(), nil)
	// A non-matching event must not enqueue a delivery.
	if err := d.HandleEvent(context.Background(), event.Event{Name: "task.create", Org: "org1", Subject: "t1"}); err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	if n := countDeliveries(t, db); n != 0 {
		t.Fatalf("non-matching event enqueued %d deliveries, want 0", n)
	}
	// A matching event enqueues exactly one.
	if err := d.HandleEvent(context.Background(), event.Event{Name: "task.update", Org: "org1", Subject: "t2"}); err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	if n := countDeliveries(t, db); n != 1 {
		t.Fatalf("matching event enqueued %d deliveries, want 1", n)
	}
}

// --- helpers ---

type deliveryState struct {
	status   string
	attempts int64
	err      string
}

func findDelivery(t *testing.T, db *sql.DB, webhookID string) sqlc.WebhookDelivery {
	t.Helper()
	var d sqlc.WebhookDelivery
	rows, err := db.Query(`SELECT id, webhook_id, event_name, event_json, status, attempts, max_attempts, response_code, error, created_at, updated_at FROM webhook_deliveries WHERE webhook_id = ?`, webhookID)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		t.Fatal("no delivery row")
	}
	var rc sql.NullInt64
	var er sql.NullString
	if err := rows.Scan(&d.ID, &d.WebhookID, &d.EventName, &d.EventJson, &d.Status, &d.Attempts, &d.MaxAttempts, &rc, &er, &d.CreatedAt, &d.UpdatedAt); err != nil {
		t.Fatalf("scan: %v", err)
	}
	return d
}

func findDeliveryState(t *testing.T, db *sql.DB, id string) deliveryState {
	t.Helper()
	var st deliveryState
	var er sql.NullString
	err := db.QueryRow(`SELECT status, attempts, error FROM webhook_deliveries WHERE id = ?`, id).Scan(&st.status, &st.attempts, &er)
	if err != nil {
		t.Fatalf("state query: %v", err)
	}
	if er.Valid {
		st.err = er.String
	}
	return st
}

func findJob(t *testing.T, db *sql.DB, id string) sqlc.Job {
	t.Helper()
	var j sqlc.Job
	var lb, la sql.NullString
	err := db.QueryRow(`SELECT id, kind, payload_json, run_at, attempts, max_attempts, status, locked_by, locked_at, created_at FROM jobs WHERE id = ?`, id).
		Scan(&j.ID, &j.Kind, &j.PayloadJson, &j.RunAt, &j.Attempts, &j.MaxAttempts, &j.Status, &lb, &la, &j.CreatedAt)
	if err != nil {
		t.Fatalf("job query: %v", err)
	}
	return j
}

func countDeliveries(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM webhook_deliveries`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}
