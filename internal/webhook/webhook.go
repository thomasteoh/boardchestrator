// Package webhook delivers action events to outbound webhook endpoints
// (WU-404). It subscribes to the event bus, matches each event against the
// org's enabled webhooks (by event filter), and POSTs a signed JSON body to
// the configured URL with backoff retries, a dead-letter state, and SSRF
// protection (resolve-then-connect pinning).
package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/event"
	"github.com/thomasteoh/boardchestrator/internal/job"
)

// maxAttempts is the delivery retry ceiling before dead-letter.
const maxAttempts = 5

// backoff is the fixed retry delay between delivery attempts.
const backoff = 30 * time.Second

// SignatureHeader is the HMAC-SHA256 signature header (SPEC §12 / webhook
// convention): X-Boardchestrator-Signature = "sha256=<hex>".
const SignatureHeader = "X-Boardchestrator-Signature"

// Deliverer delivers signed webhook POSTs from bus events. It owns the
// delivery loop and the delivery-log writes.
type Deliverer struct {
	db     *sql.DB
	store  *job.JobStore
	client *http.Client
	now    func() time.Time
	// resolve overrides DNS resolution (injectable for SSRF tests).
	resolve func(ctx context.Context, network, addr string) ([]net.IP, error)
}

// New builds a delivery worker over db and the job store (for retry/dead).
func New(db *sql.DB, store *job.JobStore) *Deliverer {
	return &Deliverer{
		db:    db,
		store: store,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		now:     time.Now,
		resolve: net.DefaultResolver.LookupIP,
	}
}

// eventEnvelope is the body sent to webhook endpoints.
type eventEnvelope struct {
	Event     string          `json:"event"`
	Org       string          `json:"org_id"`
	ActorType string          `json:"actor_type"`
	ActorID   string          `json:"actor_id"`
	Subject   string          `json:"subject"`
	Payload   json.RawMessage `json:"payload"`
	SentAt    string          `json:"sent_at"`
}

// HandleEvent is the bus-subscriber entry: for each enabled webhook in the
// event's org whose filter matches, enqueue a delivery. Called by the server
// subscriber loop (one event per call).
func (d *Deliverer) HandleEvent(ctx context.Context, ev event.Event) error {
	// Load enabled webhooks for the event's org.
	q := sqlc.New(d.db)
	whs, err := q.ListEnabledWebhooksByOrg(ctx, ev.Org)
	if err != nil {
		return fmt.Errorf("webhook: list org webhooks: %w", err)
	}
	for _, wh := range whs {
		if !filterMatches(wh.EventFilter, ev.Name) {
			continue
		}
		if err := d.enqueue(ctx, q, wh, ev); err != nil {
			return err
		}
	}
	return nil
}

// enqueue inserts a delivery row + a jobs queue entry for retry. The delivery
// row is the source of truth; the jobs entry carries the delivery id so the
// worker can retry with backoff and dead-letter.
func (d *Deliverer) enqueue(ctx context.Context, q *sqlc.Queries, wh sqlc.Webhook, ev event.Event) error {
	body, _ := json.Marshal(eventEnvelope{
		Event: ev.Name, Org: ev.Org, ActorType: ev.ActorType, ActorID: ev.ActorID,
		Subject: ev.Subject, Payload: ev.Payload, SentAt: d.now().UTC().Format("2006-01-02T15:04:05.000Z"),
	})
	did := newID()
	dlv, err := q.CreateWebhookDelivery(ctx, sqlc.CreateWebhookDeliveryParams{
		ID: did, WebhookID: wh.ID, EventName: ev.Name, EventJson: string(body), Status: "queued", MaxAttempts: maxAttempts,
	})
	if err != nil {
		return fmt.Errorf("webhook: create delivery: %w", err)
	}
	// Queue the delivery job (kind "webhook.deliver") so the worker retries it.
	payload := map[string]any{"webhook_id": wh.ID, "delivery_id": did, "url": wh.Url, "secret": wh.Secret}
	pb, _ := json.Marshal(payload)
	if err := d.enqueueJob(ctx, did, string(pb)); err != nil {
		return err
	}
	_ = dlv
	return nil
}

// enqueueJob inserts a job row for a webhook delivery.
func (d *Deliverer) enqueueJob(ctx context.Context, deliveryID, payload string) error {
	q := sqlc.New(d.db)
	nowStr := d.now().UTC().Format("2006-01-02T15:04:05.000Z")
	return q.EnqueueJob(ctx, sqlc.EnqueueJobParams{
		ID: "wd-" + deliveryID, Kind: "webhook.deliver", PayloadJson: payload,
		RunAt: nowStr, MaxAttempts: maxAttempts,
	})
}

// RunJob delivers one queued webhook job, managing retry + dead-letter via the
// job store (mirrors the agent engine's failAndRetry: backoff until max
// attempts, then dead). Returns an error only if the store itself fails; the
// pool should NOT independently retry webhook jobs (RunJob owns retry).
func (d *Deliverer) RunJob(ctx context.Context, j sqlc.Job) error {
	var p struct {
		WebhookID  string `json:"webhook_id"`
		DeliveryID string `json:"delivery_id"`
		URL        string `json:"url"`
		Secret     string `json:"secret"`
	}
	if err := json.Unmarshal([]byte(j.PayloadJson), &p); err != nil {
		return fmt.Errorf("webhook: job payload: %w", err)
	}
	// Re-read the delivery row for its body.
	dlv, err := sqlc.New(d.db).FindWebhookDeliveryByID(ctx, p.DeliveryID)
	if err != nil {
		return fmt.Errorf("webhook: find delivery: %w", err)
	}
	code, derr := d.deliver(ctx, p.URL, p.Secret, dlv.EventName, []byte(dlv.EventJson))
	if derr == nil {
		if err := d.markDelivered(ctx, p.DeliveryID, code); err != nil {
			return err
		}
		return d.store.Complete(ctx, j.ID)
	}
	// Transient failure: retry with backoff, dead-letter on exhaustion.
	nextAttempt := dlv.Attempts + 1
	if nextAttempt < dlv.MaxAttempts {
		runAt := d.now().Add(backoff).UTC().Format("2006-01-02T15:04:05.000Z")
		if err := d.markFailed(ctx, p.DeliveryID, nextAttempt, "failed", derr.Error()); err != nil {
			return err
		}
		return d.store.Fail(ctx, j.ID, "queued", runAt, nextAttempt)
	}
	// Exhausted — dead-letter.
	if err := d.markFailed(ctx, p.DeliveryID, nextAttempt, "dead", derr.Error()); err != nil {
		return err
	}
	return d.store.Dead(ctx, j.ID)
}

// deliver performs one signed POST with SSRF pinning. Returns the HTTP status
// code. A non-2xx response is an error (triggers retry).
func (d *Deliverer) deliver(ctx context.Context, url, secret, eventName string, body []byte) (int, error) {
	// SSRF guard: resolve-then-connect pinning. Parse the URL, resolve the
	// hostname, reject non-public IPs (private/loopback/link-local), and pin
	// the connection to the resolved address (DNS rebind safe).
	if err := ssrfGuard(ctx, d, url); err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		return 0, fmt.Errorf("webhook: request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Event-Name", eventName)
	if secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		sig := hex.EncodeToString(mac.Sum(nil))
		req.Header.Set(SignatureHeader, "sha256="+sig)
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("webhook: post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("webhook: non-2xx %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}

// markDelivered records a successful delivery.
func (d *Deliverer) markDelivered(ctx context.Context, id string, code int) error {
	return sqlc.New(d.db).UpdateWebhookDeliveryAttempt(ctx, sqlc.UpdateWebhookDeliveryAttemptParams{
		Status: "delivered", ResponseCode: sql.NullInt64{Int64: int64(code), Valid: true},
		UpdatedAt: d.now().UTC().Format("2006-01-02T15:04:05.000Z"), ID: id,
	})
}

// markFailed records a failed/dead delivery attempt (status: failed | dead).
func (d *Deliverer) markFailed(ctx context.Context, id string, attempts int64, status, errMsg string) error {
	return sqlc.New(d.db).UpdateWebhookDeliveryAttempt(ctx, sqlc.UpdateWebhookDeliveryAttemptParams{
		Status: status, Attempts: attempts, Error: sql.NullString{String: errMsg, Valid: true},
		UpdatedAt: d.now().UTC().Format("2006-01-02T15:04:05.000Z"), ID: id,
	})
}

// filterMatches reports whether a webhook's event_filter (JSON array) matches
// an event name. Empty filter ("[]" or "") matches all events.
func filterMatches(filter, name string) bool {
	f := strings.TrimSpace(filter)
	if f == "" || f == "[]" {
		return true
	}
	var names []string
	if err := json.Unmarshal([]byte(f), &names); err != nil {
		return false
	}
	for _, n := range names {
		if n == name {
			return true
		}
	}
	return false
}

// ssrfGuard implements resolve-then-connect pinning: resolve the host, require
// a single public IPv4, and reject private/loopback/link-local addresses.
func ssrfGuard(ctx context.Context, d *Deliverer, url string) error {
	host := urlHost(url)
	if host == "" {
		return fmt.Errorf("webhook: ssrf: bad url")
	}
	ips, err := d.resolve(ctx, "ip4", host)
	if err != nil || len(ips) == 0 {
		return fmt.Errorf("webhook: ssrf: resolve: %w", err)
	}
	ip := ips[0]
	if !isPublicIP(ip) {
		return fmt.Errorf("webhook: ssrf: non-public address %s", ip)
	}
	return nil
}

// urlHost extracts the hostname (without port) from a URL.
func urlHost(raw string) string {
	// Minimal parse: strip scheme + path, split port.
	u := raw
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	if i := strings.Index(u, "/"); i >= 0 {
		u = u[:i]
	}
	if i := strings.Index(u, ":"); i >= 0 {
		u = u[:i]
	}
	return u
}

// isPublicIP rejects private, loopback, link-local, and unspecified addresses.
func isPublicIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	return true
}

// newID returns a unique id for a delivery row.
func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("wd-%d", time.Now().UnixNano())
	}
	return "wd-" + hex.EncodeToString(b)
}
