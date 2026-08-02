// Package sse serves the realtime /events stream (SPEC §8). A Hub subscribes to
// the event bus, keys live client connections by user id, and fans matching
// events to each connection's SSE response as named text/event-stream frames.
// It heartbeats every ~25s, and supports best-effort replay from a small
// per-hub ring buffer via the Last-Event-ID header so a client that briefly
// disconnects can catch up.
//
// The endpoint needs to know who the current user is. Rather than parse cookies
// here (duplicating internal/auth), the Hub takes a UserResolver seam: the real
// wiring uses auth.SessionFrom (the session middleware already stashes the
// resolved user in the request context, WU-005), and tests inject a stub. This
// matches BACKLOG WU-007's "session auth stub interface".
package sse

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/event"
)

// Named SSE event types sent to the browser (SPEC §3, §8). The framing helper
// (frame) writes these in the `event:` line; app.js dispatches on them.
const (
	EventTaskUpdated  = "task-updated"
	EventNotification = "notification"
	EventChatDelta    = "chat-delta"
	EventRunStatus    = "run-status"
)

// HeartbeatInterval is how often an idle stream emits an SSE comment ping to
// keep the connection alive through proxies (SPEC §8: ~25s).
const HeartbeatInterval = 25 * time.Second

// ringSize is the per-hub Last-Event-ID replay buffer depth. Best-effort: a
// client offline longer than ringSize events behind cannot fully catch up and
// should refetch. Small, so memory is bounded regardless of throughput.
const ringSize = 256

// UserResolver reports the authenticated user id for a request, or "" if the
// request is unauthenticated. The production resolver reads the session the
// auth middleware placed in the context; tests inject a stub.
type UserResolver func(r *http.Request) (userID string, ok bool)

// SessionUserResolver is the production resolver: it reads the session that the
// auth session middleware (WU-005) stashed in the request context.
func SessionUserResolver(r *http.Request) (string, bool) {
	sess, ok := auth.SessionFrom(r.Context())
	if !ok || sess.UserID == "" {
		return "", false
	}
	return sess.UserID, true
}

// eventNameFor maps an action event name to the SSE event name the browser
// listens for. Unmapped actions fall back to a generic "message" event so new
// actions still stream without a code change here.
func eventNameFor(actionName string) string {
	switch {
	case actionName == "task.move" || hasPrefix(actionName, "task."):
		return EventTaskUpdated
	case actionName == "notification.markread" || hasPrefix(actionName, "notification."):
		return EventNotification
	case hasPrefix(actionName, "chat."):
		return EventChatDelta
	case hasPrefix(actionName, "run."):
		return EventRunStatus
	default:
		return "message"
	}
}

func hasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }

// client is one live SSE connection for a user.
type client struct {
	userID string
	ch     chan sseMessage
}

// sseMessage is a framed, ready-to-write event plus its monotonic id.
// Heartbeats are not modelled here — they are ticker-driven comment lines
// written directly by the handler (writeComment).
type sseMessage struct {
	id   uint64
	name string
	data []byte
}

// Hub fans bus events to connected clients. Construct with New; call Run once
// (typically in a goroutine) to pump from the bus, and Handler for the route.
type Hub struct {
	bus      *event.Bus
	resolve  UserResolver
	buffer   int
	interval time.Duration

	seq atomic.Uint64 // last assigned event id

	mu   sync.RWMutex
	subs map[*client]struct{}

	ringMu sync.Mutex
	ring   []sseMessage // fixed-size replay buffer, oldest evicted
}

// Option configures a Hub.
type Option func(*Hub)

// WithHeartbeat overrides the heartbeat interval (test seam).
func WithHeartbeat(d time.Duration) Option { return func(h *Hub) { h.interval = d } }

// WithClientBuffer overrides the per-client channel buffer.
func WithClientBuffer(n int) Option { return func(h *Hub) { h.buffer = n } }

// New builds a Hub over bus using resolve to authenticate connections.
func New(bus *event.Bus, resolve UserResolver, opts ...Option) *Hub {
	h := &Hub{
		bus:      bus,
		resolve:  resolve,
		buffer:   32,
		interval: HeartbeatInterval,
		subs:     map[*client]struct{}{},
		ring:     make([]sseMessage, 0, ringSize),
	}
	for _, o := range opts {
		o(h)
	}
	return h
}

// Run subscribes to the bus and pumps events to clients until ctx is cancelled.
// Call once. It converts each bus Event into a framed SSE message, records it in
// the ring buffer, and delivers it (non-blocking) to every client for the
// event's audience.
func (h *Hub) Run(ctx context.Context) {
	sub, cancel := h.bus.Subscribe(event.Filter{}, h.buffer*4)
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-sub.C:
			h.dispatch(ev)
		}
	}
}

// dispatch frames a bus event, records it for replay, and delivers it to
// clients. For Phase 0 every authenticated client receives every event (there
// are no orgs/memberships yet — WU-104); the audience narrows to org members in
// later WUs. Delivery is per-client non-blocking: a stalled client drops the
// event (bus-level slow-consumer protection already covered the publisher).
func (h *Hub) dispatch(ev event.Event) {
	id := h.seq.Add(1)
	name := eventNameFor(ev.Name)
	data := marshalData(ev)
	msg := sseMessage{id: id, name: name, data: data}
	h.record(msg)

	h.mu.RLock()
	defer h.mu.RUnlock()
	for c := range h.subs {
		select {
		case c.ch <- msg:
		default:
			// Client buffer full: drop for this client. It will refetch on
			// reconnect; the ring buffer covers brief gaps.
		}
	}
}

// sseData is the JSON body of a data: line.
type sseData struct {
	Name    string          `json:"name"`
	Org     string          `json:"org,omitempty"`
	Subject string          `json:"subject,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

func marshalData(ev event.Event) []byte {
	b, err := json.Marshal(sseData{
		Name:    ev.Name,
		Org:     ev.Org,
		Subject: ev.Subject,
		Payload: ev.Payload,
	})
	if err != nil {
		// Payload is already valid JSON from the action layer; a failure here
		// is not actionable, so fall back to an empty object.
		return []byte("{}")
	}
	return b
}

// record appends msg to the ring buffer, evicting the oldest when full.
func (h *Hub) record(msg sseMessage) {
	h.ringMu.Lock()
	defer h.ringMu.Unlock()
	if len(h.ring) < ringSize {
		h.ring = append(h.ring, msg)
		return
	}
	copy(h.ring, h.ring[1:])
	h.ring[len(h.ring)-1] = msg
}

// replaySince returns buffered messages with id strictly greater than lastID,
// in order. Best-effort: if lastID is older than the buffer's oldest entry the
// client has missed events beyond the buffer and should refetch (it still gets
// whatever remains).
func (h *Hub) replaySince(lastID uint64) []sseMessage {
	h.ringMu.Lock()
	defer h.ringMu.Unlock()
	out := make([]sseMessage, 0, len(h.ring))
	for _, m := range h.ring {
		if m.id > lastID {
			out = append(out, m)
		}
	}
	return out
}

// Handler serves the /events SSE stream. It authenticates via the resolver
// (401 if unauthenticated), sets the SSE headers, replays any events after
// Last-Event-ID, then streams live events until the client disconnects (request
// context cancelled). It heartbeats every interval.
func (h *Hub) Handler(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.resolve(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	h.setSSEHeaders(w)
	w.WriteHeader(http.StatusOK)
	// Flush the response headers immediately so the client's connection is
	// established before any event arrives. Without this the headers stay
	// buffered until the first body write, and an EventSource (or test client)
	// blocks waiting for the response to begin.
	flusher.Flush()

	c := &client{userID: userID, ch: make(chan sseMessage, h.buffer)}
	h.add(c)
	defer h.remove(c)

	// Best-effort replay from the ring buffer before live streaming.
	if last, ok := parseLastEventID(r); ok {
		for _, m := range h.replaySince(last) {
			if err := writeMessage(w, m); err != nil {
				return
			}
		}
		flusher.Flush()
	}

	ticker := time.NewTicker(h.interval)
	defer ticker.Stop()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case m := <-c.ch:
			if err := writeMessage(w, m); err != nil {
				return
			}
			flusher.Flush()
		case <-ticker.C:
			if err := writeComment(w, "ping"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (h *Hub) setSSEHeaders(w http.ResponseWriter) {
	head := w.Header()
	head.Set("Content-Type", "text/event-stream")
	head.Set("Cache-Control", "no-cache")
	head.Set("Connection", "keep-alive")
	// Defeat proxy buffering (nginx) so events flush promptly.
	head.Set("X-Accel-Buffering", "no")
}

func (h *Hub) add(c *client) {
	h.mu.Lock()
	h.subs[c] = struct{}{}
	h.mu.Unlock()
}

func (h *Hub) remove(c *client) {
	h.mu.Lock()
	delete(h.subs, c)
	h.mu.Unlock()
}

// ClientCount returns the number of connected clients; for tests.
func (h *Hub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.subs)
}

// parseLastEventID reads the reconnect position from the Last-Event-ID header or
// the last_event_id query param (EventSource sends the header; the query param
// is a fallback for manual reconnects).
func parseLastEventID(r *http.Request) (uint64, bool) {
	v := r.Header.Get("Last-Event-ID")
	if v == "" {
		v = r.URL.Query().Get("last_event_id")
	}
	if v == "" {
		return 0, false
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// --- SSE framing (SPEC §3, §8) ---
//
// A named data event is framed as:
//
//	id: <n>\n
//	event: <name>\n
//	data: <json>\n
//	\n
//
// A heartbeat is an SSE comment line ": ping\n\n". frame builds the byte form;
// writeMessage/writeComment write it to the response.

func frame(m sseMessage) []byte {
	return []byte(fmt.Sprintf("id: %d\nevent: %s\ndata: %s\n\n", m.id, m.name, m.data))
}

func writeMessage(w http.ResponseWriter, m sseMessage) error {
	_, err := w.Write(frame(m))
	return err
}

func writeComment(w http.ResponseWriter, text string) error {
	_, err := fmt.Fprintf(w, ": %s\n\n", text)
	return err
}
