// Package event is the in-process typed pub/sub bus (SPEC §1, §8). A single
// bus fans a published Event out to every matching subscriber. Publish is
// non-blocking: each subscriber owns a buffered channel and a slow consumer
// that lets its buffer fill has events dropped (and a Prometheus counter
// incremented) rather than stalling the publisher — the action dispatch path
// must never block on a lagging SSE client, webhook worker, or indexer.
//
// The bus deliberately does not import internal/action: action owns the
// action.Event shape and a no-op EventSink default, and having action import
// event would create a cycle (event's adapter, in adapter.go, implements
// action.EventSink). Keeping the dependency one-way (event → action) lets the
// adapter live here.
//
// Subscribers named in SPEC §8 (SSE hub, notification engine, webhook
// dispatcher, search indexer, activity writer, github transition engine) all
// subscribe through this bus with a Filter selecting the events they care about.
package event

import (
	"encoding/json"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Event is the value fanned out to subscribers. It mirrors action.Event (the
// dispatch pipeline emits one after every successful mutation) but is owned by
// this package so the bus has no dependency on action's internals beyond the
// adapter. Name is the action name ("task.create"); Org scopes the event ("" =
// platform); ActorType/ActorID identify who acted (SPEC §1 rule 3: polymorphic
// — never assume a human); Subject is the primary affected entity id;
// Payload is the action's JSON output.
type Event struct {
	Name      string
	Org       string
	ActorType string
	ActorID   string
	Subject   string
	Payload   json.RawMessage
}

// Filter selects which events a subscriber receives. The zero Filter matches
// everything. The model is intentionally small to match how the SSE hub
// consumes events (SPEC §8): a subscriber keys on org (a browser only sees its
// current org's events) and optionally narrows to specific event names.
//
//   - Org == "" matches events for any org; Org == "x" matches only org "x".
//   - Names == nil matches any event name; a non-empty set matches only those
//     names (e.g. {"task.create","task.update"} for a board view).
//
// Filtering by org and name (not subject) is enough for the SSE hub, which
// re-checks per-user authorisation and per-view relevance on its side; finer
// subject filtering would push tenancy knowledge into the bus.
type Filter struct {
	Org   string
	Names map[string]struct{}
}

// matches reports whether ev passes the filter.
func (f Filter) matches(ev Event) bool {
	if f.Org != "" && f.Org != ev.Org {
		return false
	}
	if f.Names != nil {
		if _, ok := f.Names[ev.Name]; !ok {
			return false
		}
	}
	return true
}

// Subscription is a live subscription. Read events from C; call Close (or the
// unsubscribe func returned by Subscribe) exactly once when done. C is closed
// on Close so a range over it terminates.
type Subscription struct {
	C      <-chan Event
	ch     chan Event
	filter Filter

	bus    *Bus
	once   sync.Once
	closed chan struct{}
}

// Close unsubscribes and releases resources. Safe to call more than once.
func (s *Subscription) Close() {
	s.once.Do(func() {
		s.bus.remove(s)
		close(s.closed)
		close(s.ch)
	})
}

// dropsCounter counts events dropped because a subscriber's buffer was full.
// Labelled by org so a single misbehaving tenant is visible. Registered once
// at package init via promauto (the default registry, same as server metrics).
var dropsCounter = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "bc",
		Subsystem: "event",
		Name:      "dropped_total",
		Help:      "Events dropped because a subscriber's buffer was full (slow consumer).",
	},
	[]string{"org"},
)

// DefaultBuffer is the per-subscriber channel capacity when Subscribe is called
// without an explicit size. Large enough to absorb a burst; small enough that a
// truly stalled consumer is dropped promptly rather than growing memory.
const DefaultBuffer = 64

// Bus is the in-process pub/sub bus. The zero value is not usable; call New.
type Bus struct {
	mu   sync.RWMutex
	subs map[*Subscription]struct{}
}

// New builds an empty bus.
func New() *Bus {
	return &Bus{subs: map[*Subscription]struct{}{}}
}

// Subscribe registers a subscriber with the given filter and buffer size (<= 0
// uses DefaultBuffer). It returns the Subscription (read from its C) and an
// unsubscribe func equivalent to Subscription.Close.
func (b *Bus) Subscribe(filter Filter, buffer int) (*Subscription, func()) {
	if buffer <= 0 {
		buffer = DefaultBuffer
	}
	ch := make(chan Event, buffer)
	sub := &Subscription{
		C:      ch,
		ch:     ch,
		filter: filter,
		bus:    b,
		closed: make(chan struct{}),
	}
	b.mu.Lock()
	b.subs[sub] = struct{}{}
	b.mu.Unlock()
	return sub, sub.Close
}

// remove detaches sub from the bus. Idempotent.
func (b *Bus) remove(sub *Subscription) {
	b.mu.Lock()
	delete(b.subs, sub)
	b.mu.Unlock()
}

// Publish fans ev out to every matching subscriber without blocking. If a
// subscriber's buffer is full the event is dropped for that subscriber and the
// drop counter is incremented; other subscribers are unaffected. Publish never
// blocks the caller (the dispatch path), so it is safe to call while holding a
// DB transaction's context.
func (b *Bus) Publish(ev Event) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for sub := range b.subs {
		if !sub.filter.matches(ev) {
			continue
		}
		select {
		case sub.ch <- ev:
		default:
			// Buffer full: drop rather than block the publisher (SPEC §8
			// "best effort"). SSE clients recover via Last-Event-ID replay.
			dropsCounter.WithLabelValues(ev.Org).Inc()
		}
	}
}

// SubscriberCount returns the number of live subscribers; for tests and
// introspection.
func (b *Bus) SubscriberCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subs)
}
