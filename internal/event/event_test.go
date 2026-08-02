package event

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/thomasteoh/boardchestrator/internal/action"
)

// counterValue reads the current value of a counter metric without pulling in
// prometheus/testutil (which would add an indirect test dependency). It uses
// the Collector's own Write, the same mechanism the registry uses.
func counterValue(t *testing.T, c interface{ Write(*dto.Metric) error }) float64 {
	t.Helper()
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		t.Fatalf("read counter: %v", err)
	}
	if m.Counter == nil {
		return 0
	}
	return m.Counter.GetValue()
}

// TestBusDelivery: publish → a matching subscriber receives the event.
func TestBusDelivery(t *testing.T) {
	b := New()
	sub, cancel := b.Subscribe(Filter{}, 4)
	defer cancel()

	want := Event{Name: "task.create", Org: "org1", Subject: "t1", Payload: json.RawMessage(`{"id":"t1"}`)}
	b.Publish(want)

	select {
	case got := <-sub.C:
		if got.Name != want.Name || got.Org != want.Org || got.Subject != want.Subject {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for delivery")
	}
}

// TestFilterByOrgAndName: a subscriber only receives events matching its filter.
func TestFilterByOrgAndName(t *testing.T) {
	b := New()
	sub, cancel := b.Subscribe(Filter{Org: "org1", Names: map[string]struct{}{"task.create": {}}}, 8)
	defer cancel()

	// Non-matching org — dropped.
	b.Publish(Event{Name: "task.create", Org: "org2"})
	// Matching org, non-matching name — dropped.
	b.Publish(Event{Name: "task.update", Org: "org1"})
	// Matching both — delivered.
	b.Publish(Event{Name: "task.create", Org: "org1", Subject: "keep"})

	select {
	case got := <-sub.C:
		if got.Subject != "keep" {
			t.Fatalf("received wrong event: %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("expected the matching event")
	}
	// No further events queued.
	select {
	case got := <-sub.C:
		t.Fatalf("unexpected extra event: %+v", got)
	default:
	}
}

// TestSlowConsumerDropsWithoutBlocking: a subscriber that never reads has events
// dropped past its buffer, the publisher does not block, and the drop counter
// increments.
func TestSlowConsumerDropsWithoutBlocking(t *testing.T) {
	b := New()
	const buf = 2
	_, cancel := b.Subscribe(Filter{Org: "slow"}, buf)
	defer cancel()

	before := counterValue(t, dropsCounter.WithLabelValues("slow"))

	const n = 50
	done := make(chan struct{})
	go func() {
		for i := 0; i < n; i++ {
			b.Publish(Event{Name: "task.create", Org: "slow"})
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("publisher blocked on a slow consumer")
	}

	after := counterValue(t, dropsCounter.WithLabelValues("slow"))
	drops := after - before
	if drops < float64(n-buf) {
		t.Fatalf("expected at least %d drops, got %v", n-buf, drops)
	}
}

// TestUnsubscribeStopsDelivery: after Close, publish no longer targets the sub
// and the channel is closed.
func TestUnsubscribeStopsDelivery(t *testing.T) {
	b := New()
	sub, cancel := b.Subscribe(Filter{}, 4)
	if b.SubscriberCount() != 1 {
		t.Fatalf("want 1 subscriber, got %d", b.SubscriberCount())
	}
	cancel()
	if b.SubscriberCount() != 0 {
		t.Fatalf("want 0 subscribers after close, got %d", b.SubscriberCount())
	}
	// Channel closed → receive returns zero value, not ok.
	if _, ok := <-sub.C; ok {
		t.Fatal("expected closed channel after unsubscribe")
	}
	// Double close is safe.
	sub.Close()
	// Publish after unsubscribe must not panic.
	b.Publish(Event{Name: "task.create"})
}

// TestSinkAdapterForwards: the action.EventSink adapter converts and publishes
// into the bus (integration between action and event, no cycle).
func TestSinkAdapterForwards(t *testing.T) {
	b := New()
	sub, cancel := b.Subscribe(Filter{}, 4)
	defer cancel()

	var sink action.EventSink = NewSink(b)
	sink.Emit(context.Background(), action.Event{
		Name:    "task.create",
		Org:     "org1",
		Actor:   action.Actor{Type: action.ActorUser, ID: "u1"},
		Subject: "t1",
		Payload: json.RawMessage(`{"id":"t1"}`),
	})

	select {
	case got := <-sub.C:
		if got.Name != "task.create" || got.ActorType != "user" || got.ActorID != "u1" || got.Subject != "t1" {
			t.Fatalf("adapter produced wrong event: %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("adapter did not forward the event")
	}
}
