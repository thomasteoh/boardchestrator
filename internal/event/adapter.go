package event

import (
	"context"

	"github.com/thomasteoh/boardchestrator/internal/action"
)

// SinkAdapter implements action.EventSink by forwarding each dispatched
// action.Event into the bus as an event.Event. It is the glue wired onto the
// Dispatcher via action.WithEventSink, replacing the no-op default (SPEC §4,
// §8; BACKLOG WU-007).
//
// The dependency direction is event → action (this file imports action);
// action never imports event, so there is no import cycle. That is why the
// adapter lives here rather than in internal/action.
//
// Emit is non-blocking because Bus.Publish is non-blocking, so it satisfies the
// action.EventSink contract ("non-blocking or fast; the bus buffers").
type SinkAdapter struct {
	bus *Bus
}

// NewSink returns an action.EventSink forwarding into bus.
func NewSink(bus *Bus) *SinkAdapter {
	return &SinkAdapter{bus: bus}
}

// Emit converts an action.Event to an event.Event and publishes it. The context
// is unused: publish is synchronous, non-blocking, and does no I/O.
func (a *SinkAdapter) Emit(_ context.Context, ev action.Event) {
	a.bus.Publish(Event{
		Name:      ev.Name,
		Org:       ev.Org,
		ActorType: string(ev.Actor.Type),
		ActorID:   ev.Actor.ID,
		Subject:   ev.Subject,
		Payload:   ev.Payload,
	})
}

// compile-time assertion that the adapter satisfies the action seam.
var _ action.EventSink = (*SinkAdapter)(nil)
