package sse

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/event"
)

// stubUser resolves every request to a fixed user id; the "session auth stub"
// seam (BACKLOG WU-007).
func stubUser(id string) UserResolver {
	return func(*http.Request) (string, bool) { return id, id != "" }
}

// stubMembers returns a MembershipResolver that reports the given org ids for
// every user (WU-521 test seam).
func stubMembers(orgs ...string) MembershipResolver {
	set := map[string]struct{}{}
	for _, o := range orgs {
		set[o] = struct{}{}
	}
	return func(string) []string {
		out := make([]string, 0, len(set))
		for o := range set {
			out = append(out, o)
		}
		return out
	}
}

// TestHandlerRejectsUnauthenticated: no user → 401, no stream.
func TestHandlerRejectsUnauthenticated(t *testing.T) {
	h := New(event.New(), stubUser(""))
	req := httptest.NewRequest(http.MethodGet, "/events", nil)
	rec := httptest.NewRecorder()
	h.Handler(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
}

// TestHandlerSetsSSEHeaders asserts the content-type and cache headers.
func TestHandlerSetsSSEHeaders(t *testing.T) {
	h := New(event.New(), stubUser("u1"))
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/events", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	// Cancel almost immediately so the handler returns.
	cancel()
	h.Handler(rec, req)

	if ct := rec.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content-type = %q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-cache" {
		t.Fatalf("cache-control = %q", cc)
	}
}

// TestEventFraming: a bus event reaches the stream as a well-formed SSE frame
// with id:/event:/data: lines and a blank-line terminator. Uses a real
// httptest server + client so the streamed body is read over a socket (no
// shared-buffer race with the handler's writes).
func TestEventFraming(t *testing.T) {
	bus := event.New()
	h := New(bus, stubUser("u1"), WithHeartbeat(time.Hour), WithMembershipResolver(stubMembers("org1")))
	hubCtx, hubCancel := context.WithCancel(context.Background())
	go h.Run(hubCtx)
	defer hubCancel()

	srv := httptest.NewServer(http.HandlerFunc(h.Handler))
	defer closeServer(srv)

	stream := openStream(t, srv.URL, nil)
	defer stream.close()

	// Once the client is registered, publish; the hub also has its own bus sub.
	waitFor(t, func() bool { return h.ClientCount() >= 1 })
	bus.Publish(event.Event{
		Name:    "task.update",
		Org:     "org1",
		Subject: "t7",
		Payload: json.RawMessage(`{"id":"t7"}`),
	})

	frameText := stream.readFrame(t)
	if !strings.Contains(frameText, "event: "+EventTaskUpdated+"\n") {
		t.Fatalf("missing/incorrect event line:\n%q", frameText)
	}
	if !strings.Contains(frameText, "id: 1\n") {
		t.Fatalf("missing id line:\n%q", frameText)
	}
	if !strings.Contains(frameText, `"subject":"t7"`) {
		t.Fatalf("missing data payload:\n%q", frameText)
	}
	if !strings.HasPrefix(frameText, "id: ") || !strings.HasSuffix(frameText, "\n\n") {
		t.Fatalf("frame not a well-formed id/…/blank-terminated block:\n%q", frameText)
	}
}

// TestHeartbeat: an idle stream emits an SSE comment ping.
func TestHeartbeat(t *testing.T) {
	bus := event.New()
	h := New(bus, stubUser("u1"), WithHeartbeat(20*time.Millisecond))
	hubCtx, hubCancel := context.WithCancel(context.Background())
	go h.Run(hubCtx)
	defer hubCancel()

	srv := httptest.NewServer(http.HandlerFunc(h.Handler))
	defer closeServer(srv)

	stream := openStream(t, srv.URL, nil)
	defer stream.close()

	frameText := stream.readFrame(t)
	if !strings.Contains(frameText, ": ping") {
		t.Fatalf("expected heartbeat comment, got:\n%q", frameText)
	}
}

// TestReplayFromRingBuffer: events published before a client connects are
// replayed when it reconnects with Last-Event-ID.
func TestReplayFromRingBuffer(t *testing.T) {
	bus := event.New()
	h := New(bus, stubUser("u1"), WithHeartbeat(time.Hour), WithMembershipResolver(stubMembers("o")))
	hubCtx, hubCancel := context.WithCancel(context.Background())
	go h.Run(hubCtx)
	defer hubCancel()

	// Publish three events with no client connected; they land in the ring.
	waitFor(t, func() bool { return bus.SubscriberCount() >= 1 })
	bus.Publish(event.Event{Name: "task.create", Org: "o", Subject: "a"})
	bus.Publish(event.Event{Name: "task.create", Org: "o", Subject: "b"})
	bus.Publish(event.Event{Name: "task.create", Org: "o", Subject: "c"})
	waitFor(t, func() bool { return h.lastSeq() == 3 })

	srv := httptest.NewServer(http.HandlerFunc(h.Handler))
	defer closeServer(srv)

	// Reconnect from id 1 → expect events 2 and 3 replayed (not 1).
	stream := openStream(t, srv.URL, http.Header{"Last-Event-ID": {"1"}})
	defer stream.close()

	f2 := stream.readFrame(t)
	f3 := stream.readFrame(t)
	body := f2 + f3

	if strings.Contains(body, `"subject":"a"`) {
		t.Fatalf("event 1 should not be replayed:\n%s", body)
	}
	if !strings.Contains(body, `"subject":"b"`) || !strings.Contains(body, `"subject":"c"`) {
		t.Fatalf("expected events 2 and 3 replayed:\n%s", body)
	}
	if !strings.Contains(body, "id: 2\n") || !strings.Contains(body, "id: 3\n") {
		t.Fatalf("replayed frames missing ids:\n%s", body)
	}
}

// TestEventNameMapping documents the action→SSE-event mapping.
func TestEventNameMapping(t *testing.T) {
	cases := map[string]string{
		"task.create":           EventTaskUpdated,
		"task.move":             EventTaskUpdated,
		"notification.markread": EventNotification,
		"chat.message":          EventChatDelta,
		"run.cancel":            EventRunStatus,
		"org.create":            "message",
	}
	for in, want := range cases {
		if got := eventNameFor(in); got != want {
			t.Errorf("eventNameFor(%q) = %q, want %q", in, got, want)
		}
	}
}

// stubUserParam resolves the user id from a `user` query param ("a" or "b");
// lets one hub serve two distinct clients in a test (WU-521 two-org scoping).
func stubUserParam() UserResolver {
	return func(r *http.Request) (string, bool) {
		switch u := r.URL.Query().Get("user"); u {
		case "a", "b":
			return u, true
		default:
			return "", false
		}
	}
}

// TestTwoOrgNoCrossDelivery is the WU-521 regression: two orgs' clients on one
// hub get zero cross-delivery — live (org-scoped dispatch) and via
// Last-Event-ID:0 replay. Also asserts SendToUser chat deltas are not recorded
// into the shared ring (so they never replay to anyone).
//
// Each stream is used for exactly one assertion (positive readFrame or
// negative tryReadFrame) and then closed, so the non-fatal tryReadFrame's
// lingering read goroutine never races a later readFrame on the same reader.
func TestTwoOrgNoCrossDelivery(t *testing.T) {
	bus := event.New()
	h := New(bus, stubUserParam(), WithHeartbeat(time.Hour))
	// Per-user tenant scoping: user a → orgA, user b → orgB. Must be set
	// before clients connect (the handler snapshots orgs at connect time).
	h.orgs = func(userID string) []string {
		if userID == "a" {
			return []string{"orgA"}
		}
		if userID == "b" {
			return []string{"orgB"}
		}
		return nil
	}
	hubCtx, hubCancel := context.WithCancel(context.Background())
	go h.Run(hubCtx)
	defer hubCancel()
	waitFor(t, func() bool { return bus.SubscriberCount() >= 1 })

	srv := httptest.NewServer(http.HandlerFunc(h.Handler))
	defer closeServer(srv)

	// Live, orgA event: member a receives it; non-member b (orgB member) must
	// not. Separate streams: posA asserts delivery, negB asserts absence.
	posA := openStream(t, srv.URL+"/events?user=a", nil)
	negB := openStream(t, srv.URL+"/events?user=b", nil)
	waitFor(t, func() bool { return h.ClientCount() >= 2 })
	bus.Publish(event.Event{Name: "task.create", Org: "orgA", Subject: "secretA",
		Payload: json.RawMessage(`{"secret":"A"}`)})
	fa := posA.readFrame(t)
	if !strings.Contains(fa, `"subject":"secretA"`) {
		t.Fatalf("member of orgA should receive orgA event, got:\n%q", fa)
	}
	if got := negB.tryReadFrame(); got != "" {
		t.Fatalf("non-member of orgA received orgA event (live):\n%q", got)
	}
	posA.close()
	negB.close()

	// Live, orgB event: member b receives it; non-member a must not.
	posB := openStream(t, srv.URL+"/events?user=b", nil)
	negA := openStream(t, srv.URL+"/events?user=a", nil)
	waitFor(t, func() bool { return h.ClientCount() >= 2 })
	bus.Publish(event.Event{Name: "task.create", Org: "orgB", Subject: "secretB",
		Payload: json.RawMessage(`{"secret":"B"}`)})
	fb := posB.readFrame(t)
	if !strings.Contains(fb, `"subject":"secretB"`) {
		t.Fatalf("member of orgB should receive orgB event, got:\n%q", fb)
	}
	if got := negA.tryReadFrame(); got != "" {
		t.Fatalf("non-member of orgB received orgB event (live):\n%q", got)
	}
	posB.close()
	negA.close()

	// Replay via Last-Event-ID:0 must be scoped like live. Publish an orgA
	// event while no client is connected (lands in the ring), then reconnect
	// user b (orgB member) from id 0. user b legitimately replays the orgB
	// event (id 2) but must NOT receive the orgA event (id 3, secretA2).
	bus.Publish(event.Event{Name: "task.create", Org: "orgA", Subject: "secretA2",
		Payload: json.RawMessage(`{"secret":"A2"}`)})
	waitFor(t, func() bool { return h.lastSeq() == 3 })
	negB2 := openStream(t, srv.URL+"/events?user=b", http.Header{"Last-Event-ID": {"0"}})
	// Drain up to the orgB event; assert the orgA secret never appears.
	got := negB2.readFrame(t)
	got += negB2.tryReadFrame()
	if strings.Contains(got, "secretA2") {
		t.Fatalf("non-member of orgA received orgA event via replay:\n%q", got)
	}
	if !strings.Contains(got, "secretB") {
		t.Fatalf("member of orgB should replay orgB event, got:\n%q", got)
	}
	negB2.close()

	// SendToUser chat delta targeted at user b must reach b live and not leak
	// to a live, and must not be recorded into the shared ring (so replay
	// yields nothing).
	posB2 := openStream(t, srv.URL+"/events?user=b", nil)
	negA2 := openStream(t, srv.URL+"/events?user=a", nil)
	waitFor(t, func() bool { return h.ClientCount() >= 2 })
	h.SendToUser("b", EventChatDelta, []byte(`{"delta":"hello b"}`))
	fb2 := posB2.readFrame(t)
	if !strings.Contains(fb2, EventChatDelta) || !strings.Contains(fb2, "hello b") {
		t.Fatalf("target user should receive chat delta, got:\n%q", fb2)
	}
	if got := negA2.tryReadFrame(); got != "" {
		t.Fatalf("chat delta leaked to non-target user (live):\n%q", got)
	}
	posB2.close()
	negA2.close()

	// Reconnect user b from id 0 after the chat delta: the orgB event replays
	// legitimately, but the user-targeted chat delta must NOT replay
	// (SendToUser no longer records into the shared ring).
	negB3 := openStream(t, srv.URL+"/events?user=b", http.Header{"Last-Event-ID": {"0"}})
	got3 := negB3.readFrame(t)
	got3 += negB3.tryReadFrame()
	if strings.Contains(got3, "hello b") {
		t.Fatalf("user-targeted chat delta was recorded into the shared ring and replayed:\n%q", got3)
	}
	negB3.close()
}

// --- test helpers ---

// lastSeq exposes the hub's current event id for tests.
func (h *Hub) lastSeq() uint64 { return h.seq.Load() }

// closeServer tears down an httptest server that has a long-lived SSE handler.
// httptest.Server.Close blocks until all in-flight requests finish; a streaming
// handler idling on its heartbeat ticker only notices the client left on its
// next write, so we forcibly drop client connections first — that cancels the
// handler's request context and lets Close return promptly.
func closeServer(srv *httptest.Server) {
	srv.CloseClientConnections()
	srv.Close()
}

// stream is a live SSE client connection over a real socket. Reading frames
// from a socket (rather than a shared httptest.ResponseRecorder buffer) avoids
// racing the handler's concurrent writes under -race.
type stream struct {
	ctx    context.Context
	cancel context.CancelFunc
	body   *bufio.Reader
	closer func()
}

// openStream connects to url and returns a stream. Cancelling its context (via
// close) ends the request, unblocking the handler's ctx.Done path.
func openStream(t *testing.T, url string, extra http.Header) *stream {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		cancel()
		t.Fatalf("new request: %v", err)
	}
	for k, vs := range extra {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		t.Fatalf("connect: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		cancel()
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		cancel()
		t.Fatalf("content-type = %q", ct)
	}
	return &stream{
		ctx:    ctx,
		cancel: cancel,
		body:   bufio.NewReader(resp.Body),
		closer: func() { cancel(); resp.Body.Close() },
	}
}

// readFrame reads up to (and including) the next blank-line-terminated SSE
// block and returns it as text. Fails on timeout.
func (s *stream) readFrame(t *testing.T) string {
	t.Helper()
	type res struct {
		text string
		err  error
	}
	out := make(chan res, 1)
	go func() {
		var b strings.Builder
		for {
			line, err := s.body.ReadString('\n')
			b.WriteString(line)
			if err != nil {
				out <- res{b.String(), err}
				return
			}
			if line == "\n" { // blank line terminates a frame
				out <- res{b.String(), nil}
				return
			}
		}
	}()
	select {
	case r := <-out:
		if r.err != nil && r.text == "" {
			t.Fatalf("read frame: %v", r.err)
		}
		return r.text
	case <-time.After(2 * time.Second):
		t.Fatal("timed out reading frame")
		return ""
	}
}

func (s *stream) close() { s.closer() }

// tryReadFrame attempts to read one frame with a short timeout and returns ""
// (no error) if nothing arrives — used to assert a client must NOT receive an
// event (WU-521 cross-delivery absence). Returns the frame text when one does
// arrive within the window.
func (s *stream) tryReadFrame() string {
	out := make(chan string, 1)
	go func() {
		var b strings.Builder
		for {
			line, err := s.body.ReadString('\n')
			b.WriteString(line)
			if err != nil {
				out <- b.String()
				return
			}
			if line == "\n" { // blank line terminates a frame
				out <- b.String()
				return
			}
		}
	}()
	select {
	case s := <-out:
		return s
	case <-time.After(150 * time.Millisecond):
		return ""
	}
}

// waitFor polls cond up to ~2s.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}

// TestFrameParses sanity-checks that frame output is line-parseable SSE.
func TestFrameParses(t *testing.T) {
	m := sseMessage{id: 5, name: EventChatDelta, data: []byte(`{"name":"chat.message"}`)}
	sc := bufio.NewScanner(strings.NewReader(string(frame(m))))
	var gotID, gotEvent, gotData bool
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "id: 5":
			gotID = true
		case line == "event: "+EventChatDelta:
			gotEvent = true
		case strings.HasPrefix(line, "data: "):
			gotData = true
		}
	}
	if !gotID || !gotEvent || !gotData {
		t.Fatalf("frame missing lines: id=%v event=%v data=%v", gotID, gotEvent, gotData)
	}
}
