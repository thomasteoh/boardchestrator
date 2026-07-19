package server_test

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/config"
	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
	"github.com/thomasteoh/boardchestrator/internal/event"
	"github.com/thomasteoh/boardchestrator/internal/server"
)

// eventForTest is a sample bus event for the /events integration test.
func eventForTest() event.Event {
	return event.Event{Name: "task.update", Org: "org1", Subject: "t9", Payload: json.RawMessage(`{"id":"t9"}`)}
}

// readFirstFrame reads the first blank-line-terminated SSE frame from r,
// failing on timeout. Runs the blocking read in a goroutine so a stalled stream
// does not hang the test.
func readFirstFrame(t *testing.T, r io.Reader) string {
	t.Helper()
	out := make(chan string, 1)
	go func() {
		br := bufio.NewReader(r)
		var b strings.Builder
		for {
			line, err := br.ReadString('\n')
			b.WriteString(line)
			if err != nil {
				out <- b.String()
				return
			}
			// Skip pure heartbeat/blank noise; return once we have a data frame.
			if line == "\n" && strings.Contains(b.String(), "data: ") {
				out <- b.String()
				return
			}
		}
	}()
	select {
	case s := <-out:
		return s
	case <-time.After(3 * time.Second):
		t.Fatal("timed out reading SSE frame")
		return ""
	}
}

func testConfig() *config.Config {
	return &config.Config{
		Bind:          "127.0.0.1:0",
		LogLevelStr:   "debug",
		SecretKey:     "test-secret-key",
		SessionSecret: "test-session-secret",
		AgentWorkers:  1,
	}
}

func TestHealthz(t *testing.T) {
	s := server.New(testConfig())
	srv := httptest.NewServer(s)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("status = %q, want ok", body["status"])
	}
}

func TestReadyzWhenReady(t *testing.T) {
	s := server.New(testConfig())
	s.SetReady(true)
	srv := httptest.NewServer(s)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestReadyzNotReady(t *testing.T) {
	s := server.New(testConfig())
	srv := httptest.NewServer(s)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
}

func TestMetrics(t *testing.T) {
	s := server.New(testConfig())
	srv := httptest.NewServer(s)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
}

func TestRecoverMiddleware(t *testing.T) {
	s := server.New(testConfig())
	s.SetReady(true)

	// Register a panic handler that goes through the actual server's
	// middleware chain (requestID → requestLog → recover → handler).
	s.RegisterForTest("/panic", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	}))

	srv := httptest.NewServer(s)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/panic")
	if err != nil {
		t.Fatalf("GET /panic: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestGracefulShutdown(t *testing.T) {
	cfg := testConfig()
	s := server.New(cfg)

	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = s.Start(ctx)
	}()

	// Wait for server to be ready.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if s.Ready() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !s.Ready() {
		t.Fatal("server did not become ready in time")
	}

	// Verify healthz works before shutdown.
	resp, err := http.Get("http://" + s.ListenedAddr() + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz before shutdown: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("healthz before shutdown: status = %d, want 200", resp.StatusCode)
	}

	// Initiate shutdown via context cancellation.
	cancel()

	// Wait for server to fully exit.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Server shut down cleanly.
	case <-time.After(15 * time.Second):
		t.Fatal("server did not shut down within 15s")
	}

	// Verify readiness is cleared after shutdown.
	if s.Ready() {
		t.Error("server should not be ready after shutdown")
	}
}

func TestShutdownDrainInFlightRequests(t *testing.T) {
	cfg := testConfig()
	s := server.New(cfg)

	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = s.Start(ctx)
	}()

	// Wait for ready.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if s.Ready() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !s.Ready() {
		t.Fatal("server did not become ready")
	}

	addr := s.ListenedAddr()

	// Start an in-flight request that takes time.
	reqDone := make(chan struct{})
	var respCode int
	go func() {
		resp, err := http.Get("http://" + addr + "/healthz")
		if err != nil {
			close(reqDone)
			return
		}
		respCode = resp.StatusCode
		resp.Body.Close()
		close(reqDone)
	}()

	// Give the request time to be in-flight.
	time.Sleep(200 * time.Millisecond)

	// Initiate shutdown.
	cancel()

	// Wait for the in-flight request to complete during the drain window.
	select {
	case <-reqDone:
		if respCode != http.StatusOK {
			t.Errorf("in-flight request status = %d, want 200", respCode)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("in-flight request did not complete during drain")
	}

	// Wait for server to fully exit.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(12 * time.Second):
		t.Fatal("server did not shut down after drain")
	}
}

func TestJSONResponseFormat(t *testing.T) {
	s := server.New(testConfig())
	s.SetReady(true)
	srv := httptest.NewServer(s)
	defer srv.Close()

	for _, tc := range []struct {
		path string
		code int
	}{
		{"/healthz", http.StatusOK},
		{"/readyz", http.StatusOK},
	} {
		t.Run(tc.path, func(t *testing.T) {
			resp, err := http.Get(srv.URL + tc.path)
			if err != nil {
				t.Fatalf("GET %s: %v", tc.path, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tc.code {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.code)
			}

			ct := resp.Header.Get("Content-Type")
			if !strings.Contains(ct, "application/json") {
				t.Errorf("Content-Type = %q, want application/json", ct)
			}

			// Verify it's valid JSON.
			var body map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Errorf("invalid JSON: %v", err)
			}
		})
	}
}

// --- WU-005: sessions, CSRF, CSP wired into the full router assembly ---

func TestServerCSPFreshNoncePerRequest(t *testing.T) {
	s := server.New(testConfig())
	s.SetReady(true)
	srv := httptest.NewServer(s)
	defer srv.Close()

	nonce := func() string {
		resp, err := http.Get(srv.URL + "/healthz")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		csp := resp.Header.Get("Content-Security-Policy")
		m := regexp.MustCompile(`'nonce-([A-Za-z0-9+/]+)'`).FindStringSubmatch(csp)
		if m == nil {
			t.Fatalf("no nonce in CSP header: %q", csp)
		}
		return m[1]
	}
	if a, b := nonce(), nonce(); a == b {
		t.Error("CSP nonce identical across requests through the full server, want fresh")
	}
}

func TestServerSecurityHeaders(t *testing.T) {
	s := server.New(testConfig())
	s.SetReady(true)
	srv := httptest.NewServer(s)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing nosniff header from full server")
	}
	if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Error("missing frame-ancestors in CSP from full server")
	}
}

func TestServerCSRFEnforcedWhenDBWired(t *testing.T) {
	cfg := testConfig()
	d := dbtest.New(t)
	if _, err := d.ExecContext(context.Background(), `INSERT INTO users (id, email) VALUES (?, ?)`, "u1", "u1@example.com"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	s := server.NewWithDB(cfg, d)
	s.SetReady(true)
	s.RegisterForTest("/mutate", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv := httptest.NewServer(s)
	defer srv.Close()

	store := auth.NewSessionStore(d)
	raw, sess, err := store.Create(context.Background(), "u1", "", "")
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}
	cookie := &http.Cookie{Name: auth.CookieName, Value: raw}

	// POST without CSRF token → 403.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/mutate", nil)
	req.AddCookie(cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST no-token: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("POST without CSRF token: status %d, want 403", resp.StatusCode)
	}

	// POST with valid token → 200.
	req2, _ := http.NewRequest(http.MethodPost, srv.URL+"/mutate", nil)
	req2.AddCookie(cookie)
	req2.Header.Set(auth.CSRFHeader, auth.CSRFToken(cfg.SessionSecret, sess.TokenHash))
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("POST with-token: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("POST with valid CSRF token: status %d, want 200", resp2.StatusCode)
	}
}

// TestEventsRouteAbsentWithoutDB: no DB ⇒ no session store ⇒ no /events stream.
func TestEventsRouteAbsentWithoutDB(t *testing.T) {
	s := server.New(testConfig())
	s.SetReady(true)
	srv := httptest.NewServer(s)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/events")
	if err != nil {
		t.Fatalf("GET /events: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("no-DB /events: status %d, want 404", resp.StatusCode)
	}
}

// TestEventsStreamsToAuthedUser: an authenticated user connects to /events over
// the full middleware chain and receives an event published through the
// server's bus (proving the /events route is wired to the hub and the hub to
// the bus).
func TestEventsStreamsToAuthedUser(t *testing.T) {
	cfg := testConfig()
	d := dbtest.New(t)
	if _, err := d.ExecContext(context.Background(), `INSERT INTO users (id, email) VALUES (?, ?)`, "u1", "u1@example.com"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	s := server.NewWithDB(cfg, d)
	s.SetReady(true)

	hubCtx, hubCancel := context.WithCancel(context.Background())
	defer hubCancel()
	s.RunHubForTest(hubCtx)

	srv := httptest.NewServer(s)
	defer srv.Close()

	store := auth.NewSessionStore(d)
	raw, _, err := store.Create(context.Background(), "u1", "", "")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	// Unauthenticated → 401.
	unauth, err := http.Get(srv.URL + "/events")
	if err != nil {
		t.Fatalf("GET /events unauth: %v", err)
	}
	unauth.Body.Close()
	if unauth.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth /events: status %d, want 401", unauth.StatusCode)
	}

	// Authenticated → 200 text/event-stream, receives a published event.
	streamCtx, streamCancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(streamCtx, http.MethodGet, srv.URL+"/events", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: raw})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /events authed: %v", err)
	}
	defer func() { streamCancel(); resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authed /events: status %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content-type = %q", ct)
	}

	// Publish through the server's bus once the client is connected.
	go func() {
		for i := 0; i < 50; i++ {
			s.Bus().Publish(eventForTest())
			time.Sleep(10 * time.Millisecond)
		}
	}()

	got := readFirstFrame(t, resp.Body)
	if !strings.Contains(got, "event: task-updated") || !strings.Contains(got, `"subject":"t9"`) {
		t.Fatalf("did not receive expected event frame, got:\n%q", got)
	}
}
