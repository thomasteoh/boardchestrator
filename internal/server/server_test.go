package server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/config"
	"github.com/thomasteoh/boardchestrator/internal/server"
)

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
