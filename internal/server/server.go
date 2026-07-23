// Package server provides the HTTP server with chi router, middleware,
// and graceful shutdown.
package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/config"
	"github.com/thomasteoh/boardchestrator/internal/event"
	"github.com/thomasteoh/boardchestrator/internal/job"
	"github.com/thomasteoh/boardchestrator/internal/sse"
	"github.com/thomasteoh/boardchestrator/internal/web"
)

// metrics for Prometheus /metrics endpoint.
var (
	httpReqsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "bc",
			Subsystem: "http",
			Name:      "requests_total",
			Help:      "Total HTTP requests by method, path, and status.",
		},
		[]string{"method", "path", "status"},
	)
	httpReqDur = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "bc",
			Subsystem: "http",
			Name:      "request_duration_seconds",
			Help:      "HTTP request duration in seconds.",
			Buckets:   []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		},
		[]string{"method", "path"},
	)
)

// Server wraps a chi router and http.Server with lifecycle management.
type Server struct {
	mux      *chi.Mux
	srv      *http.Server
	ready    atomic.Bool
	cfg      *config.Config
	sessions *auth.SessionStore

	// bus is the in-process event bus (SPEC §8). The action Dispatcher's
	// EventSink forwards into it (event.NewSink); the SSE hub and later
	// subscribers (notify, webhooks, search) fan out from it.
	bus *event.Bus
	// hub streams bus events to browsers over /events. Mounted only when a
	// session store exists (it needs the authenticated user).
	hub    *sse.Hub
	hubCtx context.CancelFunc

	// pool runs background job workers. Created in Start when DB is wired.
	pool *job.Pool
	db   *sql.DB
}

// New creates a configured server with routes and middleware, with no
// database wired. Session and CSRF middleware are only mounted when a database
// is provided via NewWithDB; the CSP and security-header middleware always run.
func New(cfg *config.Config) *Server {
	return NewWithDB(cfg, nil)
}

// NewWithDB creates a configured server backed by d. When d is non-nil, the
// session and CSRF middleware are mounted; the CSP/security-header middleware
// runs regardless.
func NewWithDB(cfg *config.Config, d *sql.DB) *Server {
	s := &Server{cfg: cfg, mux: chi.NewRouter(), bus: event.New()}
	if d != nil {
		s.sessions = auth.NewSessionStore(d)
		// The /events stream authenticates via the session the middleware
		// stashes in the request context (WU-005). No DB ⇒ no sessions ⇒ no
		// stream (nothing to authorise).
		s.hub = sse.New(s.bus, sse.SessionUserResolver)
		s.db = d
	}
	s.setupMiddleware()
	s.setupRoutes()
	s.srv = &http.Server{
		Handler:           s.mux,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	return s
}

func (s *Server) setupMiddleware() {
	s.mux.Use(s.requestID)
	s.mux.Use(s.requestLog)
	s.mux.Use(s.recover)
	// Security headers + per-request CSP nonce run for every request, even
	// before a DB is wired, so the app shell always renders under a strict CSP.
	s.mux.Use(auth.CSP())
	// Session resolution then CSRF protection, in that order — CSRF needs the
	// resolved session. Only mounted when a session store exists.
	if s.sessions != nil {
		sc := auth.SessionConfig{Store: s.sessions, Secret: s.cfg.SessionSecret}
		s.mux.Use(sc.Session())
		s.mux.Use(sc.CSRF())
	}
}

func (s *Server) setupRoutes() {
	s.mux.Get("/healthz", s.handleHealthz)
	s.mux.Get("/readyz", s.handleReadyz)
	s.mux.Handle("/metrics", promhttp.Handler())
	if s.hub != nil {
		s.mux.Get("/events", s.hub.Handler)
	}
	web.Routes(s.mux)
}

// Bus returns the server's event bus. The action Dispatcher wires its
// EventSink to it via event.NewSink(srv.Bus()); other subscribers (SSE hub —
// already wired — notify, webhooks, search) attach here too.
func (s *Server) Bus() *event.Bus { return s.bus }

// EventSink returns an action.EventSink forwarding successful dispatches into
// the bus. serve.go constructs no Dispatcher yet (WU-006 note: first action
// registers in WU-104); this makes the wiring available for that WU without
// changing the action seam.
func (s *Server) EventSink() *event.SinkAdapter { return event.NewSink(s.bus) }

// RunHubForTest pumps the SSE hub from the bus until ctx is cancelled. Start
// does this over the server lifetime; tests that drive the server via
// httptest.NewServer (which does not call Start) use this to activate the hub.
// No-op when no hub is wired (no DB).
func (s *Server) RunHubForTest(ctx context.Context) {
	if s.hub != nil {
		go s.hub.Run(ctx)
	}
}

// RegisterForTest mounts a handler on a path for testing.
// It goes through the full middleware chain (requestID, requestLog, recover).
// Only for use in tests — panics if called multiple times with the same pattern.
func (s *Server) RegisterForTest(pattern string, handler http.Handler) {
	s.mux.Handle(pattern, handler)
}

// ServeHTTP implements http.Handler so the server can be used directly
// with httptest.NewServer.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// --- Middleware ---

// ctxKeyRequestID is the context key for request IDs.
type ctxKeyRequestID struct{}

// RequestID returns the request ID from the context, or "" if absent.
func RequestID(ctx context.Context) string {
	if id, ok := ctx.Value(ctxKeyRequestID{}).(string); ok {
		return id
	}
	return ""
}

func (s *Server) requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if RequestID(r.Context()) != "" {
			next.ServeHTTP(w, r)
			return
		}
		reqID := genRequestID()
		ctx := context.WithValue(r.Context(), ctxKeyRequestID{}, reqID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func genRequestID() string {
	b := make([]byte, 17)
	b[0] = 'r'
	for i := 1; i < 17; i++ {
		b[i] = byte(('a' + (i*7+13)%26))
	}
	return string(b)
}

// requestLog middleware logs each request as structured JSON and records metrics.
func (s *Server) requestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{w: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		slog.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"req_id", RequestID(r.Context()),
		)
		httpReqsTotal.WithLabelValues(r.Method, r.URL.Path, fmt.Sprintf("%d", rec.status)).Inc()
		httpReqDur.WithLabelValues(r.Method, r.URL.Path).Observe(time.Since(start).Seconds())
	})
}

type statusRecorder struct {
	w      http.ResponseWriter
	status int
}

func (r *statusRecorder) Header() http.Header { return r.w.Header() }
func (r *statusRecorder) Write(p []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.w.Write(p)
	return n, err
}
func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.w.WriteHeader(code)
}

// Flush forwards to the wrapped writer so SSE streaming (the /events handler)
// can flush each frame through the logging middleware. If the underlying writer
// is not a Flusher this is a no-op.
func (r *statusRecorder) Flush() {
	if f, ok := r.w.(http.Flusher); ok {
		f.Flush()
	}
}

// recover middleware catches panics and returns 500.
func (s *Server) recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("panic recovered",
					"req_id", RequestID(r.Context()),
					"recover", rec,
				)
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// --- Handlers ---

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	serveJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if s.ready.Load() {
		serveJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}
	serveJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "starting"})
}

// serveJSON writes a JSON response.
func serveJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", " ")
	_ = enc.Encode(v) // response encode errors on trivial payloads are not actionable
}

// --- Lifecycle ---

// SetReady is exported for tests to control readiness state.
func (s *Server) SetReady(v bool) {
	s.ready.Store(v)
}

// Ready reports whether the server passed readiness.
func (s *Server) Ready() bool {
	return s.ready.Load()
}

// Start begins accepting connections on cfg.Bind and marks the server ready.
// It blocks until the server is stopped (via SIGTERM, context cancel, or Shutdown).
func (s *Server) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Bind)
	if err != nil {
		return err
	}
	addr := ln.Addr().String()
	s.srv.Addr = addr

	// Pump the SSE hub from the bus for the server's lifetime.
	if s.hub != nil {
		hubCtx, cancel := context.WithCancel(context.Background())
		s.hubCtx = cancel
		go s.hub.Run(hubCtx)
	}

	// Start the job worker pool.
	if s.db != nil {
		store := job.NewJobStore(s.db)
		s.pool = job.NewPool(ctx, job.PoolConfig{
			Store:        store,
			Handler:      job.NoopHandler,
			MaxWorkers:   4,
			PollInterval: 5 * time.Second,
			ClaimTimeout: 30 * time.Second,
		})
	}

	s.ready.Store(true)
	slog.Info("server ready", "addr", addr)

	// Watch for SIGTERM/SIGINT in background.
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(sig)
		select {
		case <-sig:
		case <-ctx.Done():
		}
		s.Shutdown()
	}()

	return s.srv.Serve(ln)
}

// Shutdown initiates graceful shutdown with a 10-second drain cap.
func (s *Server) Shutdown() {
	slog.Info("shutdown initiated")
	s.ready.Store(false)

	// Stop the SSE hub pump; live client connections end when the HTTP server
	// drains below.
	if s.hubCtx != nil {
		s.hubCtx()
	}

	// Stop the job worker pool.
	if s.pool != nil {
		s.pool.Stop()
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("shutdown error", "error", err)
	}
	slog.Info("shutdown complete")
}

// ListenedAddr returns the actual address the server is bound to, after Start.
func (s *Server) ListenedAddr() string {
	return s.srv.Addr
}
