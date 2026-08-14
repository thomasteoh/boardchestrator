// Package server provides the HTTP server with chi router, middleware,
// and graceful shutdown.
package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/agentrt"
	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/config"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/event"
	"github.com/thomasteoh/boardchestrator/internal/job"
	"github.com/thomasteoh/boardchestrator/internal/perm"
	"github.com/thomasteoh/boardchestrator/internal/report"
	"github.com/thomasteoh/boardchestrator/internal/schedule"
	"github.com/thomasteoh/boardchestrator/internal/search"
	"github.com/thomasteoh/boardchestrator/internal/sse"
	"github.com/thomasteoh/boardchestrator/internal/storage"
	"github.com/thomasteoh/boardchestrator/internal/tenant"
	"github.com/thomasteoh/boardchestrator/internal/web"
	"github.com/thomasteoh/boardchestrator/internal/webhook"
	"github.com/thomasteoh/boardchestrator/internal/wiki"
)

// timeFormat is the canonical UTC timestamp layout used across the codebase
// (matches the action package's store.go timeFormat).
const timeFormat = "2006-01-02T15:04:05.000Z"

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
	db       *sql.DB

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
	// disp is the action dispatcher. Created in Start when DB is wired.
	disp *action.Dispatcher
	// eng is the agent run engine (SPEC §10). Created in Start when DB is
	// wired; its Handler replaces the job pool's NoopHandler.
	eng *agentrt.Engine
	// resumeSub is the approval.decided subscription that enqueues run resume
	// jobs (WU-306). Its unsubscribe func is kept to stop on Shutdown.
	resumeUnsub func()
	// triggerUnsub is the mention/column subscription that enqueues agent runs
	// (WU-307). Its unsubscribe func is kept to stop on Shutdown.
	triggerUnsub func()
	// chatUnsub is the chat.sent subscription that enqueues chat runs (WU-308).
	// Kept to stop on Shutdown.
	chatUnsub func()
	// schedStop cancels the scheduled-trigger poller goroutine (WU-309).
	// Kept to stop on Shutdown.
	schedStop context.CancelFunc
	// snapStop cancels the daily sprint-snapshot poller goroutine (WU-504).
	// Kept to stop on Shutdown.
	snapStop context.CancelFunc
	// webhookDeliver delivers outbound webhooks (WU-404). Created in Start when
	// the DB + job store are wired; its RunJob handles webhook.deliver jobs.
	webhookDeliver *webhook.Deliverer
	// webhookUnsub is the bus subscription that fans events into webhook
	// deliveries. Kept to stop on Shutdown.
	webhookUnsub func()
	// trigq is the read query handle the trigger loop uses to re-read tasks,
	// comments, and columns from the DB (source of truth for mention/column
	// detection). Set in Start once the DB is wired.
	trigq *sqlc.Queries
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
		s.db = d
		// The /events stream authenticates via the session the middleware
		// stashes in the request context (WU-005). No DB ⇒ no sessions ⇒ no
		// stream (nothing to authorise).
		s.hub = sse.New(s.bus, sse.SessionUserResolver)
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
	// API key auth middleware — resolves Bearer tokens into API key actors
	// before session middleware. When a valid API key is present, it takes
	// priority over session auth for API routes.
	if s.db != nil {
		s.mux.Use(auth.APIKeyAuthMiddleware(s.db))
	}
	// Session resolution then CSRF protection, in that order — CSRF needs the
	// resolved session. Only mounted when a session store exists.
	if s.sessions != nil {
		sc := auth.SessionConfig{Store: s.sessions, Secret: s.cfg.SessionSecret}
		s.mux.Use(sc.Session())
		s.mux.Use(sc.CSRF())
	}
}

func (s *Server) setupRoutes() {
	// Wire the templ-based 403 handler for auth middleware.
	auth.ForbiddenHandler = func(w http.ResponseWriter, r *http.Request, title, message string) {
		web.RenderErrorPage(w, r, 403, title, message)
	}
	// Custom error pages for 404, 405, 500.
	s.mux.NotFound(s.handleNotFound)
	s.mux.MethodNotAllowed(s.handleMethodNotAllowed)
	s.mux.Get("/healthz", s.handleHealthz)
	s.mux.Get("/readyz", s.handleReadyz)
	s.mux.Handle("/metrics", promhttp.Handler())
	if s.hub != nil {
		s.mux.Get("/events", s.hub.Handler)
	}
	web.Routes(s.mux)
	if s.db != nil {
		ah := auth.NewOAuthHandler(auth.OIDCConfig{
			ClientID:     s.cfg.GoogleClientID,
			ClientSecret: s.cfg.GoogleClientSecret,
			BaseURL:      s.cfg.BaseURL,
		}, auth.GitHubConfig{
			ClientID:     s.cfg.GitHubClientID,
			ClientSecret: s.cfg.GitHubClientSecret,
			BaseURL:      s.cfg.BaseURL,
		}, s.sessions, s.db, auth.SessionConfig{
			Store:    s.sessions,
			Secret:   s.cfg.SessionSecret,
			Insecure: true,
		})
		ah.SecretKey = tenant.PadKey(s.cfg.SecretKey)
		ah.SetBootstrapConfig(s.cfg.AdminEmails, s.cfg.BootstrapToken)
		s.mux.Get("/auth/google", ah.HandleGoogleLogin)
		s.mux.Get("/auth/google/callback", ah.HandleGoogleCallback)
		s.mux.Get("/auth/github", ah.HandleGitHubLogin)
		s.mux.Get("/auth/github/callback", ah.HandleGitHubCallback)
	}
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

// recover middleware catches panics and returns 500 via templ error page.
func (s *Server) recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("panic recovered",
					"req_id", RequestID(r.Context()),
					"recover", rec,
				)
				w.WriteHeader(http.StatusInternalServerError)
				web.RenderErrorPage(w, r, 500, "Internal server error", "Something went wrong on our end. Please try again later.")
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

func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
	web.RenderErrorPage(w, r, 404, "Page not found", "The page you requested doesn't exist.")
}

func (s *Server) handleMethodNotAllowed(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusMethodNotAllowed)
	web.RenderErrorPage(w, r, 405, "Method not allowed", "This endpoint does not support the requested HTTP method.")
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

	// Create the agent run engine, then start the job worker pool with its
	// run handler (SPEC §10: background jobs drive runs; WU-305 replaces the
	// NoopHandler). The engine builds a provider client per run from the
	// agent's provider row and decrypts the key with the tenant secret.
	if s.db != nil {
		s.eng = agentrt.New(agentrt.Config{
			DB:         s.db,
			Secret:     s.cfg.SecretKey,
			EventSink:  s.EventSink(),
			DeltaSink:  s.chatDeltaSink(),
			OnCapAlert: s.orgCapAlertSink(),
		})
		store := job.NewJobStore(s.db)
		s.trigq = sqlc.New(s.db)
		// Outbound webhook delivery (WU-404): owns the webhook.deliver job kind.
		s.webhookDeliver = webhook.New(s.db, store)
		// The pool handler routes webhook.deliver jobs to the Deliverer; all
		// other kinds fall through to the agent engine.
		engHandler := s.eng.Handler(store)
		s.pool = job.NewPool(ctx, job.PoolConfig{
			Store: store,
			Handler: func(ctx context.Context, j sqlc.Job) error {
				if j.Kind == "webhook.deliver" {
					return s.webhookDeliver.RunJob(ctx, j)
				}
				if j.Kind == "sprint.snapshot" {
					return s.runSprintSnapshotJob(ctx, j)
				}
				return engHandler(ctx, j)
			},
			MaxWorkers:   s.cfg.AgentWorkers,
			PollInterval: 5 * time.Second,
			ClaimTimeout: 30 * time.Second,
		})
		// Approval resume (WU-306): when approval.decide marks a decision and
		// requeues a run, enqueue a fresh run job so the engine re-runs it. The
		// gate sees the decided row and proceeds/forbids accordingly.
		var resumeSub *event.Subscription
		resumeSub, s.resumeUnsub = s.bus.Subscribe(event.Filter{Names: map[string]struct{}{"approval.decided": {}}}, 16)
		go s.resumeLoop(ctx, store, resumeSub)

		// Mention + column triggers (WU-307): subscribe to the user-driven
		// task/comment/move actions and enqueue agent runs on @mentions or
		// movement into a trigger column.
		var triggerSub *event.Subscription
		triggerSub, s.triggerUnsub = s.bus.Subscribe(event.Filter{Names: map[string]struct{}{
			"task.update":    {},
			"comment.create": {},
			"task.move":      {},
		}}, 32)
		go s.triggerLoop(ctx, store, triggerSub)

		// Chat runs (WU-308): when chat.send writes a user message and emits
		// chat.sent, enqueue a chat run job for the session's agent. The engine
		// Handler detects the run's chat_session_id and streams deltas back to
		// the initiating user.
		var chatSub *event.Subscription
		chatSub, s.chatUnsub = s.bus.Subscribe(event.Filter{Names: map[string]struct{}{"chat.sent": {}}}, 16)
		go s.chatLoop(ctx, store, chatSub)

		// Scheduled triggers (WU-309): poll due triggers on a ticker and enqueue
		// agent runs (trigger='schedule', prompt as instruction). Per-project
		// overlap guard skips a project with an active run. Stopped on Shutdown.
		var schedCtx context.Context
		schedCtx, s.schedStop = context.WithCancel(ctx)
		go s.schedulerLoop(schedCtx, store)

		// Daily sprint snapshots (WU-504): poll active sprints and enqueue one
		// sprint.snapshot job per sprint per day. Stopped on Shutdown.
		var snapCtx context.Context
		snapCtx, s.snapStop = context.WithCancel(ctx)
		go s.snapshotLoop(snapCtx, store)

		// Outbound webhooks (WU-404): subscribe to all events; the deliverer
		// matches each event against the org's enabled webhooks + their event
		// filter and enqueues signed deliveries.
		var whSub *event.Subscription
		whSub, s.webhookUnsub = s.bus.Subscribe(event.Filter{}, 64)
		go func() {
			defer whSub.Close()
			for {
				select {
				case <-ctx.Done():
					return
				case ev, ok := <-whSub.C:
					if !ok {
						return
					}
					if err := s.webhookDeliver.HandleEvent(ctx, ev); err != nil {
						slog.Error("webhook: deliver event", "err", err)
					}
				}
			}
		}()
	}

	// Create the action dispatcher with DB-backed stores, scope resolver,
	// and deny-by-default permission engine.
	if s.db != nil {
		s.disp = action.New(s.db,
			action.WithScopeResolver(action.NewDBScopeResolver(s.db)),
			action.WithEventSink(s.EventSink()),
			action.WithPermissionChecker(perm.NewCheckerAdapter(s.db)),
			action.WithSecretKey(tenant.PadKey(s.cfg.SecretKey)),
		)
		web.SetDispatcher(s.disp)
		// Wire the attachment storage backend.
		store := storage.NewLocalStore(storage.Config{
			DataDir: s.cfg.DataDir,
		})
		action.SetStorageStore(store)
		web.SetFileStore(store)

		// Wire the wiki backend (WU-501): clone cache under DataDir/wiki.
		// WU-502: commit-as-user resolves the actor's linked GitHub token.
		secretKey := tenant.PadKey(s.cfg.SecretKey)
		wstore := wiki.NewStore(s.db, filepath.Join(s.cfg.DataDir, "wiki"), wiki.WithTokenFn(func(ctx context.Context, userID string) (token, login, name, email string, ok bool, err error) {
			conn, err := sqlc.New(s.db).FindGithubConnection(ctx, userID)
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return "", "", "", "", false, nil
				}
				return "", "", "", "", false, fmt.Errorf("github: find connection: %w", err)
			}
			if conn.TokenEnc == "" {
				return "", "", "", "", false, nil
			}
			plain, err := tenant.Decrypt(secretKey, conn.TokenEnc)
			if err != nil {
				return "", "", "", "", false, fmt.Errorf("github: decrypt token: %w", err)
			}
			login = conn.Login
			if u, err := sqlc.New(s.db).GetUser(ctx, userID); err == nil {
				name, email = u.Name, u.Email
			}
			return plain, login, name, email, true, nil
		}))
		action.SetWikiStore(wstore)
		web.SetWikiStore(wstore)

		// Start the search indexer — subscribes to the event bus.
		ix := search.NewIndexer(s.db)
		sub, _ := s.bus.Subscribe(event.Filter{
			Names: map[string]struct{}{
				"task.create":    {},
				"task.update":    {},
				"task.archive":   {},
				"task.unarchive": {},
				"comment.create": {},
				"comment.update": {},
				"comment.delete": {},
			},
		}, 64)
		go func() {
			defer sub.Close()
			for {
				select {
				case ev, ok := <-sub.C:
					if !ok {
						return
					}
					if err := ix.IndexEvent(context.Background(), ev.Name, ev.Payload); err != nil {
						slog.Error("search indexer", "event", ev.Name, "error", err)
					}
				case <-ctx.Done():
					return
				}
			}
		}()
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

	// Stop the approval resume subscriber (WU-306).
	if s.resumeUnsub != nil {
		s.resumeUnsub()
	}
	// Stop the mention/column trigger subscriber (WU-307).
	if s.triggerUnsub != nil {
		s.triggerUnsub()
	}
	// Stop the chat run subscriber (WU-308).
	if s.chatUnsub != nil {
		s.chatUnsub()
	}
	// Stop the scheduled-trigger poller (WU-309).
	if s.schedStop != nil {
		s.schedStop()
	}
	// Stop the daily sprint-snapshot poller (WU-504).
	if s.snapStop != nil {
		s.snapStop()
	}
	// Stop the outbound webhook subscriber (WU-404).
	if s.webhookUnsub != nil {
		s.webhookUnsub()
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

// resumeLoop drains approval.decided events and enqueues a fresh run job for
// the requeued run (WU-306 resume). It stops when the subscription channel
// closes (Shutdown calls resumeUnsub).
func (s *Server) resumeLoop(ctx context.Context, store *job.JobStore, sub *event.Subscription) {
	for {
		select {
		case <-ctx.Done():
			sub.Close()
			return
		case ev, ok := <-sub.C:
			if !ok {
				return
			}
			var payload struct {
				ID     string `json:"id"`
				Status string `json:"status"`
				RunID  string `json:"run_id"`
			}
			if err := json.Unmarshal(ev.Payload, &payload); err != nil {
				slog.Warn("resume: bad payload", "name", ev.Name, "error", err)
				continue
			}
			if payload.RunID == "" {
				continue
			}
			if err := s.eng.EnqueueResume(ctx, store, ev.Org, payload.RunID); err != nil {
				slog.Warn("resume: enqueue failed", "run_id", payload.RunID, "error", err)
			}
		}
	}
}

// mentionRe matches an @Name token. Agent names are [A-Za-z0-9_\-].
var mentionRe = regexp.MustCompile(`@([A-Za-z0-9_\-]+)`)

// triggerLoop drains task.update / comment.create / task.move events and
// enqueues agent runs (WU-307). It re-reads the source of truth from the DB
// rather than trusting the event payload, so detection is robust to partial
// updates. Guards: an agent's own actions never self-trigger, and a task with
// an active run is skipped (per-task cap 1, enforced by EnqueueRun).
func (s *Server) triggerLoop(ctx context.Context, store *job.JobStore, sub *event.Subscription) {
	for {
		select {
		case <-ctx.Done():
			sub.Close()
			return
		case ev, ok := <-sub.C:
			if !ok {
				return
			}
			if ev.ActorType == "agent" {
				// Self-trigger guard: an agent's own actions must not trigger
				// itself (loop prevention).
				continue
			}
			switch ev.Name {
			case "task.update":
				s.triggerOnTask(ctx, store, ev)
			case "comment.create":
				s.triggerOnComment(ctx, store, ev)
			case "task.move":
				s.triggerOnColumn(ctx, store, ev)
			}
		}
	}
}

// triggerOnTask scans a task's description for @mentions after a task.update
// and enqueues a mention run per matched active agent.
func (s *Server) triggerOnTask(ctx context.Context, store *job.JobStore, ev event.Event) {
	var payload struct {
		ID        string `json:"id"`
		ProjectID string `json:"project_id"`
	}
	if err := json.Unmarshal(ev.Payload, &payload); err != nil || payload.ID == "" || payload.ProjectID == "" {
		return
	}
	task, err := s.trigq.FindTaskByID(ctx, sqlc.FindTaskByIDParams{ID: payload.ID, ProjectID: payload.ProjectID})
	if err != nil {
		slog.Warn("trigger: task lookup", "error", err)
		return
	}
	s.enqueueMentions(ctx, store, ev.Org, task.Description, payload.ID, payload.ProjectID, ev.ActorID)
}

// triggerOnComment scans a new comment's body for @mentions.
func (s *Server) triggerOnComment(ctx context.Context, store *job.JobStore, ev event.Event) {
	var payload struct {
		ID        string `json:"id"`
		TaskID    string `json:"task_id"`
		ProjectID string `json:"project_id"`
	}
	if err := json.Unmarshal(ev.Payload, &payload); err != nil || payload.ID == "" || payload.TaskID == "" || payload.ProjectID == "" {
		return
	}
	var comment sqlc.Comment
	if _, err := s.trigq.FindCommentByID(ctx, sqlc.FindCommentByIDParams{ID: payload.ID, ProjectID: payload.ProjectID}); err != nil {
		slog.Warn("trigger: comment lookup", "error", err)
		return
	}
	s.enqueueMentions(ctx, store, ev.Org, comment.Body, payload.TaskID, payload.ProjectID, ev.ActorID)
}

// enqueueMentions parses @mentions in text and enqueues a mention run for each
// matched active org agent. initiatedBy is the mentioning user (from the event
// actor) — only user actors reach here (agent actors were guarded earlier).
func (s *Server) enqueueMentions(ctx context.Context, store *job.JobStore, orgID, text, taskID, projectID, initiatedBy string) {
	seen := map[string]bool{}
	for _, m := range mentionRe.FindAllStringSubmatch(text, -1) {
		name := m[1]
		if seen[name] {
			continue
		}
		seen[name] = true
		agent, err := s.trigq.FindActiveAgentByOrgAndName(ctx, sqlc.FindActiveAgentByOrgAndNameParams{
			OrgID: sql.NullString{String: orgID, Valid: orgID != ""},
			Name:  name,
		})
		if err != nil {
			continue // not an active agent — not a mention
		}
		mention := "@" + name
		if _, created, err := s.eng.EnqueueRun(ctx, store, orgID, agent.ID, "mention", taskID, "", projectID, initiatedBy, mention); err != nil {
			slog.Warn("trigger: enqueue mention", "agent", agent.ID, "error", err)
		} else if created {
			slog.Debug("trigger: mention enqueued", "agent", agent.ID, "task", taskID)
		}
	}
}

// triggerOnColumn fires when a task moves into a column configured with a
// trigger_agent_id. The column's trigger_prompt is interpolated with the task.
func (s *Server) triggerOnColumn(ctx context.Context, store *job.JobStore, ev event.Event) {
	var payload struct {
		ID        string `json:"id"`
		ProjectID string `json:"project_id"`
		Status    string `json:"status"`
	}
	if err := json.Unmarshal(ev.Payload, &payload); err != nil || payload.ID == "" || payload.ProjectID == "" || payload.Status == "" {
		return
	}
	task, err := s.trigq.FindTaskByID(ctx, sqlc.FindTaskByIDParams{ID: payload.ID, ProjectID: payload.ProjectID})
	if err != nil {
		slog.Warn("trigger: task lookup", "error", err)
		return
	}
	col, err := s.trigq.FindBoardColumnByProjectAndStatus(ctx, sqlc.FindBoardColumnByProjectAndStatusParams{ProjectID: payload.ProjectID, Status: payload.Status})
	if err != nil || !col.TriggerAgentID.Valid || col.TriggerAgentID.String == "" {
		return // no trigger column at this status
	}
	// Interpolate the prompt: {title}, {key}, {id}, {status}.
	prompt := col.TriggerPrompt
	prompt = strings.ReplaceAll(prompt, "{title}", task.Title)
	prompt = strings.ReplaceAll(prompt, "{key}", task.Key)
	prompt = strings.ReplaceAll(prompt, "{id}", task.ID)
	prompt = strings.ReplaceAll(prompt, "{status}", task.Status)
	if _, created, err := s.eng.EnqueueRun(ctx, store, ev.Org, col.TriggerAgentID.String, "column", payload.ID, "", task.ProjectID, "", prompt); err != nil {
		slog.Warn("trigger: enqueue column", "agent", col.TriggerAgentID.String, "error", err)
	} else if created {
		slog.Debug("trigger: column enqueued", "agent", col.TriggerAgentID.String, "task", payload.ID)
	}
}

// chatLoop drains chat.sent events and enqueues chat run jobs (WU-308). It
// re-reads the chat session from the DB (source of truth for the agent + scope)
// rather than trusting the event payload. The run is enqueued with the session's
// agent and the user's latest message as the instruction; the engine Handler
// detects the run's chat_session_id and streams deltas back to the initiator.
func (s *Server) chatLoop(ctx context.Context, store *job.JobStore, sub *event.Subscription) {
	for {
		select {
		case <-ctx.Done():
			sub.Close()
			return
		case ev, ok := <-sub.C:
			if !ok {
				return
			}
			var payload struct {
				ChatID string `json:"chat_id"`
				Text   string `json:"text"`
			}
			if err := json.Unmarshal(ev.Payload, &payload); err != nil {
				slog.Warn("chat: bad payload", "error", err)
				continue
			}
			if payload.ChatID == "" {
				continue
			}

			q := sqlc.New(s.db)
			sess, err := q.FindChatSessionByID(ctx, sqlc.FindChatSessionByIDParams{ID: payload.ChatID, OrgID: ev.Org})
			if err != nil {
				slog.Warn("chat: session lookup", "chat_id", payload.ChatID, "error", err)
				continue
			}
			if _, created, err := s.eng.EnqueueRun(ctx, store, ev.Org, sess.AgentID, "chat", "", payload.ChatID, sess.ProjectID.String, sess.CreatedBy, payload.Text); err != nil {
				slog.Warn("chat: enqueue run", "chat_id", payload.ChatID, "error", err)
			} else if created {
				slog.Debug("chat: run enqueued", "chat_id", payload.ChatID, "agent", sess.AgentID)
			}
		}
	}
}

// chatDeltaSink returns the engine's chat-streaming sink (WU-308): it frames
// each assistant content delta as a chat-delta SSE event and targets it to the
// run's initiating user via SendToUser (not broadcast to the whole org). The
// payload mirrors sseData so app.js can dispatch on the chat-delta event name.
func (s *Server) chatDeltaSink() func(chatID, runID, userID, delta string) {
	return func(chatID, runID, userID, delta string) {
		if s.hub == nil {
			return
		}
		payload, err := json.Marshal(struct {
			ChatID string `json:"chat_id"`
			RunID  string `json:"run_id"`
			Delta  string `json:"delta"`
		}{ChatID: chatID, RunID: runID, Delta: delta})
		if err != nil {
			return
		}
		s.hub.SendToUser(userID, sse.EventChatDelta, payload)
	}
}

// orgCapAlertSink returns the callback the engine invokes once per org when
// the org's monthly spend first crosses cap*alert%/100 (WU-310). It records an
// org_cap_alerts row and publishes an org.cap.threshold bus event so the UI
// surfaces the alert.
func (s *Server) orgCapAlertSink() func(orgID string) {
	return func(orgID string) {
		ctx := context.Background()
		q := sqlc.New(s.db)
		org, err := q.FindOrgByID(ctx, orgID)
		if err != nil {
			slog.Warn("cap alert: find org", "org", orgID, "error", err)
			return
		}
		spend, err := q.OrgMonthlySpend(ctx, sqlc.OrgMonthlySpendParams{
			OrgID:      orgID,
			FinishedAt: sql.NullString{String: monthStartUTC(), Valid: true},
		})
		if err != nil {
			slog.Warn("cap alert: spend", "org", orgID, "error", err)
			return
		}
		alert, err := q.CreateOrgCapAlert(ctx, sqlc.CreateOrgCapAlertParams{
			ID:       capAlertID(),
			OrgID:    orgID,
			SpendUsd: spend,
			CapUsd:   org.MonthlyCapUsd,
		})
		if err != nil {
			slog.Warn("cap alert: record", "org", orgID, "error", err)
			return
		}
		// Publish the alert event on the bus so connected UIs can surface it.
		payload, _ := json.Marshal(alert)
		s.bus.Publish(event.Event{Name: "org.cap.threshold", Org: orgID, Subject: "org.cap.threshold", Payload: payload})
	}
}

// monthStartUTC returns the UTC start-of-month timestamp for the current month
// in the canonical format (WU-310 usage window).
func monthStartUTC() string {
	now := time.Now().UTC()
	return time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).Format("2006-01-02T15:04:05.000Z")
}

// capAlertID returns a unique id for an org_cap_alerts row (WU-310).
func capAlertID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// schedulerLoop polls due scheduled triggers on a ticker and enqueues agent
// runs (WU-309). Each due trigger fires once per poll: it re-reads the trigger,
// enqueues a run with trigger='schedule' and the prompt as the instruction, then
// advances next_at via the cron expression. The EnqueueRun per-project overlap
// guard skips a project with an active run, so schedules don't pile up.
func (s *Server) schedulerLoop(ctx context.Context, store *job.JobStore) {
	interval := time.Duration(s.cfg.SchedPollInterval) * time.Second
	if interval <= 0 {
		interval = 60 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			s.fireDueTriggers(ctx, store, now)
		}
	}
}

// fireDueTriggers enqueues a run for every enabled trigger whose next_at is at
// or before now, then advances each trigger's next_at (or clears it on a cron
// error / pause). Runs are enqueued with the trigger's agent + prompt; the
// overlap guard (per-project cap) is enforced inside EnqueueRun.
func (s *Server) fireDueTriggers(ctx context.Context, store *job.JobStore, now time.Time) {
	q := sqlc.New(s.db)
	// Compare against RFC3339 to match schedule.NextAt's format so the
	// lexicographic next_at <= now comparison is consistent.
	due, err := q.ListDueScheduledTriggers(ctx, now.UTC().Format(time.RFC3339))
	if err != nil {
		slog.Warn("scheduler: list due", "error", err)
		return
	}
	for _, t := range due {
		if ctx.Err() != nil {
			return
		}
		// Fire: enqueue a run for the project's agent with the prompt. The
		// per-project overlap guard inside EnqueueRun skips if the project has
		// an active run. initiatedBy is the schedule (system), not a user.
		if _, created, err := s.eng.EnqueueRun(ctx, store, t.OrgID, t.AgentID, "schedule", "", "", t.ProjectID, "schedule", t.Prompt); err != nil {
			slog.Warn("scheduler: enqueue", "trigger", t.ID, "error", err)
		} else if created {
			slog.Debug("scheduler: fired", "trigger", t.ID, "agent", t.AgentID, "project", t.ProjectID)
		}

		// Advance next_at from the cron expression. On error, clear next_at so
		// the row stops firing until edited.
		nextAt, err := schedule.NextAt(t.CronExpr, now)
		if err != nil {
			nextAt = ""
		}
		if err := q.UpdateScheduledTrigger(ctx, sqlc.UpdateScheduledTriggerParams{
			CronExpr:  t.CronExpr,
			Prompt:    t.Prompt,
			AgentID:   t.AgentID,
			Enabled:   t.Enabled,
			NextAt:    nextAt,
			UpdatedAt: now.UTC().Format(timeFormat),
			ID:        t.ID,
			OrgID:     t.OrgID,
		}); err != nil {
			slog.Warn("scheduler: advance next_at", "trigger", t.ID, "error", err)
		}
	}
}

// runSprintSnapshotJob handles a sprint.snapshot job: parse the sprint_id from
// the payload and take a daily snapshot (WU-504). Idempotent per day.
func (s *Server) runSprintSnapshotJob(ctx context.Context, j sqlc.Job) error {
	var p struct {
		SprintID string `json:"sprint_id"`
	}
	if err := json.Unmarshal([]byte(j.PayloadJson), &p); err != nil || p.SprintID == "" {
		return fmt.Errorf("sprint.snapshot: bad payload: %q", j.PayloadJson)
	}
	return report.RunSprintSnapshot(ctx, s.db, p.SprintID)
}

// snapshotLoop enqueues one sprint.snapshot job per active sprint per day.
// It mirrors schedulerLoop: poll, find active sprints, and enqueue a job
// unless one is already queued/running for that sprint today (the snapshot
// itself is idempotent, so a duplicate run is harmless).
func (s *Server) snapshotLoop(ctx context.Context, store *job.JobStore) {
	interval := time.Duration(s.cfg.SchedPollInterval) * time.Second
	if interval <= 0 {
		interval = 60 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	lastDay := ""
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			day := now.UTC().Format("2006-01-02")
			if day == lastDay {
				continue
			}
			lastDay = day
			q := sqlc.New(s.db)
			sprints, err := q.ListActiveSprints(ctx)
			if err != nil {
				slog.Warn("snapshot: list active sprints", "error", err)
				continue
			}
			for _, sp := range sprints {
				if ctx.Err() != nil {
					return
				}
				payload, _ := json.Marshal(map[string]string{"sprint_id": sp.ID})
				if err := store.Enqueue(ctx, "snap:"+sp.ID+":"+day, "sprint.snapshot", string(payload), now.UTC().Format(timeFormat), 3); err != nil {
					slog.Warn("snapshot: enqueue", "sprint", sp.ID, "error", err)
				}
			}
		}
	}
}
