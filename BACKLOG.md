# Boardchestrator — Build Backlog

Loop ledger. One work unit (WU) per iteration. Statuses: `ready` | `in-progress` | `done <date> <commit-subject>` | `blocked(<reason or QUESTIONS ref>)`.

Rules: pick the **first `ready` WU whose deps are all `done`**, top to bottom. Update this file in the same commit as the work. Never reorder or renumber; append notes under the WU if needed. Acceptance criteria (AC) require automated tests unless marked `Manual:`.

---

## Phase 0 — Foundation (branch `build/phase-0`)

### WU-001 · Repo scaffold — `done 2026-07-17 WU-001: repo scaffold`
Deps: none.

Initial scaffold: Go module, cmd/bc entry point with serve/backup subcommands, config loading, Makefile, golangci-lint, .gitignore. Worker subagent created cmd/ and go.mod; orchestrator completed config/tests/Makefile/ignore/lint and fixed golangci-lint compat issues.
Go module `github.com/thomasteoh/boardchestrator`; `cmd/bc` with `serve` (flag/env parse, hello handler) and stub `backup`; `internal/config` loading all `BC_*` vars with defaults + validation; slog JSON logger with level from env; Makefile (`gen`, `check`, `check-scope` [placeholder pass], `dev`, `build`); `.gitignore`; golangci-lint config.
AC: `make check` green; `config.Load` unit tests cover defaults, overrides, invalid values; `bc serve` starts and logs a structured startup line. Manual: curl `/` returns placeholder.

### WU-002 · HTTP server core — `done 2026-07-17 WU-002`
Deps: 001.
chi router; middleware: request-id, structured request log, recover; `/healthz`, `/readyz`; Prometheus `/metrics`; graceful shutdown on SIGTERM (drains, 10s cap).
AC: handler tests for healthz/readyz/metrics; shutdown test asserts in-flight request completes; recover middleware turns panic into 500 + log, test proves it.

### WU-003 · SQLite + migrations + sqlc — `done 2026-07-19 WU-003: SQLite open + embedded migrations + sqlc config + check-scope gate`
Deps: 001.
`internal/db`: open with WAL, foreign_keys, busy_timeout; golang-migrate embedded, run at startup; sqlc config; migration 0001: `users`, `identities`, `sessions`, `platform_settings`; `dbtest` helper (temp file DB, migrations applied); `check-scope` gate implemented (script scanning sqlc queries on tenant tables for org_id param — table list maintained in the script).
AC: dbtest spins/uses/destroys a DB in tests; migration up+down round-trips; WAL confirmed via pragma test; check-scope fails on a deliberate fixture and passes on the repo.
Notes: driver is modernc.org/sqlite v1.46.1 (pure Go — see Q3; newest version whose dep closure keeps `go 1.25` under the pinned local toolchain). sqlc pinned at v1.30.0 in the Makefile (`go run mod@version`; v1.31.x needs go ≥ 1.26); `make gen` skips sqlc until the first query file lands but the config was validated end-to-end with a throwaway query. Tenant-table list lives in `scripts/check-scope.sh` (empty for now — the 0001 tables are platform-scoped); grow it in the same commit as any migration adding an org_id table. check-scope self-tests against committed fixtures in `scripts/testdata/check-scope/` on every run. Manual: `bc serve` against a fresh DB logged "database ready", created all four tables + seeded platform_settings(id=1, bootstrap_done=0), healthz 200, clean shutdown.

### WU-004 · App shell (templ + HTMX, responsive) — `done 2026-07-20 WU-004: app shell (templ layout, vendored htmx/Alpine-CSP, responsive tokens)`
Deps: 002.
templ base layout: header, sidebar (desktop) / bottom-nav + drawer (mobile), main slot; embedded static assets with cache-busting hashes; vendored htmx, Alpine, app.js (SSE helper stub); `app.css` design tokens, dark/light via `data-theme` + `prefers-color-scheme`; breakpoints 640/1024.
AC: layout renders (templ unit test on rendered HTML: nav present, nonce attr present); static served with immutable cache headers (handler test); `make check` includes templ generate diff-clean. Manual: shell verified at 375px and 1280px widths.
Notes: templ v0.3.1001 pinned in Makefile (CLI + runtime module must match); `make gen` now runs templ generate, `make check` enforces `*_templ.go` diff-clean. Vendored Alpine **CSP build** (`@alpinejs/csp` 3.15.8) not standard Alpine — standard Alpine's `new Function()` eval violates the nonce-CSP of SPEC §15; all component logic must live in app.js via `Alpine.data(...)`, templates only reference names. See static/vendor/VENDOR.md. Nonce passed into `Base(Shell)` as a param; real per-request source lands in WU-005. templ emits lowercase `<!doctype html>` (valid HTML5); test asserts lowercase. Manual note: mobile/desktop verified by CSS inspection (breakpoint rules at 640/1024 present, drawer + bottom-nav rules exist), not a headless visual render.

### WU-005 · Sessions, CSRF, CSP — `done 2026-07-20 WU-005: sessions, CSRF, nonce CSP + security headers`
Deps: 003, 004.
Server-side session store (sessions table) with `__Host-bc_session` cookie; CSRF per-session token, middleware rejecting mutating requests without it, token injected into base layout `hx-headers`; nonce-based CSP middleware; security headers (nosniff, frame-ancestors none, referrer-policy).
AC: tests — mutation without CSRF → 403, with → 200; CSP header carries fresh nonce per request; session create/rotate/expiry covered.

Notes:
- New package `internal/auth`: `SessionStore` (sqlc-backed, sessions table), CSRF helpers, and the CSP/Session/CSRF middleware. First sqlc queries landed (`internal/db/queries/sessions.sql` → `internal/db/sqlc`); `make gen`/`make check` now exercise sqlc for real. **sqlc v1.30.0 quirk:** a leading block comment before the first `-- name:` query mangles the generated SQL (drops trailing tokens/`;`) — keep query files starting directly with `-- name:`; per-query comments are fine.
- **Session tokens:** 32 random bytes, hex; only SHA-256 hash stored (`sessions.token_hash`). Sliding TTL 14d, absolute cap 90d (constants `auth.SlidingTTL`/`AbsoluteTTL`). Lookup slides expiry (capped), deletes+rejects expired. `Rotate` creates-new-then-deletes-old (call on login/privilege change); `Revoke` for logout; `PurgeExpired` for a future sweep. Clock injectable via `WithClock` for expiry tests.
- **CSRF:** synchronizer token bound to session = `HMAC-SHA256(BC_SESSION_SECRET, session.token_hash)`, hex. Stateless (recompute + constant-time compare), deterministic per session so it injects into every render. Accepted from `X-CSRF-Token` header (HTMX, wired via `hx-headers` on `<body>`) or `csrf_token` form field. Safe methods (GET/HEAD/OPTIONS/TRACE) exempt; mutating request with no session also 403.
- **CSP:** fresh nonce per request in context (`auth.Nonce`); `Shell.Nonce` now sourced from it (replaces WU-004 placeholder — `TestAppShellFreshNoncePerRequest` still green; web test router mounts `auth.CSP()`). Policy: `default-src 'self'`, `script-src 'self' 'nonce-…'`, `style-src 'self' 'nonce-…'` (layout has no inline style today — nonce is headroom, no unsafe-inline/eval anywhere), `frame-ancestors 'none'`, `object-src 'none'`, `base-uri/form-action/connect-src/font-src 'self'`, `img-src 'self' data:`. Plus `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`.
- **Router order** (`internal/server`): reqid → log → recover → **CSP (always)** → Session → CSRF. Session/CSRF only mount when a DB is wired: added `server.NewWithDB(cfg, *sql.DB)`; `server.New(cfg)` = no-DB (CSP-only, keeps existing tests). `serve.go` now uses `NewWithDB`.
- **Test seam:** `SessionConfig.Insecure` drops the `Secure` cookie attr for plain-HTTP httptest only; production cookie attributes are never weakened (dedicated `TestSessionCookieAttributes` asserts Secure/HttpOnly/SameSite=Lax/Path=/, no Domain on the real config). Note: server integration CSRF test works over plain HTTP because `Secure` gates browser send, not server-side `r.Cookie` reads.
- AC→test: mutation-no-token→403 & with-token→200 = `TestServerCSRFEnforcedWhenDBWired` (full router) + `TestCSRFBlocksMutationWithoutToken`/`TestCSRFAllowsMutationWithValidToken` (middleware); fresh nonce per request = `TestServerCSPFreshNoncePerRequest`, `TestCSPFreshNoncePerRequest` (also asserts header nonce == context nonce), `TestAppShellFreshNoncePerRequest`; session create/rotate/expiry = `TestSessionCreateAndLookup`, `TestSessionRotateInvalidatesOld`, `TestSessionExpiredRejected`, `TestSessionSlidingExpiry`, `TestSessionAbsoluteCap`, `TestSessionRevoke`, `TestSessionPurgeExpired`; extras: cross-session CSRF rejected, safe-method exempt, cookie attrs, hx-headers injection, strict-policy assertions. No new migration needed (sessions table from 0001 sufficient). Opened QUESTIONS Q4 (require BC_SESSION_SECRET — deferred to WU-101, non-blocking).

### WU-006 · Action registry + dispatch — `done 2026-07-20 WU-006: action registry + dispatch pipeline + idempotency/audit migration`
Deps: 003.
`internal/action` per SPEC §4: Definition, Register (panic on dup), Dispatch pipeline (schema validate → scope resolve → perm hook interface → approval hook interface [no-op impl for now] → tx execute → idempotency store → event emit → audit hook); `ErrApprovalPending`, `ErrForbidden`; dry-run mode; migration: `idempotency_keys`, `audit_log`.
AC: unit tests for every pipeline branch: invalid input, unknown action, dup register panic, idempotent replay returns stored result, dry-run does not execute, high-impact emits audit via hook, event emitted with actor.

Notes:
- **Pipeline** (`internal/action/dispatch.go`, `Dispatcher.Dispatch`) runs exactly in SPEC §4 order: resolve/validate actor → lookup action → validate input schema → scope resolve → permission → approval gate (agents only) → dry-run branch (Preview or input echo, no exec/store/event/audit/mutation) → idempotency check (stored result returned without re-running Handle) → execute Handle in a `db.BeginTx` (commit on success, rollback on handler error) → store idempotent result → emit event carrying the actor → audit (ImpactHigh for all actors, and *every* agent action regardless of impact).
- **Hook seams (injectable on `Dispatcher` via `With*` options), where later WUs plug in:**
  - `PermissionChecker.Allow` — default `allowAllPermissions` (Phase 0 has no roles). **WU-105** replaces with the deny-by-default `internal/perm` engine via `WithPermissionChecker`.
  - `ApprovalGate.Gate` — default `noopApprovalGate` (always ApprovalProceed). **WU-306** implements per-impact-class policy, persists `approvals` rows, and returns `ApprovalPending`/`ApprovalForbid`; wire via `WithApprovalGate`. Gate is consulted for agent actors only.
  - `ScopeResolver.Resolve` — default `noopScopeResolver`. **WU-104** enforces id existence + actor membership once orgs/teams/projects exist; wire via `WithScopeResolver`.
  - `EventSink.Emit` — default `noopEventSink`; `Event{Name,Org,Actor,Subject,Payload}` shape owned here (no `internal/event` yet). **WU-007** builds the bus, implements `EventSink`, and fans out to SSE/notify/webhook/search/activity; wire via `WithEventSink`.
  - `AuditSink` (DB-backed default) + `IdempotencyStore` (DB-backed default) over the 0002 tables; `Clock` injectable via `WithClock`.
- **Schema validation:** chose a small `Schema` interface (`Validate(json.RawMessage) error`) with a std-lib-only `ObjectSchema` (required/type/unknown-field checks) + `FuncSchema`, **not** a JSON Schema dependency. SPEC §4 says "compiled once"; the interface satisfies that and keeps Phase 0 deps at std-lib only. A JSON-Schema-backed impl can slot behind the same interface later (WU-401 input fuzzing, WU-402 OpenAPI) without touching Dispatch. No QUESTIONS entry — within WU discretion per the env note.
- **Handler tx contract:** `ActionCtx.Tx` is a `*action.Queries` (wraps sqlc `*Queries` bound to the dispatch tx). Handlers never open their own tx. A nil-`db` Dispatcher runs Handle with nil Tx (narrow unit tests only).
- **Migration 0002** (`0002_action_infra`): `idempotency_keys` (no org_id — global key), `audit_log` (org_id NULLABLE). check-scope.sh documents both as deliberate exclusions from `TENANT_TABLES` (not weakened; self-test still green). Round-trip covered by extending `migratedTables` in `internal/db/db_test.go`.
- **sqlc:** query files start directly with `-- name:` per the v1.30.0 quirk; generated output diff-clean.
- **AC→test** (`internal/action/*_test.go`): invalid input rejected = `TestDispatchInvalidInputRejected` (6 cases, asserts Handle not called) + `TestObjectSchemaValidate`; unknown action = `TestDispatchUnknownAction`; dup Register panic = `TestRegisterDuplicatePanics` (recovers); idempotent replay returns stored result without re-exec = `TestDispatchIdempotentReplay` (asserts Handle ran once); dry-run no exec/mutate = `TestDispatchDryRunDoesNotExecute` (+ no audit) & `TestDispatchDryRunNilPreviewEchoesInput` & `TestDryRunEmitsNoEvent`; ImpactHigh audit via hook = `TestDispatchImpactHighEmitsAudit` (+ `TestDispatchAgentActionAlwaysAudited`, `TestDefaultAuditSinkWritesRow`); event with actor = `TestDispatchEmitsEventWithActor`; extras: `TestDispatchForbiddenWhenPermDenies`, `TestDispatchApprovalPending`/`ApprovalForbid`/`ApprovalGateSkippedForNonAgent`, `TestDispatchScopeFailure`, `TestHandlerErrorRollsBackTx`/`SuccessCommitsTx`, `TestClockInjectable`, `TestDispatchRejectsBadActor`.
- **`bc serve` unchanged:** migration 0002 applies via the embedded FS at startup; no action packages register yet (first is WU-104), so no Dispatcher is constructed in serve.go — the defaults are ready for that WU.

### WU-007 · Event bus + SSE hub — `done 2026-07-20 WU-007: event bus + SSE hub + /events endpoint`
Deps: 002, 006.
`internal/event` typed pub/sub (buffered, non-blocking, drop-with-metric on slow consumer); `internal/sse` hub keyed by user with topic filter; `/events` endpoint (session auth stub interface), heartbeat, Last-Event-ID ring buffer.
AC: bus delivery + slow-consumer tests; SSE handler test asserts event framing, heartbeat, replay from ring buffer.

Notes:
- **Bus filter model** (`internal/event`): `Filter{Org, Names}`. `Org==""` matches any org, else exact-match; `Names==nil` matches any action name, else membership in the set. Filtering is by **org + action name only, not subject** — enough for the SSE hub (which re-checks per-user/per-view relevance) and keeps tenancy knowledge out of the bus. Per-subscriber buffered channel (default 64); `Publish` is non-blocking — on a full buffer it drops for that subscriber and increments `bc_event_dropped_total{org}` (promauto default registry, same as the server's HTTP metrics), never blocking the publisher/dispatch path. Subscribe returns a `*Subscription` (read `.C`) + an unsubscribe func; `Close` is idempotent and closes the channel.
- **EventSink adapter location + import-cycle decision:** the adapter lives in `internal/event` (`event.SinkAdapter`, `event.NewSink(bus)`), NOT in `internal/action`. Dependency direction is one-way **event → action**: the adapter imports `action` to implement `action.EventSink` and convert `action.Event`→`event.Event`. `action` does not import `event`, so no cycle. The `action.EventSink` interface was **not changed**. Wire onto the Dispatcher via the existing `action.WithEventSink(server.EventSink())` — the no-op default from WU-006 is replaced only where a Dispatcher is constructed, which is still nowhere in serve.go (WU-006 note: first action registers in WU-104), so the adapter is made available (`server.Bus()`, `server.EventSink()`) and unit-tested; no Dispatcher wiring change was needed this WU.
- **SSE event names** (`internal/sse`, SPEC §3/§8 framing helper `frame`): `task-updated`, `notification`, `chat-delta`, `run-status`. `eventNameFor` maps action-name prefixes (`task.*`→task-updated, `notification.*`→notification, `chat.*`→chat-delta, `run.*`→run-status) with a generic `message` fallback so new actions stream without a code change. Frame is `id: <n>\nevent: <name>\ndata: <json>\n\n`; heartbeat is a `: ping\n\n` comment every 25s (`HeartbeatInterval`, overridable in tests via `WithHeartbeat`). `data:` JSON carries `{name,org,subject,payload}`.
- **How current-user is resolved:** the hub takes a `UserResolver` seam (the BACKLOG "session auth stub interface"). Production uses `sse.SessionUserResolver`, which reads the session the WU-005 middleware stashed in the request context via the existing `auth.SessionFrom` accessor — **no new accessor needed, no cookie parsing duplicated**. Tests inject a stub resolver. Unauthenticated → 401.
- **Last-Event-ID / replay:** per-hub fixed-size ring buffer (256 events, best-effort). Every dispatched bus event gets a monotonic id; on reconnect the handler reads `Last-Event-ID` (header, or `last_event_id` query fallback) and replays buffered events with a greater id before live streaming. A client further behind than the buffer catches whatever remains and should refetch.
- **Server wiring:** `Server` now owns a `*event.Bus` (always) and a `*sse.Hub` (only when a DB/session store is wired — the stream needs the authed user). `/events` mounts only in that case (no-DB server → 404). `hub.Run` is pumped for the server lifetime (started in `Start`, cancelled in `Shutdown`). Added `statusRecorder.Flush()` so SSE frames flush through the request-logging middleware; the handler flushes response headers immediately after `WriteHeader` so `EventSource`/clients establish the connection before the first event.
- **Phase-0 audience:** `dispatch` currently fans every event to every authenticated client (no orgs/memberships until WU-104); the audience narrows to org members in later WUs. Per-client delivery is also non-blocking (stalled client drops; ring buffer + reconnect cover gaps).
- **AC→test:** bus delivery = `event.TestBusDelivery` (+ `TestFilterByOrgAndName`, `TestSinkAdapterForwards`, `TestUnsubscribeStopsDelivery`); slow-consumer drops-without-blocking + counter increments = `event.TestSlowConsumerDropsWithoutBlocking` (reads the counter via `client_model` directly to avoid adding prometheus/testutil's indirect test dep — `client_model` was already an indirect dep, now promoted to direct by `go mod tidy`; no new module, `go 1.25` unchanged); SSE event framing (`id:`/`event:`/`data:` + blank-line terminator) = `sse.TestEventFraming` + `TestFrameParses`; heartbeat = `sse.TestHeartbeat`; replay from ring via Last-Event-ID = `sse.TestReplayFromRingBuffer`; plus `sse.TestHandlerRejectsUnauthenticated`, `TestHandlerSetsSSEHeaders`, `TestEventNameMapping`, and server integration `server.TestEventsStreamsToAuthedUser` / `TestEventsRouteAbsentWithoutDB`. Streaming tests use `httptest.NewServer` + a real HTTP client reading frames over a socket (not a shared `ResponseRecorder`) so `-race` sees no data race; `closeServer` drops client conns before `srv.Close()` for idle-heartbeat streams.
- No QUESTIONS entries; all within-WU discretion per the env note. No new migration.

### WU-008 · Dockerfile + CI — `ready`
Deps: 001.
Multi-stage Dockerfile (distroless nonroot, /data volume); workflows: `lint.yml` (PR→main: golangci-lint, gofmt, templ gen check), `test.yml` (push→main: `go test -race ./...`), `release.yml` (tag `*-rc.*` matching `^\d+\.\d+\.\d+-rc\.\d+$`: build image, no push; tag `^\d+\.\d+\.\d+$`: buildx, push ghcr `X.Y.Z` + `latest`).
AC: `docker build` succeeds locally; workflows lint clean (actionlint if available); tag-pattern filtering covered by workflow-level `if` conditions reviewed against both tag shapes. Manual: build run recorded in note below.

### WU-009 · Landing page — `in-progress`
Deps: 004.
Static landing at `/` for unauthenticated users: hero, feature sections (board, agents, wiki, MCP), animated flair honouring reduced-motion, screenshots placeholder slots, links to login + GitHub repo; OpenGraph/Twitter meta, favicon set.
AC: handler test (unauthenticated `/` → landing; authenticated → app shell redirect); HTML validates (no unclosed tags via parser test); reduced-motion media query present. Manual: visual pass at 375/1280px.

### WU-010 · PWA — `ready`
Deps: 004, 009.
Manifest + icons; `sw.js` caching app shell + static (cache-first static, network-first documents, never API/SSE); offline fallback page with reconnect notice.
AC: manifest served with correct MIME + linked from layout; sw excludes `/api`, `/events`, `/mcp` (unit test on route matcher logic extracted to testable JS-free Go route list or documented manual check). Manual: Lighthouse installable check.

---

## Phase 1 — Identity & Tenancy (branch `build/phase-1`)

### WU-101 · Google OIDC login — `ready`
Deps: 005.
Discovery-based OIDC with PKCE, state, nonce; `/auth/google` + callback; user create/link by verified email; session issued + rotated; login rate limit.
AC: httptest fake IdP covers happy path, bad state, bad nonce, unverified email; session cookie attributes asserted.

### WU-102 · GitHub OAuth login — `ready`
Deps: 101.
GitHub flow with state; email fetch (primary verified); identity link to existing user by email; stores token_enc for later GitHub features.
AC: fake GitHub server tests: new user, link-to-existing, missing verified email → friendly error.

### WU-103 · Bootstrap gating — `ready`
Deps: 101.
Per SPEC §7: `BC_ADMIN_EMAILS` / `BC_BOOTSTRAP_TOKEN` gate; token logged while unclaimed; pre-bootstrap non-admin logins rejected with page; `bootstrap_done` flip is atomic.
AC: tests for all three paths (email match, token, rejected); concurrent first-login race yields exactly one admin (tx test).

### WU-104 · Orgs, teams, projects — `ready`
Deps: 006, 103.
Migrations `orgs, org_secrets, teams, projects, roles, memberships`; actions `org.create/update`, `team.create/update`, `project.create/update/archive` (project KEY validation `^[A-Z][A-Z0-9]{1,9}$`, next_task_num=1); context fields editable; encrypted org_secrets helpers; sqlc queries all org-scoped (check-scope now enforcing for these tables).
AC: action tests incl. duplicate slug/key rejection; secrets round-trip encrypt/decrypt; check-scope covers new tables.

### WU-105 · Permission engine + roles — `ready`
Deps: 104.
`internal/perm` per SPEC §6; seed system roles (Org Owner, Team Admin, Member, Viewer, Guest) as migration data; actions `role.create/update/assign`; copy-on-edit for system roles; dispatch perm hook wired to engine (replacing stub).
AC: resolution tests: org-level grant applies to child project; additive union; wildcard `task.*`; agent role∩skills intersection (skills stubbed as fixture); deny-by-default; copy-on-edit leaves system role untouched.

### WU-106 · Memberships & invites — `ready`
Deps: 105.
Actions `member.invite/remove`, `invite.accept`; invite email-less flow v1: generate link (shown to inviter to share; no SMTP), token hashed, expiry; accept binds after SSO; membership CRUD UI (org/team/project people pages).
AC: invite lifecycle tests (create, accept, expired, reuse rejected); remove revokes access (perm test).

### WU-107 · Tenancy UI — `ready`
Deps: 104, 105, 106.
templ pages: org switcher, org/team/project settings (name, context markdown with preview, visibility), roles editor (grant matrix), people pages; breadcrumbs; responsive.
AC: handler tests for each page incl. permission-denied renders; context save round-trips. Manual: mobile pass.

### WU-108 · User settings — `ready`
Deps: 105.
Pages: theme (persisted, instant apply), timezone (browser-default detect), sessions list + revoke, notification prefs skeleton (table + toggles; engine lands in WU-211).
AC: theme/timezone persistence tests; revoked session rejected on next request.

### WU-109 · API keys — `ready`
Deps: 105.
`apikey.create/revoke` actions; settings UI (show-once secret); bearer auth middleware resolving key → actor(apikey, owner) with scope intersection; last_used tracking.
AC: create/parse/verify tests; revoked + wrong-secret rejected; scope narrowing enforced in a dispatch test (key without `task.create` cannot despite owner grant).

### WU-110 · Audit log — `ready`
Deps: 104, 106.
Audit writer wired to dispatch hook (ImpactHigh + all agent actions + logins/key events); org audit page (filter by actor/action/date) + CSV export; platform audit for platform admin.
AC: audited actions produce rows with actor/ip; non-privileged user cannot view (perm test); CSV golden test.

### WU-111 · Data export & deletion — `ready`
Deps: 108, 110.
Per-user JSON export (profile, memberships, authored comments/tasks refs); account deletion: PII scrubbed, identities/sessions/keys removed, authored content re-attributed to "Former member"; org export (platform admin): full org JSON.
AC: export golden structure test; post-deletion login impossible, content anonymised, FK integrity holds.

---

## Phase 2 — Boards & Tasks (branch `build/phase-2`)

### WU-201 · Task model + CRUD actions — `ready`
Deps: 105.
Migrations: tasks, task_assignees/watchers, labels, task_labels, task_relations, comments, task_activity, custom_field_defs/values; actions `task.create/update/assign/label/relate/archive`, `label.create/update`; per-project numbering (tx-safe `next_task_num`); activity rows on every change; `KEY-n` reference parser package.
AC: numbering race test (parallel creates → unique nums); every mutation writes activity with actor; relation cycle allowed except self-reference; custom field validation per kind.

### WU-202 · Task detail page — `ready`
Deps: 201, 007.
Full task view: markdown description (edit-in-place), fields sidebar (assignees, labels, points, priority, due, sprint slot), relations, watchers, activity timeline, comments thread (markdown + preview, edit/delete); @mention autocomplete (users; agents come in WU-306); dates in viewer timezone; responsive sheet layout on mobile.
AC: handler tests: render, edit description, comment CRUD, mention persists metadata; XSS test (script in markdown neutralised).

### WU-203 · Board columns config + board view — `ready`
Deps: 201.
`board_columns` migration + defaults on project create (Backlog/To Do/In Progress/Review/Done); column settings UI (add/rename/recolour/reorder/WIP/state mapping/move-roles); board view rendering columns + cards (title, key, assignee avatars, labels, points), WIP indicator; swimlanes by assignee/label/custom field.
AC: default columns seeded; board render test with swimlanes; WIP breach shows indicator (render test).

### WU-204 · Drag-and-drop + move — `ready`
Deps: 203, 007.
SortableJS wiring (pointer + long-press touch); `task.move` action (column/state + position REAL midpoint, periodic rebalance); HTMX reorder endpoint; card "Move to…" menu (keyboard/touch path, full keyboard grab-move-drop); column move-roles enforced; SSE `task-updated` refreshes other viewers' boards.
AC: move action tests (position ordering, forbidden column for role, state sync); rebalance test; SSE event emitted on move.

### WU-205 · Backlog view + saved filters + bulk ops — `ready`
Deps: 201, 203.
Backlog: ordered list with inline edit + drag-rank; filter bar (assignee, label, sprint, state, text) → `saved_filters` (share to team, pin as board tab); multi-select with bulk assign/label/move/sprint.
AC: filter query builder tests (each dimension + combinations); bulk op is one action dispatch per semantic op with n subjects (activity per task); pinned filter renders as tab.

### WU-206 · Sprints — `ready`
Deps: 205.
Sprint CRUD actions; assign tasks in/out (from backlog + task page); active-sprint board filter; close sprint → prompt to move open tasks (to backlog/next sprint).
AC: sprint lifecycle tests; close-with-open-tasks flow moves correctly; board filter shows only sprint tasks.

### WU-207 · Attachments (local) — `ready`
Deps: 202, 009.
Storage interface + local backend per SPEC §9; upload (drag-drop + picker) with org size/type limits; image re-encode; SVG sanitise; inline image preview lightbox; document list with download (attachment disposition, nosniff); `attachment.upload/delete` actions.
AC: limit enforcement tests; SVG with script sanitised (golden); served headers asserted; delete removes blob + row.

### WU-208 · Search (FTS5) — `ready`
Deps: 201, 007.
FTS migration; indexer subscribed to task/comment events (wiki joins in WU-503); `search.query` action with permission-filtered results; search page + command palette (`ctrl/cmd-k`: tasks, actions).
AC: index-on-event tests; visibility filter test (private project hidden from non-member); palette endpoint returns mixed ranked results.

### WU-209 · Task templates + recurring — `ready`
Deps: 201.
Template CRUD (capture fields/labels/points/checklist-as-description); create-from-template; recurring rules (cron via robfig/cron parser, scheduler job in queue table) spawning from template.
AC: template round-trip; cron next_at computation tests; scheduler idempotence (no double-spawn on restart).

### WU-210 · Archive — `ready`
Deps: 201, 205.
Archive task (hidden from board/backlog, searchable, restorable); archive project (read-only banner, hidden from switchers, restorable by org owner).
AC: archived exclusion + restore tests; archived project rejects mutations (dispatch test).

### WU-211 · Notifications — `ready`
Deps: 007, 202.
Engine subscribed to events: assigned, @mentioned, watched-task state change, (agent kinds reserved); per-user prefs honoured; grouping (n changes on task X within window); notification centre UI (badge via SSE, list, mark read/all-read).
AC: each trigger → row for right users only (self-action excluded); pref off suppresses; grouping window test; markread action test.

### WU-212 · Realtime board/task polish — `ready`
Deps: 204, 211.
SSE-driven partial refresh: board cards, task detail (comment appears live), notification badge; `aria-live` regions; reconnect with backoff + missed-event refetch.
AC: event→partial mapping tests; reconnect logic unit test. Manual: two-browser live check.

### WU-213 · Responsive board (mobile focus mode) — `ready`
Deps: 204.
Single-column focus with horizontal swipe between columns, sticky column header + count; card tap → task sheet; long-press drag; bottom nav wired (Boards/Backlog/Chat placeholder/Search/Notifications).
AC: render tests for mobile shell variants. Manual: 375px walkthrough of move-via-menu and swipe.

### WU-214 · Accessibility pass — `ready`
Deps: 202, 204, 205, 211.
Keyboard operability audit + fixes (board grab/move/drop shortcuts documented in a help dialog); ARIA roles on columns/cards/dialogs; focus management (open/close returns focus); visible focus rings; contrast fixes both themes; reduced-motion honoured everywhere.
AC: automated: templ renders carry expected roles/labels (tests); axe-core check via chromedp if available, else Manual: documented keyboard walkthrough of board, task, palette.

### WU-215 · Phase 2 hardening — `ready`
Deps: all 2xx.
Fuzz markdown/mention/KEY-ref parsers; race-detector soak on board mutations; N+1 query audit on board/backlog renders (query-count assertions); error-page polish (403/404/500 templ pages).
AC: fuzz corpora committed; query-count tests for board render ≤ fixed budget; error pages tested.

---

## Phase 3 — Agent Harness (branch `build/phase-3`)

### WU-301 · Job queue — `ready`
Deps: 006.
`jobs` migration; claim/backoff/max-attempts per SPEC §10; worker pool with graceful drain; dead-job status + requeue action; queue depth/age metrics.
AC: claim contention test (n workers, no double-claim); backoff schedule test; drain-on-shutdown test.

### WU-302 · Providers (OpenAI-compatible) — `ready`
Deps: 104.
`providers` + `provider_orgs` migrations; platform-admin UI (create provider: base URL, key, models; allocate to orgs); provider client with streaming, retry/jitter, usage capture; `codex_sso` kind registered but returns "not yet supported" (QUESTIONS Q1).
AC: client tests against httptest fake (stream parse, 429 retry, usage extraction); allocation visibility test (org sees only allocated).

### WU-303 · Agents + templates — `ready`
Deps: 302, 105.
`agents` migration; platform template CRUD + allocation; org agent CRUD (customise allocated: name, context, skills, role, retry, rate, budget, approval policy); unique @name per org; membership rows for agents (actor_type=agent).
AC: template→org customisation copy semantics tests; name uniqueness; agent-as-member permission resolution test.

### WU-304 · Skills hub — `ready`
Deps: 303.
`skills`, `agent_skills` migrations; skill CRUD UI (instructions editor, allowed-actions picker from registry, param schema, optional external MCP endpoints with encrypted creds + SSRF-validated URLs); versioning (edit bumps version, agents pin latest by default); import/export JSON bundle; platform vs org scoping.
AC: allowed-actions must be subset of registry (validation test); import round-trip golden; effective-permission intersection test with WU-105 engine; SSRF validator rejects private ranges.

### WU-305 · Run engine + tool loop — `ready`
Deps: 301, 303, 006.
`runs`, `run_steps` migrations; lifecycle per SPEC §10; context assembly (labelled cascade); tool loop with registry-derived tools filtered by effective perms; step cap; cancellation; transcripts stored; failure→retry per agent policy→notify; run detail UI (steps, tokens) linked from task.
AC: fake-provider integration tests: happy multi-tool run, permission-denied tool call recorded + surfaced to model, step cap halt, cancel mid-run, retry-then-fail notifies; context assembly golden test (ordering + labels).

### WU-306 · Approval gates — `ready`
Deps: 305.
`approvals` migration; dispatch approval hook implemented (policy per impact class from agent config); run state `awaiting_approval`; approval UI on task + notification (kind: approval requested); `approval.decide` resumes run with result; forbid class blocks with clear model-visible error; high-impact default require-approval on new agents.
AC: gate matrix tests (auto/require/forbid × read/low/high); resume-after-approve continues run correctly (fake provider); reject surfaces to model and run completes gracefully.

### WU-307 · @mention + column triggers — `ready`
Deps: 305, 204.
Mention parser recognises active org agents in saved description/comments → enqueue run (trigger=mention, task context, the mentioning text as instruction); column `trigger_agent_id/prompt` settings UI; `task.move` into trigger column enqueues (trigger=column, prompt template with task interpolation); agent thread rendering on task (distinct styling, collapsible steps); loop guard: an agent's own actions never trigger mentions/column runs of itself; per-task concurrent-run cap 1 (queue serialises).
AC: mention→run created (not for inactive/unknown names, not self-trigger); column trigger fires once per entry; template interpolation golden; agent thread renders transcript.

### WU-308 · Chat sidebar — `ready`
Deps: 305, 007.
`chat_sessions/messages` migrations; desktop sidebar + mobile full-screen drawer; scope selector (project default; team/org for permitted); streaming via SSE (`chat-delta`); agent picker (@agent in chat); action cards ("Created BC-142" linked); propose→approve inline for high-impact (diff/preview via dry-run, apply on confirm); history per user/scope; slash commands `/assign /label /decompose` expanding to prompts.
AC: streaming endpoint test (delta framing); card render from run steps; propose-approve flow test (dry-run then real dispatch); scope permission test.

### WU-309 · Scheduled triggers — `ready`
Deps: 305, 209.
`scheduled_triggers` migration; per-project UI (cron, agent, prompt); scheduler enqueues runs; overlap guard (skip if previous still running); pause/resume.
AC: schedule fire test with fake clock; overlap skip test; timezone handling (cron evaluated in project owner org's configured tz — default UTC, documented).

### WU-310 · Cost controls + usage — `ready`
Deps: 305.
Token/cost aggregation from run_steps (pricing table per provider model, editable by platform admin); org monthly spend vs cap: threshold alert notification, hard stop blocks new runs (clear error to trigger); per-agent runs/hour + token budget enforced at claim; org usage dashboard (by agent/project/timeframe).
AC: cap threshold + hard stop tests; rate limit claim test; dashboard aggregation golden.

### WU-311 · Phase 3 hardening — `ready`
Deps: all 3xx.
Prompt-injection defences documented + tested: task/comment content wrapped in clearly delimited data blocks in context, system prompt instructs against instruction-following from data; tool-arg validation fuzz; run transcript redaction of provider keys; kill-switch (org owner can disable all agents instantly).
AC: injection canary test (malicious comment attempts `member.invite`; assert gate/deny path); kill-switch test; fuzz corpora committed.

---

## Phase 4 — API Surface (branch `build/phase-4`)

### WU-401 · REST API core — `ready`
Deps: 109, 006.
`/api/v1/actions/{name}` uniform RPC from registry; bearer auth; problem+json errors with stable codes; `Idempotency-Key`; per-key token-bucket rate limit + headers.
AC: RPC dispatch tests (auth, scope, unknown action, validation error shape); idempotent replay; 429 with headers.

### WU-402 · Resource routes + OpenAPI — `ready`
Deps: 401.
Resource-style GET aliases (projects, tasks incl. by `KEY-n`, comments, sprints, labels, search) with cursor pagination + ETag/If-Match on task update; OpenAPI 3.1 generated from registry (+aliases), served + embedded docs viewer.
AC: pagination round-trip; stale If-Match → 412; OpenAPI validates against schema; docs page renders.

### WU-403 · MCP server — `ready`
Deps: 401.
Streamable HTTP `/mcp` per SPEC §12 (record SDK-vs-in-repo decision here); tools filtered per key (omission not denial); resources (`bc://…`) incl. assembled context; prompts (`decompose_task`, `summarise_sprint`, `triage_backlog`); approval_pending result for gated calls.
AC: MCP client-sim tests: initialize, tools/list scoped, tool call happy + approval_pending, resources read, prompts get; unauthorized tool absent from list.

### WU-404 · Outbound webhooks — `ready`
Deps: 007, 104.
Webhook CRUD (org/team) with event filter; HMAC-SHA256 signature header; delivery worker (queue) with backoff retries + dead-letter status + redelivery button; SSRF guard (resolve-then-connect pinning); delivery log UI.
AC: signature verification golden; retry/DLQ tests; SSRF pinning test (DNS rebind simulation); filter test.

### WU-405 · GitHub links + inbound webhooks — `ready`
Deps: 201, 102.
`project_github` config (repo, transitions map, webhook secret); inbound `/hooks/github` (signature verify); `KEY-n` extraction from branch/commit/PR body → `github_links`; PR opened/merged → configured transitions via dispatch (actor: github integration service actor); task page shows linked PRs/commits with state.
AC: signature reject test; extraction table tests (branch, commit msg, body, multiple keys); merge→transition dispatch test; link render.

### WU-406 · User GitHub connection — `ready`
Deps: 102, 108.
Settings: connect GitHub (reuse SSO identity token if present, else PAT entry, encrypted); token used by wiki edits (Phase 5) and shown-as-connected state; disconnect.
AC: PAT store/retrieve round-trip encrypted; disconnect wipes token.

### WU-407 · Phase 4 hardening — `ready`
Deps: all 4xx.
API fuzz (action inputs from schemas); rate-limit soak; OpenAPI↔registry drift test (CI compares); MCP conformance re-run; audit coverage check (all ImpactHigh via API audited).
AC: drift test in `make check`; fuzz corpora committed.

---

## Phase 5 — Wiki, Reporting, Storage (branch `build/phase-5`)

### WU-501 · Wiki read + render — `ready`
Deps: 104.
`wiki_configs` (org owner sets repo; team admin sets ref/path — enforced by distinct permissions); go-git shallow checkout cache + refresh policy; page tree nav; goldmark render with mermaid client-side + sanitised SVG; relative link/image resolution confined to path; `KEY-n` autolinks to tasks.
AC: checkout/refresh tests against local fixture repo; traversal attempt blocked; render goldens (md, mermaid block, svg sanitised); autolink test.

### WU-502 · Wiki edit + history — `ready`
Deps: 501, 406.
UI editor with live preview; commit as the user's linked GitHub token (WU-406); users without a linked token get read-only wiki + "connect GitHub in settings" prompt (Q2); commit message editable; non-FF retry-once then conflict UI; history view (log per file) + read-only revision render; create/rename/delete page.
AC: commit-as-user test (fixture remote); unlinked user sees read-only + prompt, edit endpoint rejects; conflict path test; history render.

### WU-503 · Wiki search + task↔wiki links — `ready`
Deps: 501, 208.
Indexer walks checkout on refresh into FTS; wiki results in global search + palette; task descriptions/comments autolink `[[wiki page]]` syntax; wiki pages list tasks referencing them.
AC: index-on-refresh test; permission scoping (project visibility) test; backlink query test.

### WU-504 · Sprint & flow reports — `ready`
Deps: 206.
Burndown/burnup per sprint (daily snapshots via scheduler job); cycle/lead time from activity history; project distributions; charts server-rendered SVG (no JS dep); CSV export of reports + filtered task lists.
AC: snapshot job idempotent; metric computation goldens from fixture history; CSV goldens; SVG renders (parse test).

### WU-505 · Agent usage dashboard — `ready`
Deps: 310.
Org dashboard: runs/tokens/cost/actions by agent, project, timeframe; drill-down to run list; CSV export.
AC: aggregation goldens; permission test (org owner only by default).

### WU-506 · S3 attachment backend — `ready`
Deps: 207.
S3 store impl (AWS SDK v2, custom endpoint, path-style option); org settings UI for backend config (encrypted); migration helper `bc storage migrate` local→S3; served via streamed proxy (same headers as local).
AC: tests against minio-compatible fake or SDK middleware stub; config round-trip; migrate helper moves + verifies checksums.

### WU-507 · Backup + ops polish — `ready`
Deps: 003.
`bc backup` (`VACUUM INTO` to timestamped file, prunes to N); `/readyz` covers DB + queue health; docs: RESTORE.md, DEPLOY.md (compose example, volume layout, env reference generated from config struct).
AC: backup/restore round-trip test; readyz degradation test; env reference generation test.

### WU-508 · Release readiness — `ready`
Deps: all.
Full pass: `make check` on clean clone; container smoke (compose up, bootstrap, create org→project→task via UI path exercised by chromedp if available else scripted curl); tag `0.1.0-rc.1` dry-run pipeline; CHANGELOG.md.
AC: smoke script committed + green. Manual: rc pipeline run recorded here.
