# Boardchestrator — Build Backlog

Loop ledger. One work unit (WU) per iteration. Statuses: `ready` | `in-progress` | `done <date> <commit-subject>` | `blocked(<reason or QUESTIONS ref>)`.

Rules: pick the **first `ready` WU whose deps are all `done`**, top to bottom. Update this file in the same commit as the work. Never reorder or renumber; append notes under the WU if needed. Acceptance criteria (AC) require automated tests unless marked `Manual:`.

**Branching: each WU gets a distinct branch `wu-<N>` from `main`.** Push to origin, PR on GitHub, squash-merge via PR. See `PROCESS-WORKFLOW.md`.

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

### WU-008 · Dockerfile + CI — `done 2026-07-22 WU-008: Dockerfile + CI`
Deps: 001.
Multi-stage Dockerfile (distroless nonroot, /data volume); workflows: `lint.yml` (PR→main: golangci-lint, gofmt, templ gen check), `test.yml` (push→main: `go test -race ./...`), `release.yml` (tag `*-rc.*` matching `^\d+\.\d+\.\d+-rc\.\d+$`: build image, no push; tag `^\d+\.\d+\.\d+$`: buildx, push ghcr `X.Y.Z` + `latest`).
AC: `docker build` succeeds locally; workflows lint clean (actionlint if available); tag-pattern filtering covered by workflow-level `if` conditions reviewed against both tag shapes. Manual: build run recorded in note below.

### WU-009 · Landing page — `done 2026-07-20 WU-009: landing page`
Deps: 004.
Static landing at `/` for unauthenticated users: hero, feature sections (board, agents, wiki, MCP), animated flair honouring reduced-motion, screenshots placeholder slots, links to login + GitHub repo; OpenGraph/Twitter meta, favicon set.
AC: handler test (unauthenticated `/` → landing; authenticated → app shell redirect); HTML validates (no unclosed tags via parser test); reduced-motion media query present. Manual: visual pass at 375/1280px.

### WU-010 · PWA — `done 2026-07-21 WU-010: PWA (manifest, service worker, offline)`
Deps: 004, 009.
Manifest + icons; `sw.js` caching app shell + static (cache-first static, network-first documents, never API/SSE); offline fallback page with reconnect notice.
AC: manifest served with correct MIME + linked from layout; sw excludes `/api`, `/events`, `/mcp` (unit test on route matcher logic extracted to testable JS-free Go route list or documented manual check). Manual: Lighthouse installable check.

---

## Phase 1 — Identity & Tenancy (branch `build/phase-1`)

### WU-101 · Google OIDC login — `done 2026-07-24 WU-101: Google OIDC login`
Deps: 005.
Discovery-based OIDC with PKCE, state, nonce; `/auth/google` + callback; user create/link by verified email; session issued + rotated; login rate limit.
AC: httptest fake IdP covers happy path, bad state, bad nonce, unverified email; session cookie attributes asserted.

### WU-102 · GitHub OAuth login — `done 2026-07-24 WU-102: GitHub OAuth login`
Deps: 101.
GitHub flow with state; email fetch (primary verified); identity link to existing user by email; stores token_enc for later GitHub features.
AC: fake GitHub server tests: new user, link-to-existing, missing verified email → friendly error.

### WU-103 · Bootstrap gating — `done 2026-07-24 WU-103: Bootstrap gating`
Deps: 101.
Per SPEC §7: `BC_ADMIN_EMAILS` / `BC_BOOTSTRAP_TOKEN` gate; token logged while unclaimed; pre-bootstrap non-admin logins rejected with page; `bootstrap_done` flip is atomic.
AC: tests for all three paths (email match, token, rejected); concurrent first-login race yields exactly one admin (tx test).

### WU-104 · Orgs, teams, projects — `done 2026-07-26 WU-104: orgs teams projects`
Deps: 006, 103.
Migrations `orgs, org_secrets, teams, projects, roles, memberships`; actions `org.create/update`, `team.create/update`, `project.create/update/archive` (project KEY validation `^[A-Z][A-Z0-9]{1,9}$`, next_task_num=1); context fields editable; encrypted org_secrets helpers; sqlc queries all org-scoped (check-scope now enforcing for these tables).
AC: action tests incl. duplicate slug/key rejection; secrets round-trip encrypt/decrypt; check-scope covers new tables.

### WU-105 · Permission engine + roles — `done 2026-07-26 WU-105: permission engine + role/membership actions + deny-by-default wiring`
Deps: 104.
`internal/perm` per SPEC §6; seed system roles (Org Owner, Team Admin, Member, Viewer, Guest) as migration data; actions `role.create/update/assign`; copy-on-edit for system roles; dispatch perm hook wired to engine (replacing stub).
AC: resolution tests: org-level grant applies to child project; additive union; wildcard `task.*`; agent role∩skills intersection (skills stubbed as fixture); deny-by-default; copy-on-edit leaves system role untouched.

### WU-106 · Memberships & invites — `done`
Deps: 105.
Actions `member.invite/remove`, `invite.accept`; invite email-less flow v1: generate link (shown to inviter to share; no SMTP), token hashed, expiry; accept binds after SSO; membership CRUD UI (org/team/project people pages).
AC: invite lifecycle tests (create, accept, expired, reuse rejected); remove revokes access (perm test).

### WU-107 · Tenancy UI — `done`
Deps: 104, 105, 106.
templ pages: org switcher, org/team/project settings (name, context markdown with preview, visibility), roles editor (grant matrix), people pages; breadcrumbs; responsive.
AC: handler tests for each page incl. permission-denied renders; context save round-trips. Manual: mobile pass.

### WU-108 · User settings — `done 2026-08-04 wu-108: user settings — theme/timezone/sessions`
Deps: 105.
Pages: theme (persisted, instant apply), timezone (browser-default detect), sessions list + revoke, notification prefs skeleton (table + toggles; engine lands in WU-211).
AC: theme/timezone persistence tests; revoked session rejected on next request.

### WU-109 · API keys — `done 2026-08-05 WU-109: API keys — migration, sqlc, actions, Bearer auth, settings UI, tests`
Deps: 105.
`apikey.create/revoke` actions; settings UI (show-once secret); bearer auth middleware resolving key → actor(apikey, owner) with scope intersection; last_used tracking.
AC: create/parse/verify tests; revoked + wrong-secret rejected; scope narrowing enforced in a dispatch test (key without `task.create` cannot despite owner grant).

### WU-110 · Audit log — `done 2026-08-05 WU-110: audit log — actions, org page, CSV export, filtered queries`
Deps: 104, 106.
Audit writer wired to dispatch hook (ImpactHigh + all agent actions + logins/key events); org audit page (filter by actor/action/date) + CSV export; platform audit for platform admin.
AC: audited actions produce rows with actor/ip; non-privileged user cannot view (perm test); CSV golden test.

### WU-111 · Data export & deletion — `done 2026-08-05 WU-111: data export & deletion — actions, sqlc, tests`
Deps: 108, 110.
Per-user JSON export (profile, memberships, authored comments/tasks refs); account deletion: PII scrubbed, identities/sessions/keys removed, authored content re-attributed to "Former member"; org export (platform admin): full org JSON.
AC: export golden structure test; post-deletion login impossible, content anonymised, FK integrity holds.

---

## Phase 2 — Boards & Tasks (branch `build/phase-2`)

### WU-201 · Task model + CRUD actions — `done 2026-07-28 WU-201: task CRUD + labels + comments + custom fields + activity`
Deps: 105.
Migrations: tasks, task_assignees/watchers, labels, task_labels, task_relations, comments, task_activity, custom_field_defs/values; actions `task.create/update/assign/label/relate/archive`, `label.create/update`; per-project numbering (tx-safe `next_task_num`); activity rows on every change; `KEY-n` reference parser package.
AC: numbering race test (parallel creates → unique nums); every mutation writes activity with actor; relation cycle allowed except self-reference; custom field validation per kind.

### WU-202 · Task detail page — `done 2026-07-28 WU-202: task detail page (templ + routes + stub handler)`
Deps: 201, 007.
Full task view: markdown description (edit-in-place), fields sidebar (assignees, labels, points, priority, due, sprint slot), relations, watchers, activity timeline, comments thread (markdown + preview, edit/delete); @mention autocomplete (users; agents come in WU-306); dates in viewer timezone; responsive sheet layout on mobile.
AC: handler tests: render, edit description, comment CRUD, mention persists metadata; XSS test (script in markdown neutralised).

### WU-203 · Board columns config + board view — `done 2026-07-29 WU-203: board columns CRUD + board view + column settings UI`
Deps: 201.
`board_columns` migration + defaults on project create (Backlog/To Do/In Progress/Review/Done); column settings UI (add/rename/recolour/reorder/WIP/state mapping/move-roles); board view rendering columns + cards (title, key, assignee avatars, labels, points), WIP indicator; swimlanes by assignee/label/custom field.
AC: default columns seeded; board render test with swimlanes; WIP breach shows indicator (render test).

### WU-204 · Drag-and-drop + move — `done 2026-07-29 WU-204: drag-and-drop + task.move action + SortableJS wiring`
Deps: 203, 007.
SortableJS wiring (pointer + long-press touch); `task.move` action (column/state + position REAL midpoint, periodic rebalance); HTMX reorder endpoint; card "Move to…" menu (keyboard/touch path, full keyboard grab-move-drop); column move-roles enforced; SSE `task-updated` refreshes other viewers' boards.
AC: move action tests (position ordering, forbidden column for role, state sync); rebalance test; SSE event emitted on move.

### WU-205 · Backlog view + saved filters + bulk ops — `done 2026-07-29 WU-205: backlog view, saved_filters CRUD, bulk assign/label/move`
Deps: 201, 203.
Backlog: ordered list with inline edit + drag-rank; filter bar (assignee, label, sprint, state, text) → `saved_filters` (share to team, pin as board tab); multi-select with bulk assign/label/move/sprint.
AC: filter query builder tests (each dimension + combinations); bulk op is one action dispatch per semantic op with n subjects (activity per task); pinned filter renders as tab.

### WU-206 · Sprints — `done 2026-07-30 WU-206: sprint CRUD actions + templ list view + ListTasksBySprint query + route wiring`
Deps: 205.
Sprint CRUD actions; assign tasks in/out (from backlog + task page); active-sprint board filter; close sprint → prompt to move open tasks (to backlog/next sprint).
AC: sprint lifecycle tests; close-with-open-tasks flow moves correctly; board filter shows only sprint tasks.

### WU-207 · Attachments (local) — `done 2026-07-31 wu-207: attachment storage, actions, routes, UI, tests`
Deps: 202, 009.
Storage interface + local backend per SPEC §9; upload (drag-drop + picker) with org size/type limits; image re-encode; SVG sanitise; inline image preview lightbox; document list with download (attachment disposition, nosniff); `attachment.upload/delete` actions.
AC: limit enforcement tests; SVG with script sanitised (golden); served headers asserted; delete removes blob + row.

### WU-208 · Search (FTS5) — `done 2026-08-03 wu-208: FTS5 search — migration, indexer, action, routes, UI, tests`
Deps: 201, 007.
FTS migration; indexer subscribed to task/comment events (wiki joins in WU-503); `search.query` action with permission-filtered results; search page + command palette (`ctrl/cmd-k`: tasks, actions).
AC: index-on-event tests; visibility filter test (private project hidden from non-member); palette endpoint returns mixed ranked results.

### WU-209 · Task templates + recurring — `done 2026-08-03 WU-209: task templates + recurring rules — migration, sqlc queries, action handlers, scheduler, tests`
Deps: 201.
Template CRUD (capture fields/labels/points/checklist-as-description); create-from-template; recurring rules (cron via robfig/cron parser, scheduler job in queue table) spawning from template.
AC: template round-trip; cron next_at computation tests; scheduler idempotence (no double-spawn on restart).

### WU-210 · Archive — `done 2026-08-03 WU-210: archive — task archive/unarchive round-trip test`
Deps: 201, 205.
Archive task (hidden from board/backlog, searchable, restorable); archive project (read-only banner, hidden from switchers, restorable by org owner).
AC: archived exclusion + restore tests; archived project rejects mutations (dispatch test).

### WU-211 · Notifications — `done 2026-08-03 WU-211: notifications — migration, sqlc queries, action handlers (mark_read/mark_all_read/list/unread_count), notify engine stub`
Deps: 007, 202.
Engine subscribed to events: assigned, @mentioned, watched-task state change, (agent kinds reserved); per-user prefs honoured; grouping (n changes on task X within window); notification centre UI (badge via SSE, list, mark read/all-read).
AC: each trigger → row for right users only (self-action excluded); pref off suppresses; grouping window test; markread action test.

### WU-212 · Realtime board/task polish — `done 2026-08-03 wu-212: SSE-driven partial refresh with reconnect/backoff`
Deps: 204, 211.
SSE-driven partial refresh: board cards, task detail (comment appears live), notification badge; `aria-live` regions; reconnect with backoff + missed-event refetch.
AC: event→partial mapping tests; reconnect logic unit test. Manual: two-browser live check.

### WU-213 · Responsive board (mobile focus mode) — `done 2026-08-04 wu-213 mobile focus mode, card tap navigation, long-press drag`
Deps: 204.
Single-column focus with horizontal swipe between columns, sticky column header + count; card tap → task sheet; long-press drag; bottom nav wired (Boards/Backlog/Chat placeholder/Search/Notifications).
AC: render tests for mobile shell variants. Manual: 375px walkthrough of move-via-menu and swipe.

### WU-214 · Accessibility pass — `done 2026-08-05 WU-214: accessibility pass — keyboard shortcuts help, focus trap, grab-move-drop, aria-expanded, dark contrast fix`
Deps: 202, 204, 205, 211.
Keyboard operability audit + fixes (board grab/move/drop shortcuts documented in a help dialog); ARIA roles on columns/cards/dialogs; focus management (open/close returns focus); visible focus rings; contrast fixes both themes; reduced-motion honoured everywhere.
AC: automated: templ renders carry expected roles/labels (tests); axe-core check via chromedp if available, else Manual: documented keyboard walkthrough of board, task, palette.

### WU-215 · Phase 2 hardening — `done 2026-08-07 wu-215: phase 2 hardening — error pages, fuzz corpus, race soak, check-scope exemption, N+1 query budget`
Deps: all 2xx.
Fuzz markdown/mention/KEY-ref parsers; race-detector soak on board mutations; N+1 query audit on board/backlog renders (query-count assertions); error-page polish (403/404/500 templ pages).
AC: fuzz corpora committed; query-count tests for board render ≤ fixed budget; error pages tested.

---

## Phase 3 — Agent Harness (branch `build/phase-3`)

### WU-301 · Job queue — `done 2026-07-24 WU-301: Job queue`
Deps: 006.
`jobs` migration; claim/backoff/max-attempts per SPEC §10; worker pool with graceful drain; dead-job status + requeue action; queue depth/age metrics.
AC: claim contention test (n workers, no double-claim); backoff schedule test; drain-on-shutdown test.

### WU-302 · Providers (OpenAI-compatible) — `done 2026-08-07 wu-302: providers + provider_orgs migration, sqlc queries, check-scope gate; merge dff7867`
Deps: 104.
`providers` + `provider_orgs` migrations; platform-admin UI (create provider: base URL, key, models; allocate to orgs); provider client with streaming, retry/jitter, usage capture; `codex_sso` kind registered but returns "not yet supported" (QUESTIONS Q1).
AC: client tests against httptest fake (stream parse, 429 retry, usage extraction); allocation visibility test (org sees only allocated).
Notes: merged `ready`→`done` post-hoc (BACKLOG lagged the merge). Pre-existing lint debt in this WU (client.go errcheck/G404/S1000, providers.go unused type, web/providers errcheck) was fixed in `cc84e99 Repair WU-303 merge + unblock make check` to get the CI gate green.

### WU-303 · Agents + templates — `done 2026-08-08 WU-303 agents + templates: merge; repair cc84e99`
Deps: 302, 105.
`agents` migration; platform template CRUD + allocation; org agent CRUD (customise allocated: name, context, skills, role, retry, rate, budget, approval policy); unique @name per org; membership rows for agents (actor_type=agent).
AC: template→org customisation copy semantics tests; name uniqueness; agent-as-member permission resolution test.
Notes: **merge was broken — repaired in cc84e99.** Three defects fixed post-merge: (1) generated sqlc/templ outputs (agents.sql.go, agents_templ.go, models.go structs) were never committed → `main` failed to build on clean checkout; (2) agents.sql broke the check-scope gate — DeleteAgent/UpdateAgent/CreateAgentSkill/DeleteAgentSkill/ListAgentSkills were not org-scoped (cross-org tampering by known ID); scoped them via agents.org_id, cross-org update/delete now silent no-ops, skill ops via EXISTS/JOIN, added `agent.list-skills` action; (3) migration 0019's agent_skills FK referenced a non-existent `skills` table (dangling until WU-304) — created the minimal `skills` table per SPEC §10 in 0019. Also fixed agents_test registry bug (relied on init() instead of reset()+re-register) and added cross-org rejection tests (delete/update/skill).

### WU-304 · Skills hub — `done 2026-08-08 wu-304: skills hub`
Deps: 303.
`skills`, `agent_skills` migrations; skill CRUD UI (instructions editor, allowed-actions picker from registry, param schema, optional external MCP endpoints with encrypted creds + SSRF-validated URLs); versioning (edit bumps version, agents pin latest by default); import/export JSON bundle; platform vs org scoping.
AC: allowed-actions must be subset of registry (validation test); import round-trip golden; effective-permission intersection test with WU-105 engine; SSRF validator rejects private ranges.
Notes: skills/agent_skills tables already created in migration 0019 (during cc84e99 repair); no new migration needed. Implemented org-scoped skill CRUD actions, version-bump update, latest-by-name resolution, import/export, SSRF + encryption, and the perm-engine AllowAgent intersection (role grants ∩ attached skills' allowed_actions).

### WU-305 · Run engine + tool loop — `done 2026-08-09 WU-305: agent run engine (internal/agentrt)`
Deps: 301, 303, 006.
`runs`, `run_steps` migrations; lifecycle per SPEC §10; context assembly (labelled cascade); tool loop with registry-derived tools filtered by effective perms; step cap; cancellation; transcripts stored; failure→retry per agent policy→notify; run detail UI (steps, tokens) linked from task.
AC: fake-provider integration tests: happy multi-tool run, permission-denied tool call recorded + surfaced to model, step cap halt, cancel mid-run, retry-then-fail notifies; context assembly golden test (ordering + labels).
Notes: run engine in `internal/agentrt`; provider client built per-run from agent's provider row + key decrypted via tenant secret; run-detail route `/app/org/{orgID}/project/{projectID}/task/{taskID}/run/{runID}` (task-detail DB handler still stubbed — link lands with WU-202's real handler).

### WU-306 · Approval gates — `done 2026-08-10 WU-306: approval gates — gate, decide action, resume path, notifications, run-detail UI`
Deps: 305.
`approvals` migration; dispatch approval hook implemented (policy per impact class from agent config); run state `awaiting_approval`; approval UI on task + notification (kind: approval requested); `approval.decide` resumes run with result; forbid class blocks with clear model-visible error; high-impact default require-approval on new agents.
AC: gate matrix tests (auto/require/forbid × read/low/high); resume-after-approve continues run correctly (fake provider); reject surfaces to model and run completes gracefully.

### WU-307 · @mention + column triggers — `done 2026-08-10 WU-307: @mention + column triggers — comment actions, EnqueueRun, triggerLoop, agent thread UI`
Deps: 305, 204.
Mention parser recognises active org agents in saved description/comments → enqueue run (trigger=mention, task context, the mentioning text as instruction); column `trigger_agent_id/prompt` settings UI; `task.move` into trigger column enqueues (trigger=column, prompt template with task interpolation); agent thread rendering on task (distinct styling, collapsible steps); loop guard: an agent's own actions never trigger mentions/column runs of itself; per-task concurrent-run cap 1 (queue serialises).
AC: mention→run created (not for inactive/unknown names, not self-trigger); column trigger fires once per entry; template interpolation golden; agent thread renders transcript.

### WU-308 · Chat sidebar — `done 2026-08-11 WU-308: chat sidebar — sessions, messages, streaming, propose-approve`
Deps: 305, 007.
`chat_sessions/messages` migrations; desktop sidebar + mobile full-screen drawer; scope selector (project default; team/org for permitted); streaming via SSE (`chat-delta`); agent picker (@agent in chat); action cards ("Created BC-142" linked); propose→approve inline for high-impact (diff/preview via dry-run, apply on confirm); history per user/scope; slash commands `/assign /label /decompose` expanding to prompts.
AC: streaming endpoint test (delta framing); card render from run steps; propose-approve flow test (dry-run then real dispatch); scope permission test.
Notes: chat deltas targeted per-user via `Hub.SendToUser`; `chat.send` enqueues the run via a `chat.sent` event + server `chatLoop` (actions have no JobStore); engine branches on `run.ChatSessionID` into a streaming `chatStreamLoop`; propose/approve re-dispatch the card's inner action via `/api/action/{name}` with `X-Dry-Run`/`X-Org-Id`/`X-Project-Id` headers.

### WU-309 · Scheduled triggers — `done 2026-08-11 WU-309: scheduled triggers — migration, actions, UI, scheduler + overlap guard`
Deps: 305, 209.
`scheduled_triggers` migration (0024); per-project UI (`/app/org/{orgID}/project/{projectID}/triggers`: cron, agent, prompt + pause/resume/delete); scheduler enqueues runs (trigger='schedule', prompt as instruction); overlap guard (skip if previous still running — per-project cap via new runs.project_id, migration 0025); pause/resume.
AC: schedule fire test with fake clock; overlap skip test; timezone handling (cron evaluated in UTC — org-tz documented as future refinement, orgs have no tz column yet).
Notes: added `project_id` to runs (migration 0025) + `CountActiveRunsByProject` for the overlap guard; `EnqueueRun` gained a projectID arg threaded through mention/column/chat callers; scheduler is a ticker goroutine (`schedulerLoop`/`fireDueTriggers`) stopped on Shutdown; `SchedPollInterval` config (BC_SCHED_POLL_INTERVAL, default 60s); next_at compared in RFC3339 to match `schedule.NextAt`.

### WU-310 · Cost controls + usage — `done 2026-08-11 WU-310: cost controls + usage — model pricing, org cap + threshold alert, per-agent limits, usage dashboard`
Deps: 305.
Token/cost aggregation from run_steps (pricing table per provider model, editable by platform admin); org monthly spend vs cap: threshold alert notification, hard stop blocks new runs (clear error to trigger); per-agent runs/hour + token budget enforced at claim; org usage dashboard (by agent/project/timeframe).
AC: cap threshold + hard stop tests; rate limit claim test; dashboard aggregation golden.
Notes: `model_pricing` (0026) is platform-global (no org_id) — exempted from check-scope tenant list; orgs gained `monthly_cap_usd` + `cap_alert_pct`; per-agent `runs_per_hour`/`token_budget` enforced in `EnqueueRun`; threshold alert fires once per org (in-memory `capAlerted` map) and records an `org_cap_alerts` row + publishes `org.cap.threshold`; `pricing.*`/`org.cap.set`/`usage.read` actions + `/app/org/{orgID}/usage` dashboard (by agent/project).

### WU-311 · Phase 3 hardening — `done 2026-08-11 WU-311: hardening — kill-switch, transcript redaction, injection canary + fuzz tests`
Deps: all 3xx.
Prompt-injection defences documented + tested: task/comment content wrapped in clearly delimited data blocks in context, system prompt instructs against instruction-following from data; tool-arg validation fuzz; run transcript redaction of provider keys; kill-switch (org owner can disable all agents instantly).
AC: injection canary test (malicious comment attempts `member.invite`; assert gate/deny path); kill-switch test; fuzz corpora committed.
Notes: `agent.kill-all` (ScopeOrg, perm `agent.kill`) deactivates every org agent via `DeactivateAllAgentsByOrg`; org creation now seeds a system `Owner` role (org.* + agent.* + agent.kill) and auto-memberships the creator as owner. Transcript redaction masks the live decrypted provider key out of run_steps request/response JSON (`redactSecrets`). Injection canary asserts task/comment content stays inside `[task]...[/task]` DATA blocks + systemPrompt injection guard; fuzz corpus validates malformed tool args rejected by schema.

---

## Phase 4 — API Surface (branch `build/phase-4`)

### WU-401 · REST API core — `done 2026-08-11 WU-401: REST API core — RPC, bearer auth, problem+json, idempotency, rate limit`
Deps: 109, 006.
`/api/v1/actions/{name}` uniform RPC from registry; bearer auth; problem+json errors with stable codes; `Idempotency-Key`; per-key token-bucket rate limit + headers.
AC: RPC dispatch tests (auth, scope, unknown action, validation error shape); idempotent replay; 429 with headers.
Notes: `handleRPCv1` in `internal/web/rpc_v1.go` reads the actor from `auth.APIKeyActorFrom` (bearer middleware already in the server chain), maps dispatch sentinels to RFC 7807 problem+json with stable codes (`unauthorized`, `unknown_action`, `invalid_input`, `scope_error`, `forbidden`, `approval_pending`, `internal`, `rate_limited`), honors `Idempotency-Key` + `X-Org-Id`/`X-Project-Id`/`X-Team-Id` scope headers, and applies an in-memory per-key token bucket (burst 60 / 1 per sec, tunable via `SetRateLimit`) with `X-RateLimit-Limit`/`X-RateLimit-Remaining`/`Retry-After` headers.

### WU-402 · Resource routes + OpenAPI — `done 2026-08-11 WU-402: resource routes + OpenAPI`
Deps: 401.
Resource-style GET aliases (projects, tasks incl. by `KEY-n`, comments, sprints, labels, search) with cursor pagination + ETag/If-Match on task update; OpenAPI 3.1 generated from registry (+aliases), served + embedded docs viewer.
AC: pagination round-trip; stale If-Match → 412; OpenAPI validates against schema; docs page renders.
Notes: `internal/web/resources_v1.go` adds `/api/v1` GET aliases (projects, task-by-`KEY-n`, comments, sprints, labels, search) + PUT task update under bearer auth; cursor pagination uses a base64 **offset** cursor (name-ordered slice, round-trip safe); task GET/UPDATE guarded by strong ETag (`etagFor(id,updated_at)`), stale `If-Match` → 412 problem+json `conflict`; `internal/web/openapi_v1.go` serves a hand-built OpenAPI 3.1 doc at `/api/v1/openapi.json` (paths for RPC + resources, BearerAuth security scheme, Problem schema) + embedded docs viewer page at `/app/docs`.

### WU-403 · MCP server — `done 2026-08-11 WU-403: MCP server`
Deps: 401.
Streamable HTTP `/mcp` per SPEC §12 (record SDK-vs-in-repo decision here); tools filtered per key (omission not denial); resources (`bc://…`) incl. assembled context; prompts (`decompose_task`, `summarise_sprint`, `triage_backlog`); approval_pending result for gated calls.
AC: MCP client-sim tests: initialize, tools/list scoped, tool call happy + approval_pending, resources read, prompts get; unauthorized tool absent from list.
Notes: **decision — in-repo minimal JSON-RPC** (no `modelcontextprotocol/go-sdk`): the surface we need (initialize, tools/list, tools/call, resources/list+read, prompts/list+get) is small and the repo owns auth + dispatch seams; the SDK adds a heavy dep for little gain. `internal/mcp/server.go` implements Streamable HTTP (non-streaming, single JSON-RPC response) at `/mcp` behind API-key auth; per-key tool filtering reads the key's `scope_json` permission list (omission not denial — absent from tools/list, and a call to a non-granted tool errors); `tools/call` dispatches via the action dispatcher (dots→underscores names); **high-impact calls by a key return `{"status":"approval_pending","approval_id":…}` without executing** (no run exists for a key, so the approval is not persisted — run-bound persistence is a follow-up); resources `bc://project/{key}` + `bc://task/{key}-{n}` resolved from the DB (wiki + assembled-context land with the wiki package WU-501); prompts `decompose_task`/`summarise_sprint`/`triage_backlog`. Mounted at `/mcp` in web.go behind APIKeyAuthMiddleware.

### WU-404 · Outbound webhooks — `done 2026-08-11`
Deps: 007, 104.
Webhook CRUD (org/team) with event filter; HMAC-SHA256 signature header; delivery worker (queue) with backoff retries + dead-letter status + redelivery button; SSRF guard (resolve-then-connect pinning); delivery log UI.
AC: signature verification golden; retry/DLQ tests; SSRF pinning test (DNS rebind simulation); filter test.
Notes: `migrations/0027_webhooks` + `webhooks`/`webhook_deliveries` tables; `internal/webhook` package (subscribes to event bus, matches org webhooks by event filter, POSTs signed JSON envelope, retries with fixed 30s backoff + dead-letter on exhaustion via the JobStore); SSRF guard = resolve-then-connect — hostname is resolved and non-public (loopback/private/link-local) addresses rejected; HMAC-SHA256 signature in `X-Boardchestrator-Signature: sha256=<hex>`; management actions `webhook.create/update/delete/list` (org-scoped); delivery worker wired into server pool handler (routes `webhook.deliver` job kind to the Deliverer; other kinds fall through to the agent engine). AC tests: signature golden, retry+DLQ, DNS-rebind SSRF pinning, event-filter, CRUD round-trip.

### WU-405 · GitHub links + inbound webhooks — `done 2026-08-12`
Deps: 201, 102.
`project_github` config (repo, transitions map, webhook secret); inbound `/hooks/github` (signature verify); `KEY-n` extraction from branch/commit/PR body → `github_links`; PR opened/merged → configured transitions via dispatch (actor: github integration service actor); task page shows linked PRs/commits with state.
AC: signature reject test; extraction table tests (branch, commit msg, body, multiple keys); merge→transition dispatch test; link render.
Notes: `migrations/0028_github` + `project_github`/`github_links` tables; `internal/github` package — `Receiver.Handle` verifies `X-Hub-Signature-256` (HMAC-SHA256 with per-repo webhook_secret) before parsing, extracts `KEY-n` refs from branch/commit/PR bodies via regex, upserts `github_links` (unique on project+kind+key+key_num+ref) resolving each to a task by (project_id, key, key_num), and on PR opened/merged dispatches `task.move` to the configured transition status via the dispatcher under a new `service` actor type (`ActorService`, trusted in the perm checker). Route mounted at `/hooks/github` without API-key auth (GitHub signs payloads). Config actions `github.config.upsert/delete` (project-scoped). AC tests: signature reject (wrong secret 401, missing 401, unknown repo 404), extraction table, merge→transition dispatch, link-list render data.

### WU-406 · User GitHub connection — `done 2026-08-12`
Deps: 102, 108.
Settings: connect GitHub (reuse SSO identity token if present, else PAT entry, encrypted); token used by wiki edits (Phase 5) and shown-as-connected state; disconnect.
Notes: `migrations/0029_github_connections` — `github_connections` (user_id PK, provider oauth|pat, token_enc AES-GCM, login, created/updated). GitHub OAuth callback now captures the access token and stores it encrypted on the user's github identity (`identities.token_enc` via `SetIdentityToken`; OAuthHandler gained SecretKey from `tenant.PadKey(BC_SECRET_KEY)`). Actions `github.connect` (source oauth reuses identity token via `FindIdentityByUserAndProvider`; source pat encrypts with `ac.SecretKey`), `github.disconnect` (wipes row), `github.status` (connected/provider/login, never token). `internal/github.TokenForUser` decrypts the connection token for Phase-5 wiki commits. AC tests: PAT store/retrieve encrypted round-trip, disconnect wipes, status connected, oauth reuse, TokenForUser not-connected + round-trip.
AC: PAT store/retrieve round-trip encrypted; disconnect wipes token.

### WU-407 · Phase 4 hardening — `done 2026-08-12`
Deps: all 4xx.
API fuzz (action inputs from schemas); rate-limit soak; OpenAPI↔registry drift test (CI compares); MCP conformance re-run; audit coverage check (all ImpactHigh via API audited).
AC: drift test in `make check`; fuzz corpora committed.
Notes: `internal/web/drift_test.go` walks the chi router via `chi.Walk` and checks every `/api/action/*` route resolves to a registered action, OpenAPI action paths only reference registered actions, and the v1 RPC generic path exists — runs in `make check`. Caught + removed a dead `task.reorder` route (no such action; reorder is `task.move`/`board.column.reorder`). `internal/action/api_fuzz_test.go` fuzzes every registered ObjectSchema action against the committed corpus `internal/action/fuzz_corpus.json` (always-invalid shapes) plus per-schema malformed inputs (missing required, wrong types); valid schema-built inputs accepted. `internal/web/rate_soak_test.go` — deterministic token-bucket soak (50 reqs/burst 5 → 5/45, per-key isolation, refill recovery) + API-level soak through real auth+handler (burst 3 → 3/7). `internal/action/audit_coverage_test.go` proves ImpactHigh is audited and ImpactLow is not, and every registered ImpactHigh action carries a permission. Fixed `tokenBucket` fresh-key accounting (was granting an extra token).

---

## Phase 5 — Wiki, Reporting, Storage (branch `build/phase-5`)

### WU-501 · Wiki read + render — `done` (99486e9, 2026-08-13)
Deps: 104.
`wiki_configs` (org owner sets repo; team admin sets ref/path — enforced by distinct permissions); go-git shallow checkout cache + refresh policy; page tree nav; goldmark render with mermaid client-side + sanitised SVG; relative link/image resolution confined to path; `KEY-n` autolinks to tasks.
AC: checkout/refresh tests against local fixture repo; traversal attempt blocked; render goldens (md, mermaid block, svg sanitised); autolink test.

### WU-502 · Wiki edit + history — `done (03deba3, 2026-08-14)`
Deps: 501, 406.
UI editor with live preview; commit as the user's linked GitHub token (WU-406); users without a linked token get read-only wiki + "connect GitHub in settings" prompt (Q2); commit message editable; non-FF retry-once then conflict UI; history view (log per file) + read-only revision render; create/rename/delete page.
AC: commit-as-user test (fixture remote); unlinked user sees read-only + prompt, edit endpoint rejects; conflict path test; history render.

### WU-503 · Wiki search + task↔wiki links — `done (e0da435, 2026-08-14)`
Deps: 501, 208.
Indexer walks checkout on refresh into FTS; wiki results in global search + palette; task descriptions/comments autolink `[[wiki page]]` syntax; wiki pages list tasks referencing them.
AC: index-on-refresh test; permission scoping (project visibility) test; backlink query test.

### WU-504 · Sprint & flow reports — `done` (86ad416, 2026-08-14)
Deps: 206.
Burndown/burnup per sprint (daily snapshots via scheduler job); cycle/lead time from activity history; project distributions; charts server-rendered SVG (no JS dep); CSV export of reports + filtered task lists.
AC: snapshot job idempotent; metric computation goldens from fixture history; CSV goldens; SVG renders (parse test).

### WU-505 · Agent usage dashboard — `done` (acfdcaf, 2026-08-14)
Deps: 310.
Org dashboard: runs/tokens/cost/actions by agent, project, timeframe; drill-down to run list; CSV export.
AC: aggregation goldens; permission test (org owner only by default).

### WU-506 · S3 attachment backend — `done` (ad9adb8, 2026-08-15)
Deps: 207.
S3 store impl (AWS SDK v2, custom endpoint, path-style option); org settings UI for backend config (encrypted); migration helper `bc storage migrate` local→S3; served via streamed proxy (same headers as local).
AC: tests against minio-compatible fake or SDK middleware stub; config round-trip; migrate helper moves + verifies checksums.

### WU-507 · Backup + ops polish — `done` (51eae7c, 2026-08-15)
Deps: 003.
`bc backup` (`VACUUM INTO` to timestamped file, prunes to N); `/readyz` covers DB + queue health; docs: RESTORE.md, DEPLOY.md (compose example, volume layout, env reference generated from config struct).
AC: backup/restore round-trip test; readyz degradation test; env reference generation test.

### WU-508 · Release readiness — `done` (adaaa9f, 2026-08-15)
Deps: all.
Full pass: `make check` on clean clone; container smoke (compose up, bootstrap, create org→project→task via UI path exercised by chromedp if available else scripted curl); tag `0.1.0-rc.1` dry-run pipeline; CHANGELOG.md.
AC: smoke script committed + green. Manual: rc pipeline run recorded here.
Result: smoke (scripts/smoke.sh) PASS — surfaced 4 release-blocking bugs, all fixed (platform-scope grants, org-owner role perms, missing create routes, Dockerfile nonroot+make build). Clean-clone make check PASS; image builds+runs; workflow YAML valid; tag v0.1.0-rc.1 local.

### WU-509 · Route gaps — S3 config + role editor stubs — `done (9c25ee2, 2026-08-15)`
Deps: 506, 107.
Comprehensive review (2026-08-15) found two real 404/501 bugs:
1. `org.storage.configure` has **no POST route** in web.go — the S3 settings form (`settings_org.templ`) posts to `/api/action/org.storage.configure` → 404. Only `org.storage.status` is wired (GET inline-dispatch). WU-506 regression missed by WU-508 smoke (smoke didn't exercise S3 config).
2. `handleOrgRoleNew` / `handleOrgRoleEdit` (web.go:203/207) are **501 stubs** — `/app/org/{orgID}/roles/new` and `/roles/{roleID}/edit` render nothing, though routes are registered and `role.create`/`role.update` actions + RolesEditorPage exist. Role editing UI incomplete since WU-107.
Result: registered POST `/api/action/org.storage.configure` (+ status); handleOrgRoles loads roles via role.list; role new/edit pages implemented (RoleFormPage, preloaded name/grants); role.create/update accept `grants_str` (flat form value) via splitGrants. AC: `org.storage.configure` POST route registered (form posts reach the action); S3 config round-trip via smoke — PASS; role new/edit page handlers render a grant-editor posting to role.create/role.update — PASS; both pages return 200 + save — PASS.
Full-pass: make check PASS, 22 pkgs green, smoke PASS (`org=a09e.. project=cf65.. task=92d7.. role=5d73..`), git clean.

### WU-510 · Notifications page — `/notifications` 404s; wire notif.list/mark_read/mark_all_read — `done (0ee4e63, 2026-08-16)`
Deps: 211.
`notif.list` / `notif.mark_read` / `notif.mark_all_read` actions exist, but only `/api/notif/unread-count` GET is wired (and its handler was a **stub returning `{"count":0}`**). The layout's `/notifications` link 404s — no notifications page route or view. Notify engine (`internal/notify`) is real, events are grouped, but there's no list/mark UI.
Result: `handleNotifications` renders a personal notification centre (direct sqlc read, user-scoped from session — same pattern as unread-count/reports/search); `handleNotifMarkRead`/`handleNotifMarkAllRead` direct sqlc mutations (accept hx-vals JSON or form id); `handleNotifUnreadCount` stub → real `UnreadNotificationCount`; `NotificationsPage` templ; badge SSE handler fixed (fetch count JSON → update Alpine `x-text`, was `bc.sse.refresh` innerHTML-swapping JSON). Routes: `GET /app/notifications`, `POST /api/notif/mark-read` + `/api/notif/mark-all-read`.
Design note: `notif.*` actions are ScopePlatform + perm only on platform admin (`["*"]`), ungrantable to regular users, so the UI bypasses action dispatch for the user's own notifications (consistent with the pre-existing unread-count handler).
AC: `/app/notifications` GET route + list view rendering session user's notifications; POST mark-read + mark-all-read wired; unread-count returns real DB count (0→1→0 round-trip); badge updates via SSE/Alpine.
Full-pass: make check PASS (22 pkgs), smoke PASS (`notif page 200; count 0→1→0`), git clean.

### WU-511 · Task templates + recurring — wire UI — `done (2a86c15, 2026-08-16)`
Deps: 209.
`template.*` / `recurring.*` actions had full backend (schedule engine computes cron nextAt) but **no routes, no UI, no dispatch anywhere** — dead actions. Task templates (create-from) and recurring tasks existed server-side but were unreachable.
Result: new project **TemplatesPage** at `/app/org/{orgID}/project/{projectID}/templates` listing task templates + recurring rules (direct sqlc reads, reports pattern) with create / create-from / delete and recurring create / delete forms (htmx → registered actions). Registered `template.create/update/create_from/delete` + `recurring.create/update/delete` POST routes (were unregistered 404s). Added missing `template.delete` action (query existed, no action). Fixed **latent scope bug**: `handleAction` only resolved project/team scope from `X-Org-Id`/`X-Project-Id`/`X-Team-Id` headers, which htmx forms don't send — added fallback populating `Opts` from the action input's `org_id`/`project_id`/`team_id`. This also fixes `board.column.create` and every project-/team-scoped form (they would 403 "missing org_id or project_id"). Headers still win when present.
AC: project templates page lists templates + recurring rules; create/delete + create-from round-trip; routes registered; smoke round-trip.
Full-pass: make check PASS (22 pkgs), smoke PASS (`templates page 200; template.create → template; create_from → task ceb0-2; recurring.create → rule`), git clean. Also fixed latent board.column.create scope failure.

### WU-512 · Outbound webhooks — wire UI — `done (32b3814, 2026-08-16)`
Deps: 405.
`webhook.create/update/delete/list` actions had sqlc + retry/DLQ/SSRF-guard engine but **no routes, no UI, no dispatch** — Phase 4 outbound surface was backend-only. Inbound GitHub hooks wired (handleGithubHook); outbound management wasn't.
Result: org **WebhooksPage** at `/app/org/{orgID}/webhooks` listing webhooks (direct sqlc ListWebhooksByOrg, reports pattern) with create form (name/url/secret/team/event_filter_str) + enable/disable toggle + delete (htmx → registered actions). Registered `webhook.create/update/delete/list` POST routes (were unregistered 404s). Added `event_filter_str` (comma-separated, splitGrants) to create/update inputs — htmx forms can't send a JSON array, mirrors role grants_str pattern.
AC: webhooks admin page + create/update/delete/list routes; toggle + delete round-trip; delivery log + retry/DLQ controls noted as follow-up (engine exists, no UI page for deliveries yet).
Full-pass: make check PASS (22 pkgs), smoke PASS (`webhooks page 200; webhook.create → webhook; toggle disable → page No; delete → DB row gone + page no longer lists`), git clean. Smoke greps match `<td>name</td>` cells (form placeholder "e.g. Slack channel" would false-positive a bare name grep).

### WU-513 · Q4 decision — require `BC_SESSION_SECRET` — `done (decided 2026-08-16, code landed 87afbf8)`
Deps: 101.
QUESTIONS.md Q4 asked whether `config.Load` should require `BC_SESSION_SECRET` (empty → CSRF HMAC keyed on `""`, weakens security; future session-cookie signing unsafe). Options: (a) require min-32 in config.Load + update tests; (b) leave optional + document; (c) auto-generate (breaks multi-instance).
Result: **decided (a)** — already implemented in `87afbf8` (WU-101, 2026-07-24): `config.Load` requires `BC_SESSION_SECRET` ≥32 chars (fatal on load), covered by `TestLoadRequiresSessionSecret` + `TestLoadSessionSecretTooShort`. `bc serve` + smoke harness already supply it. No new code needed; closed the decision record in QUESTIONS.md Q4.
AC: answer recorded in QUESTIONS.md Q4 (a); required-check verified present in config.go; config tests pass.
Full-pass: `go test ./internal/config/` PASS. No build changes (code already landed under WU-101).

### WU-514 · Wiki status stale — `done (2026-08-16)`
Deps: none.
`~/wiki/projects/boardchestrator.md` line 18 said "Phase 3 in progress, WUs 304+ ready" — stale; all WUs were done and the Ready list empty.
Result: **verified fixed** — status line now current ("Phase 0–5 complete through WU-513 (2026-08-16)"), no "Phase 3 in progress"/"WUs 304+" text remains, Ready list empty (stray WU-514 row removed). Re-indexed via `qmd update` (done under WU-510/511/512/513 close-outs).
AC: Status section current; no stale text; Ready list clean; wiki re-indexed.
Full-pass: grep for stale phrases → none; Ready table empty; `qmd update` clean. Docs-only, no code.

### WU-515 · Public OSS website + docs — `done (2026-08-16, 3691554)`
Deps: none.
Gap: no README, no docs site, no LICENSE — the repo had no public face beyond DEPLOY.md.
Result: **Go static site generator** at `website/` (markdown-driven, goldmark + yaml, single base template — awry pattern, no node deps). Pages: home (hero + 4 feature cards + brand canvas animation), docs/getting-started, deployment (env reference table), concepts. OG/canonical meta, sitemap.xml, robots.txt, llms.txt, SVG favicon, dark/light theme toggle. GitHub Pages deploy workflow `.github/workflows/pages.yml`. README.md (what/why/quickstart/layout), LICENSE (Apache-2.0), docs pages surfaced in README.
AC: public site builds (`go build` + `bc-site build`), Pages workflow present, README + LICENSE added.
Full-pass: `go build` OK; 6 pages generated; served + verified (CSS, canvas `ready`, zero JS errors); smoke WU-513 UI section PASS; `make check` PASS.

### WU-516 · App UI polish — `done (2026-08-16, 3691554)`
Deps: none.
Gap (from UX review): landing page unstyled (missing CSS classes), nav badge unstyled, broken favicon.ico, false Ctrl+K claim, manifest theme mismatch, unicode glyph icons.
Result: **styled landing** (bc-hero/features/feature-card + bc-btn-secondary + entrance animation with stagger, reduced-motion safe), **SVG favicon** served at /favicon.svg (replaced garbage 40-byte public/favicon.ico, dead dir removed), **SVG icon marks** replacing ☰/◐ glyphs, **manifest theme_color** → #2f6fed (test updated), **Ctrl+K removed** from help dialog (no palette exists).
AC: landing renders styled; favicon served as SVG; icons are SVG; manifest accent correct; help honest.
Full-pass: `go test ./internal/web/...` PASS; `go build ./...` PASS; smoke WU-513 UI section PASS; `make check` PASS.

### WU-517 · In-app help/docs area — `done (2026-08-16, 9187c3d)`
Deps: none.
Gap: `/app/docs` was a bare OpenAPI spec dump (raw JSON `<pre>`), no usable help; only a keyboard-shortcut dialog existed.
Result: **real help page** — `docs.templ` app-shell page with sidebar nav + `bc-prose` body. **7 embedded markdown guides** (`internal/web/docs/*.md`, `//go:embed`): getting-started, board, backlog, chat, wiki, permissions, webhooks — rendered via `wiki.Render` (sanitized, GFM, consistent with wiki pages). OpenAPI reference link retained; spec still at `/api/v1/openapi.json`. Routes `/app/docs` + `/app/docs/{slug}`.
AC: /app/docs renders help overview + sidebar + API link; each guide renders with active nav; spec endpoint intact.
Full-pass: `go test ./internal/web/...` PASS (TestDocsPageRenders extended + TestDocsGuideRenders new); `go build ./...` PASS; smoke WU-517 docs section PASS; `make check` PASS.

### WU-518 · API/action + MCP docs — `done (2026-08-16, 8718fb5)`
Deps: WU-517 (docs area).
Gap: the OpenAPI spec existed but no human guide covered the action dispatch pipeline, auth, or MCP integration.
Result: **two guides added** to the in-app help sidebar + index:
- `api.md` — action dispatch pipeline (resolve→validate→scope→perm→approval→idem→tx→event→audit), auth (session cookie + `X-CSRF-Token` HMAC, API-key `Bearer <prefix><secret>`), scoping (`X-Org-Id`/`X-Project-Id`/`X-Team-Id` headers + input fallback), dry-run (`X-Dry-Run: true`), idempotency (`idem` key), action index by domain.
- `mcp.md` — Boardchestrator's own MCP endpoint (`POST /mcp`, Streamable HTTP JSON-RPC: initialize/tools/list/tools/call/resources/prompts; tool names dots→underscores; scope-aware tools), plus plugging external MCP servers into agents via Skills.
AC: both guides render with active nav; index lists them; smoke covers both slugs.
Full-pass: `go test ./...` (22 pkgs) PASS; smoke WU-517 (now incl. api+mcp) PASS; `make check` PASS.

---

## Phase 6 — Security remediation (post-review 2026-08-17)

Source: six-dimension review of `main` at `e46fb31` (tenant isolation, auth/secrets, action registry/permissions, agent runtime/MCP, data layer, web/XSS). Build was green at review time — `go build`, `go vet`, `gofmt`, `go test -race` (22 pkgs) and `scripts/check-scope.sh` all passed. **The gates did not catch any of the findings below**; see WU-545.

Recurring root cause across findings: *the safe helper exists but was never wired in.* `md.Render` has zero production callers; `search.FilterByVisibility` is called on 1 of 4 paths; `SessionStore.Rotate` is never called; `orgExists()` stands where a membership check belongs; `api_keys.org_id`/`scope_json` are selected then discarded; SSE scope-narrowing was deferred to "later WUs" that never landed. Most fixes are small and local.

Ordering: **WU-519 … WU-527 are deploy blockers** — the product must not run as a multi-tenant service until they are all done. WU-528 … WU-542 are correctness/hardening. WU-543 … WU-546 are process and docs.

Branching per the rules above: one branch `wu-<N>` per WU from `main`, PR, squash-merge.

---

### WU-519 · Attachments: authorize downloads + validate MIME — `done (2026-08-18)`
Deps: none.
Two defects that chain into full script execution (see WU-525).
1. **`GET /files/{attachmentID}` has no authentication of any kind.** Route `internal/web/web.go:1352`, handler `web.go:724`. No `SessionFrom`, no `APIKeyActorFrom`, no org check — it reads the id, calls `GetAttachment`, and streams the bytes. `att.OrgID` is used *only* to pick the storage backend (`web.go:750`), never to authorize. Anonymous cross-tenant download by attachment id.
2. **Attachment MIME is attacker-chosen.** `internal/action/attachments.go:114` stores `Mime: input.MimeType` verbatim from client JSON. `internal/storage/storage.go:118-137` *does* validate a MIME — but one derived from the filename extension — and then discards it without comparing. Upload `notes.txt` with `"mime_type":"text/javascript"` and a JS body; `web.go:768` serves it as `text/javascript`, satisfying `nosniff`.

Result: **both fixed + tested.**
1. **Download authorized.** `handleAttachmentDownload` now requires an authenticated principal and org membership: session principal → `FindMembership(att.OrgID)` (no row → 404); API-key principal → `FindAPIKeyByID` + `key.OrgID == att.OrgID` (else 404); neither → 401. Cross-tenant and anonymous callers get 404/401, never confirming existence.
2. **MIME derived, client claim dropped.** `storage.Store.Upload` now returns the extension-derived MIME (`LocalStore`, `S3Store`); `attachment.upload` stores that derived type and ignores `input.MimeType`. A `.txt` upload claiming `text/javascript` is stored and served as `text/plain`.

AC: `/files/{id}` requires an authenticated principal (session or API key) **and** membership of `att.OrgID` — anonymous → 401, non-member → 404 (not 403; do not confirm existence cross-tenant); `attachment.upload` rejects an `input.MimeType` that disagrees with the extension-derived type, or drops the field and stores only the derived type; tests cover anonymous, cross-org member, and same-org member; test asserts a `.txt` upload cannot be served as `text/javascript`.
Full-pass: `go test ./...` PASS; `make check` PASS. New tests: `TestAttachmentUploadDerivesMIME` (action), `TestAttachmentDownloadRequiresMembership` + `TestAttachmentDownloadAPIKeyOrgBinding` (web).


### WU-520 · Search: enforce org scoping on all call sites — `done (2026-08-18)`
Deps: none.
`search.Query` took a `userID` argument that appeared in **no WHERE clause** — the tasks and comments queries had no org or user predicate. Scoping was a separate opt-in function, `FilterByVisibility`, called on exactly one of four paths; the other three answered unscoped or anonymous. `/api/search` additionally discarded the session-lookup `ok`, answering unauthenticated callers.

| Call site | Before | After |
|---|---|---|
| `internal/action/search.go` (search.query) | caller-side `FilterByVisibility` (dropped wiki hits) | scoped inside `Query`; wiki survives |
| `internal/web/web.go` (search page) | unscoped, ignored `ok` | session required, scoped |
| `internal/web/web.go` (`/api/search`) | unscoped, answered anonymous | session required (401), scoped |
| `internal/web/resources_v1.go` (API-key REST) | scoped by key id (no memberships) | scoped by `actor.OwnerUserID` |

Result: **all four call sites scoped + tested.** `search.Query` now scopes tasks/comments through their owning project's org membership (`EXISTS` on `memberships`) and returns nil for empty `userID` (unauthenticated); `QueryWiki` returns nil for empty `userID` and always filters by membership. The redundant caller-side `FilterByVisibility` (which silently dropped every wiki hit — empty `ProjectID` on wiki rows) is deleted. `/api/search` and the search page now reject anonymous callers (401). The API-key REST search scopes by the key's `OwnerUserID`, not the key id.

AC: org/visibility scoping is enforced **inside** `search.Query`/`QueryWiki` (parameter actually used), not left to an optional caller-side filter; all four call sites pass a real principal; `/api/search` rejects unauthenticated callers; wiki results survive filtering on the action path; regression test seeds two orgs and asserts a search in org A returns zero rows from org B on every one of the four paths.
Full-pass: `go test ./...` PASS; `make check` PASS. New tests: `TestQueryOrgScoping` (search), `TestSearchQueryOrgScoping` (action, wiki survival), `TestSearchAPIAuthAndOrgScoping` (web). Wiki index tests updated to pass a member userID.

### WU-521 · SSE: scope delivery and the replay ring — `done (2026-08-19)`
Deps: none.
`Hub.dispatch` (`internal/sse/sse.go`) iterated every subscriber with no org, membership, or permission filter, and the comment at `:156` was explicit that Phase 0 fanned every event to every authenticated client — "the audience narrows to org members in later WUs". The narrowing never landed. The replay ring was global too: `SendToUser` recorded per-user chat deltas into the shared 256-entry ring, and `Last-Event-ID: 0` replayed the last 256 events platform-wide to any session. Combined with WU-522 this was live cross-tenant credential theft: org A watched org B's `apikey.create` payloads in real time.

AC: an event is delivered only to clients whose principal is a member of `ev.Org` (and, for user-targeted messages, only to that user); the replay ring is partitioned per audience, or replay is filtered by the same predicate as live delivery; test with two orgs' clients on one hub asserts zero cross-delivery live **and** zero cross-delivery via `Last-Event-ID: 0`; `SendToUser` no longer records into the shared ring.
Result: **all AC met.** Added a `MembershipResolver` seam (`WithMembershipResolver`); the production wiring resolves each user's org memberships via a new sqlc query `FindOrgIDsForActor`. `dispatch` now delivers an org-scoped event only to member clients (platform-wide `ev.Org == ""` to all authenticated); `client` carries a snapshot of the user's orgs resolved at connect. `replaySince` filters by the **same predicate** as live delivery (per-audience, not a partitioned ring). `SendToUser` frames a user-targeted message and delivers live only to that user, and **no longer records into the shared ring** (so chat deltas never replay to anyone).
New sqlc query: `FindOrgIDsForActor` (memberships → org ids for a user) in `internal/db/queries/orgs.sql`, regenerated by `make gen`.
New test: `TestTwoOrgNoCrossDelivery` — two orgs' clients (user a ∈ orgA, user b ∈ orgB) on one hub: orgA event reaches a not b (live), orgB event reaches b not a (live), orgA event via `Last-Event-ID: 0` does not reach b, chat delta via `SendToUser` reaches only its target and does not replay. Updated `TestEventFraming`/`TestReplayFromRingBuffer` to wire a membership stub; `TestEventsStreamsToAuthedUser` seeds an org membership so the org-scoped event is delivered.
Full-pass: `go test ./...` PASS (with `-race` on sse); `make check` PASS.

### WU-522 · Stop fanning out plaintext API keys — `ready`
Deps: none.
`handleApikeyCreate` (`internal/action/apikeys.go:98`) returns `{"id", "secret": fullSecret}`. The dispatcher marshals that result once (`internal/action/dispatch.go:211`) and fans it to four sinks:
- `dispatch.go:232` — `apikey.create` is `ImpactHigh` (`apikeys.go:35`), so `Detail: payload` is written to `audit_log.detail_json`. Unconditional, every key.
- `dispatch.go:224` → event bus → SSE (WU-521) and outbound webhooks (`internal/webhook/webhook.go:99`).
- `dispatch.go:218` — persisted to `idempotency_keys.result_json` when the caller sent a key.

The sha256-at-rest design in `migrations/0016_api_keys.up.sql` is fully defeated: every key ever minted sits in cleartext in the DB, in every backup and export, and leaves the process over HTTP. `SELECT detail_json FROM audit_log WHERE action='apikey.create'` yields every key in the org.
The correct pattern already exists elsewhere — `org.storage.status` masks `SecretAccessKey` (`internal/action/storage_settings.go:104`) and `githubConnectionJSON` omits `TokenEnc` (`github_connection.go:129`). This is a forgotten case, not a missing convention.
AC: a `Definition` can mark result fields as secret (or return a separate non-persisted channel for the one-time secret); the plaintext key reaches the HTTP response **only**; audit, event payload, and idempotency result all carry the redacted form; test asserts `audit_log.detail_json`, the emitted event payload, and `idempotency_keys.result_json` contain no substring of the issued secret; audit a repo-wide sweep for other handlers returning credentials.

### WU-523 · Bind API keys to their org; replace `orgExists` with a membership check — `ready`
Deps: none.
`internal/auth/apikey.go:66` builds the actor with `Type`/`ID`/`OwnerUserID`/`IP` only — `key.OrgID` and `key.ScopeJson` are read from the row (`internal/db/queries/api_keys.sql:6`) and **discarded**, under a comment that claims "Build actor with scope intersection". `action.Actor` has no org field at all (`internal/action/action.go:119`). The MCP handler does this correctly (`internal/mcp/server.go:75` pins org to `key.OrgID`) and is the model.
Consequently the REST resource routes authenticate but never authorize: `requireAPIKey` (`internal/web/resources_v1.go:54`) returns `actor.ID` and **every caller discards it with `_`**; the only check is `orgExists()` (`:64`), which verifies the org exists, not that the caller belongs to it. Affected: `/api/v1/orgs/{orgID}/projects` (`:74`), `.../projects/{projectKey}/tasks/{taskKey}` (`:118`), `.../tasks/{taskID}/comments` (`:156`), `.../projects/{projectID}/sprints` (`:184`), `/labels` (`:212`), and `PUT .../tasks/{taskID}` (`:258`). The comments and sprints handlers are doubly broken — `orgID` is existence-checked then dropped entirely, so a project id from org B works under `/orgs/A/`.
Secondary: `perm.CheckerAdapter.Allow` (`internal/perm/engine.go:267`) passes `ac.Actor.ID` as the user id, and `grantsForScope` (`:181`) queries memberships with `ActorType: "user"` — so API-key actors resolve zero grants. That fails *closed* today, which is the only reason this is not already a write breach. **Do not "fix" that mismatch before the org binding lands**, or `POST /api/v1/actions/{name}` (`internal/web/rpc_v1.go:160`, org taken verbatim from `X-Org-Id`) becomes a full cross-tenant write RPC.
AC: `action.Actor` carries `OrgID`; `apikey.go` populates it from `key.OrgID` and parses `scope_json`; any request whose path/header/body org differs from the key's org is rejected; `orgExists` is replaced by a membership assertion; `orgID` is threaded into `ListCommentsByTask`, `ListSprints`, and `FindTaskByID`; `perm` resolves API-key actors via `OwnerUserID` intersected with the key scope; test asserts a key from org A gets 404 on every `/api/v1/orgs/B/...` route.

### WU-524 · Scope idempotency lookups to (key, actor, action) — `ready`
Deps: none.
`dbIdempotencyStore.Get` (`internal/action/store.go:34`) looks up `GetIdempotencyKey(ctx, key)` on the **key string alone**. `Put` (`:45`) writes `actor` and `action` columns that are never read back or compared. On a hit, `Dispatch` (`internal/action/dispatch.go:196`) returns the stored `result_json` verbatim and returns *before* executing, before the event sink, and before the audit append. `opts.Idem` comes straight from the caller-controlled `Idempotency-Key` header (`internal/web/rpc_v1.go:157`).
The permission check at `dispatch.go:156` runs against the action name **the attacker supplies**, not the one that stored the row. So: call a permissionless action (`invite.accept`, see WU-534) with an `Idempotency-Key` another org used, and receive their stored result — which per WU-522 may be an `apikey.create` payload. No handler runs, no audit row, no org check anywhere on the path. Keys are client-chosen and typically predictable.
AC: the lookup is keyed on `(key, actor, action)` and a hit whose stored action differs is rejected (409, not a silent replay); test asserts actor B cannot read actor A's stored result, and that the same key under a different action name does not hit.

### WU-525 · Sanitize rendered markdown (task descriptions, comments, wiki) — `ready`
Deps: none.
Three separate holes, all landing in `@templ.Raw`:
1. **Task descriptions are raw HTML.** `internal/web/web.go:524` sets `view.DescriptionHTML = AutolinkWiki(view.Description)`; `AutolinkWiki` (`internal/wiki/autolink.go:78`) only rewrites `[[name]]` and performs no escaping or sanitizing. The `else` branch (`web.go:526`) assigns the raw markdown directly. Sink: `internal/web/views/task_detail.templ:21`. **`md.Render` has zero production callers** (verified by grep) — the sanitizing renderer exists and was never wired to this path.
2. **Wiki sanitizer bypasses** (`internal/wiki/sanitize.go`, goldmark runs with `html.WithUnsafe()` at `render.go:38`): `filterAttrs` (`:135`) extracts the tag name with `IndexAny(tagSrc, " \t\r\n>")`, so `<svg/onload=alert(1)>` — no whitespace — yields a "name" of the whole string and is written back verbatim. Separately the `javascript:` check (`:145`) is **dead code**: the attribute regex (`:127`) captures the surrounding quotes, so `val` always starts with `"` or `'` and the prefix test can never fire. `<a href='javascript:alert(1)'>` and `<a href=" javascript:alert(1)">` both pass. `xlink:href` is allowed on every tag (`:170`).
3. **`md.Render` itself is not safe** despite its doc comment: `internal/md/markdown.go:188-190` builds `<img src="$2">`/`<a href="$2">` with no scheme allowlist. Attribute breakout is prevented (`html.EscapeString` runs first at `:37`), so this is scheme-only — but fix it before wiring it in.

The CSP (`internal/auth/middleware.go:83`) is a genuine nonce policy with no `unsafe-inline`, which currently downgrades these from instant XSS to HTML injection — **and WU-519's MIME hole is exactly what defeats it** (`<script src="/files/{id}">` satisfies `script-src 'self'`). Fix both or neither.
Note `views/task_detail.templ:82,332` renders `c.BodyHTML` through `templ.Raw` as well; nothing populates it today, so fix it in the same pass before it becomes live.
AC: task descriptions and comment bodies render through a sanitizing pipeline (scheme allowlist on `href`/`src`/`xlink:href`, attribute filtering that handles `/`-delimited and unquoted attributes); the two `sanitize.go` bypasses have regression tests (`<svg/onload=…>`, single-quoted and space-prefixed `javascript:`); `md.Render` gets a scheme allowlist; a test asserts no `templ.Raw` sink receives unsanitised user input.

### WU-526 · OAuth handler hardening — `ready`
Deps: none.
Four defects in `internal/auth`, one branch:
1. **`state` is not bound to the browser.** `internal/auth/handler.go:38` — `stateMap map[string]stateEntry` keyed only on the state value; no cookie, no session association. State *is* CSPRNG-generated (`:204`) and *is* verified (`:158`, `:219`), but any state minted by any visitor validates any other visitor's callback. Attacker completes consent with their own account, captures `code`+`state`, then induces the victim to load the callback (a GET) — the victim's browser is issued a session for the **attacker's** account, and everything they subsequently create lands in the attacker's tenant. Same on both providers. `GitHubProvider.Exchange` (`github.go:53`) takes a `state` param and never reads it.
2. **Unauthenticated remote crash.** That same map is written at `handler.go:149,210`, read at `:158,219`, deleted at `:163,224`, all from HTTP handler goroutines, with **no mutex anywhere in the file** (verified). Concurrent `GET /auth/google` triggers Go's `throw("concurrent map writes")`, which the `recover` middleware (`server.go:159`) cannot catch — the process dies. Also there is no sweep despite the comment at `:36` claiming cleanup, so it grows unboundedly.
3. **Login cookie minted without `Secure`.** `internal/server/server.go:204` hardcodes `Insecure: true` in the `SessionConfig` passed to the OAuth handler — the production wiring path, not a test seam. The global middleware (`server.go:172`) correctly leaves it false, so only the login cookie is affected. With the `__Host-` prefix, conforming browsers reject it outright (login silently fails in a real browser) while non-enforcing clients send a 14-day session over plaintext HTTP. Go's `http.Client` ignores cookie prefixes, which is why tests pass.
4. **GitHub `client_secret` in a URL, reflected to unauthenticated callers.** `internal/auth/github.go:55` builds `...access_token?client_id=%s&client_secret=%s&code=%s`. On transport failure Go's `*url.Error.Error()` embeds the full URL, and `handler.go:234` writes `err.Error()` into the 403 body. Induce any outbound failure and read the OAuth client secret off the error page. Even absent an error it transits in a URL into every egress proxy log. Same reflection at `handler.go:173,183,250`.

Also in scope, cheap while here: the Google ID token is decoded but never verified (`oidc.go:81` — no signature, `iss`, `aud`, `exp`, or nonce check). Currently mitigated only because the token comes straight from Google's token endpoint over TLS; the fallback `FetchGoogleUserInfo` (`oidc.go:103`) checks nothing at all, and `bootstrapGate` grants platform-owner on an email match (`handler.go:71`). Prefer `github.com/coreos/go-oidc` over hand-parsing.
AC: state is stored in a signed/`__Host-` cookie or the session and verified against the callback, not a global map; the map (if retained) is mutex-guarded with a TTL sweep, and a concurrency test drives parallel logins under `-race`; `Insecure` is derived from config, not hardcoded, and a test asserts the login cookie carries `Secure` under the production config; the GitHub token exchange sends credentials in a POST body; internal error strings are logged, never reflected to the client; ID-token claims are verified.

### WU-527 · Approval gate + agent self-escalation — `ready`
Deps: none.
The gate is trivially defeatable by its own subject.
1. **The gate reads the acting agent's own policy.** `internal/agentrt/approvals.go:79` fetches `FindAgentByID(ctx, ac.Actor.ID)` — the agent being gated — and reads `agent.ApprovalPolicyJson`. There is no org-level policy anywhere in the codebase.
2. **The policy parse fails open.** `approvals.go:85` does `_ = json.Unmarshal(...)` (error discarded); `policyFor` (`:36`) returns `"auto"` for a missing key; `decisionFor` (`:44`) has `default: return ApprovalProceed` for `"auto"` *and anything unknown*. An empty, malformed, or partially-written policy auto-approves every impact class including `high`, permanently.
3. **`agent.update` writes both fields unvalidated.** `internal/action/agents.go:158-195` writes caller-supplied `role_id` (`:167`) and `approval_policy` (`:181`) with no validation, via a full-row-overwrite query (`internal/db/queries/agents.sql:7`) — so omitting `approval_policy` sets it to `""`.

Escalation: an agent whose role∩skills includes `agent.update` calls it on its own id with `{"role_id":"<Org Owner>","approval_policy":""}`. That single call is `ImpactHigh` and parks for approval — a human reviewer sees only "agent.update" and a JSON blob. On approval the agent holds `["*"]` and has zeroed its own gate; every subsequent high action runs unattended.
AC: approval policy is read from the **org**, not the acting agent; unparseable or missing policy fails **closed** (`require`) for `high`, and the unmarshal error is surfaced not discarded; `agent.update` validates `role_id` against roles in scope, rejects an agent targeting its own `role_id`/`approval_policy`, and is a partial update rather than a full-row overwrite; approval prompts render the concrete field diff, not a raw blob; tests cover self-update rejection and malformed-policy-fails-closed.

---

### WU-528 · Bound the SQLite connection pool — `ready`
Deps: none.
`internal/db/db.go:23` returns the `*sql.DB` without `SetMaxOpenConns`/`SetMaxIdleConns`; `grep -rn SetMaxOpenConns --include=*.go` returns **zero hits repo-wide**. Go defaults to unlimited connections, so N goroutines each take a connection and contend for the single WAL write lock; the 5s `busy_timeout` defers but does not prevent `SQLITE_BUSY: database is locked`.
The codebase has already normalised the bug: `internal/action/race_test.go:81` asserts that concurrent mutations failing with "database is locked" is *expected*. That is a test blessing the defect. Two users dragging cards on the same board simultaneously = one 500 and a silently lost move.
Several other findings are only as dangerous as `SQLITE_BUSY` is frequent (WU-531's discarded errors, WU-532's swallowed index errors), so this goes first in the P1 block.
Correctly handled and not to be disturbed: the DSN pragma syntax at `db.go:24` applies WAL, `foreign_keys(1)`, `busy_timeout(5000)`, `synchronous(NORMAL)` to **every** pooled connection, and `internal/db/db_test.go:59` asserts them live.
AC: writes are serialised (`SetMaxOpenConns(1)`, or a 1-conn writer pool plus an N-conn reader pool); `race_test.go` no longer tolerates "database is locked" and asserts every concurrent mutation succeeds; a concurrency test drives parallel board mutations with zero `SQLITE_BUSY`.

### WU-529 · Move audit and idempotency writes inside the action transaction — `ready`
Deps: none.
`execute()` (`internal/action/dispatch.go:252`) is a correct tx boundary in isolation — BeginTx, rollback on handler error, commit. But steps 9/10/11 (`:205-245`) all run **after** that commit returns:
- **Idempotency (`:217`)** — the mutation commits, `idem.Put` fails, Dispatch returns an error, the caller retries with the same key, gets no hit at `:196`, and **the action executes a second time**. Duplicate task, duplicate invite, double state transition. This defeats the entire purpose of the layer.
- **Audit (`:235`)** — every `ImpactHigh` action and every agent action commits its mutation first and audits second. If the append fails or the process dies, a privileged mutation is permanent with no audit record.
AC: the idempotency `Put` and the audit `Append` execute inside the same transaction as the handler; a fault-injection test asserts that a failing audit write rolls back the mutation, and that a failing idempotency write does not permit double execution.

### WU-530 · Serialise run-enqueue limit checks — `ready`
Deps: 528.
`EnqueueRun` (`internal/agentrt/engine.go:362-390`) is check-then-act with no transaction — the engine's `q` is `sqlc.New(cfg.DB)` (`:75`), bound to `*sql.DB` and never a `*sql.Tx`. `OrgMonthlySpend` (`:367`) and `CreateRun` (`:387`) are separate autocommit statements with nothing serialising them. Ten concurrent enqueues all read the same under-cap spend and all insert: the org's monthly USD cap is breached by up to N× concurrency. **This is real money on a multi-tenant platform.**
Identical TOCTOU on every safety limit: `CountActiveRunsByTask` (`:301`), `CountActiveRunsByProject` (`:315`), `CountRunsByAgentInWindow` (`:334`), `SumAgentTokensInWindow` (`:347`) — each a read followed by an unguarded insert. The per-task overlap guard, which exists precisely to stop two agents editing one task, does not hold under concurrency.
Related: the cap is only evaluated at enqueue. Nothing re-checks inside `runToolLoop`/`chatStreamLoop`, so a single long run can burn arbitrarily far past the cap (see WU-538).
AC: the read-check-write is one transaction (or a conditional `INSERT ... WHERE (SELECT …) < cap`); a concurrency test enqueues N runs against a cap of 1 and asserts exactly one succeeds; same for the per-task and per-project active-run guards.

### WU-531 · Job pool: stop discarding handler retry state — `ready`
Deps: 528.
`internal/job/pool.go:212` treats a `nil` return as success and unconditionally calls `store.Complete()`. But both handlers own their own retry and return `nil` on the **failure** path:
- `Deliverer.RunJob` (`internal/webhook/webhook.go:161,167`) returns `d.store.Fail(...)` / `d.store.Dead(...)`, both `nil` on success — the pool then marks the job `succeeded`, erasing the requeue. The comment at `webhook.go:143` states the invariant ("RunJob owns retry") that the pool does not honour.
- `Engine.failAndRetry` (`internal/agentrt/engine.go:497`) does the same.

So a webhook endpoint returning 500 records `attempts=1, status=failed`, requeues for +30s, and is immediately marked succeeded — never claimed again, no dead-letter. `MaxAttempts` and backoff are dead configuration on both paths.
Also in this file:
- `ClaimTimeout: 30 * time.Second` (`internal/server/server.go:488`, stored `pool.go:141`) is **never read again** — there is no reaper for jobs stuck in `running`.
- `pool.go:205,207` discard errors with `_ =`; a `SQLITE_BUSY` there strands the job in `running` forever.
- `pool.go:197,205,212` all use `p.ctx`, which `Stop()` cancels (`:155`) — every in-flight job during graceful shutdown fails its completion write with `context canceled` and is stranded.
- `pool.go:170-193` — every worker independently calls `ListQueued` (LIMIT 25) and races to claim the same rows, wasting N−1 claim attempts per job against the write lock.

Correctly handled: `ClaimJob` (`pool.go:42`, `jobs.sql:11`) is a single atomic conditional `UPDATE … RETURNING` — claiming itself is race-free.
AC: the pool distinguishes "handler owns terminal state" from "handler succeeded" (explicit sentinel or a `Result` return) and never overwrites a `Fail`/`Dead` with `Complete`; a reaper reclaims `running` jobs older than `ClaimTimeout`; completion writes use a context that survives `Stop()`; errors are logged not discarded; test asserts a failing webhook delivery is retried `MaxAttempts` times and then dead-lettered.

### WU-532 · FTS index correctness — `ready`
Deps: none.
`tasks_fts` is an FTS5 external-content table (`migrations/0013_search.up.sql:6`). The indexer handles `task.create` and `task.update` in the **same branch** with a plain `INSERT INTO tasks_fts (rowid, …)` and no preceding delete (`internal/search/search.go:46`). FTS5 does not upsert, so editing a title five times leaves six index entries: the task appears six times in one result list, and searching the **original** title still returns it forever. Same defect for comments (`:83`).
Also:
- `search.go:44` — `if err != nil { return nil }` swallows the rowid lookup error; a `SQLITE_BUSY` means the task is silently never indexed, no log, no retry.
- No `task.unarchive` case in the switch (`:27-102`) though `UnarchiveTask` exists (`internal/db/queries/tasks.sql:52`); `task.archive` deletes the FTS row and unarchiving never restores it, so the task is permanently unsearchable.
- Indexing is driven by events emitted **after** commit (`dispatch.go:225`) and there is no rebuild or backfill path anywhere — a crash between commit and index is a permanent search gap.

`internal/wiki/store.go:97-121` does this correctly (delete-then-reinsert inside a tx with `defer tx.Rollback()`) and is the pattern to copy.
AC: delete-before-insert for tasks and comments; `task.unarchive` reindexes; index errors are logged and retried, not swallowed; a `bc reindex` (or startup backfill) path exists; test edits a task title 5× and asserts exactly one hit and zero hits on the old title.

### WU-533 · Webhook delivery: SSRF, atomicity, secret handling — `ready`
Deps: 531.
1. **The SSRF guard does not do what its comment claims.** `internal/webhook/webhook.go:237-252` — the doc says "resolve-then-connect pinning (DNS rebind safe)"; no pinning exists. `ssrfGuard` resolves the host and checks `ips[0]`, then `deliver` (`:179`) builds a request from the **original URL string** and lets the client re-resolve. Classic DNS-rebinding window. Only `ips[0]` is inspected, so `[1.2.3.4, 127.0.0.1]` passes. `d.client` (`:53`) sets no `CheckRedirect` (`grep -rn CheckRedirect` → nothing), so a `302 Location: http://169.254.169.254/…` reaches cloud metadata. `isPublicIP` (`:270`) relies on `ip.IsPrivate()`, missing `100.64.0.0/10` and `0.0.0.0/8`. `urlHost` (`:255`) is a hand-rolled parser resolving a different string than `http.NewRequestWithContext` parses.
2. **Enqueue is not atomic.** `CreateWebhookDelivery` (`:102`) and `EnqueueJob` (`:122`) run on two `sqlc.New(d.db)` handles — two autocommit transactions. If the second fails, a `webhook_deliveries` row sits in `queued` with no job: never delivered, never retried, never dead-lettered, reported as queued forever. `HandleEvent` (`:86`) returns on the first error mid-loop, so a 5-webhook org can end up 2 delivered, 1 orphaned, 2 never created, with no rollback.
3. **The signing secret is copied in plaintext into the job payload.** `:109` marshals `wh.Secret` into `jobs.payload_json`, duplicating it into a table with different retention and access, readable by the admin queue viewer, `ListDead`, `ListQueued`, and any DB export. The delivery row is already re-read at `:148`; read the secret from the webhook row at delivery time instead.

Correctly handled: the payload **is** HMAC-SHA256 signed over the exact body (`:183`) and the secret is not sent to the destination.
AC: the guard resolves once and dials the pinned IP (custom `DialContext`), checks **all** returned addresses, blocks redirects (or re-validates each hop), covers CGNAT/`0.0.0.0/8`, and uses `net/url`; delivery row + job are created in one transaction and a per-webhook failure does not abort the loop; the secret is no longer persisted to `jobs.payload_json`; tests cover a rebinding resolver, a metadata-IP redirect, and a multi-A-record host.

### WU-534 · Impact classes, `ActorService` bypass, `invite.accept` — `ready`
Deps: 527.
The default policy is `{"read":"auto","low":"auto","high":"require"}` (`internal/action/agents.go:149`, `migrations/0019_agents.up.sql:19`), so **every `ImpactLow` action runs for an agent with no human approval**. Misclassified:

| Action | Location | Why |
|---|---|---|
| `webhook.update` | `webhooks.go:56` | repoints an existing webhook URL/secret → silent exfiltration of all org events. create/delete are High; only update is Low |
| `wiki.config.repo` / `.ref` | `wiki.go:82` / `:90` | repoints the org wiki at an attacker repo; wiki content feeds agent context → prompt-injection channel into every agent |
| `wiki.delete` / `wiki.rename` | `wiki.go:130` / `:122` | data destruction under `wiki.edit` at Low |
| `user.export` | `data_export.go:30` | full personal-data export (`org.export` at `:45` is correctly High) |
| `github.connect` / `.disconnect` | `github_connection.go:25` / `:33` | establishes/tears down a platform integration credential |
| `attachment.delete` | `attachments.go:48` | blob deletion gated only on `task.update` |
| `chat.send` | `chat.go:165` | enqueues another agent run; `MaxStepsPerRun` is per-run, so there is no cross-run recursion bound |
| `task.bulk_move` / `bulk_assign` / `bulk_label` | `filter.go:75-91` | unbounded mass mutation at single-item class |
| `role.list` | `perms.go:69` | a pure read declared Low — desynchronises the read/write partition |

Two structural issues in the same area:
- **`ActorService` bypasses the permission engine entirely** — `internal/perm/engine.go:259`: `if ac.Actor.Type == action.ActorService { return true, nil }`, no grant walk, no org check. `internal/github/github.go:227` dispatches `task.move` as `Actor{Type: ActorService, ID: "github"}`, authenticated only by the per-project webhook secret — and `github.config.upsert`, which **sets that secret**, is `ImpactLow` (`internal/action/github.go:14`). An agent holding it can set the secret, forge signed deliveries, and drive `task.move` as a principal the engine never checks.
- **`invite.accept` is the only action with `Permission: ""`** (`internal/action/invites.go:67`), and both agent gates treat empty as allow — `toolsForAgent` (`internal/agentrt/tools.go:82`), `agentPermChecker.Allow` (`internal/agentrt/perms.go:113`), and `keyAllows` (`internal/mcp/server.go:154`). It is `ScopePlatform` + `ImpactLow`, so it survives every filter on the MCP path and `handleInviteAccept` (`invites.go:179`) then writes a membership with `ActorID: ac.Actor.ID`, `ActorType: "user"` — inserting an agent or API-key id as a user membership.

Correctly classified and not to be disturbed: `role.*`, `membership.*` (`perms.go:31-64`), `member.invite`/`member.remove` (`invites.go:52`), `apikey.*` (`apikeys.go:35`), `skill.*` (`skills.go:76`), `provider.*` (`providers.go:48`), `org.cap.set`, `org.storage.configure` — all High with a specific grant. The privilege-granting surface is right; the gaps are integration config and data export/deletion.
AC: the impact classes above are corrected with a rationale comment on each; empty `Permission` is rejected at `Register` (a registry test asserts no definition has one) and `invite.accept` gets an explicit permission with a token-bound check; `ActorService` is scoped to a permission set rather than a blanket allow; `github.config.upsert` is `ImpactHigh`.

### WU-535 · `perm.intersectGrants` returns the broader term — `ready`
Deps: none.
`internal/perm/engine.go:164-178` appends `g` — the **role grant** — rather than `u`, the matched skill action:
```go
for _, g := range grants {
    for _, u := range union {
        if checkPermission(u, []string{g}) { out = append(out, g); break }
    }
}
```
This is not an intersection. Role `["*"]` matches any skill action, so `out == ["*"]` and `checkPermission` (`:230`) then returns true for **every** permission; the seeded Org Owner role holds `["*"]` (`:33`). Role `["task.*"]` ∩ skill `["task.create"]` yields `["task.*"]`, granting `task.archive`/`task.unarchive`. The narrowing effect of skills is erased whenever the role holds a wildcard.
Currently latent — no code path constructs an `ActorAgent` against the server dispatcher (`grep ActorAgent` over `internal/web`, `internal/server`, `internal/mcp`, `internal/auth` → no hits); the agent runtime uses its own checker. But this is the function the SPEC comment at `:82` designates as authoritative, and any future agent-actor route inherits it.
Correctly handled for contrast: `agentrt.EffectivePerms` (`internal/agentrt/perms.go:206`) genuinely intersects by exact membership and cannot widen — `validateAllowedActions` (`internal/action/skills.go:155`) rejects any skill entry not in the registry, so `"*"` cannot be stored on a skill. Note the side effect: role `task.*` ∩ skill `task.create` yields the **empty** set there, which fails closed but reads as a silent misconfiguration to operators — worth a warning log.
AC: `intersectGrants` emits the matched union member `u`; table test covers `["*"] ∩ ["task.create"] == ["task.create"]` and `["task.*"] ∩ ["task.create"] == ["task.create"]`; add the operator warning for an empty intersection.

### WU-536 · `BC_SECRET_KEY` derivation + AEAD associated data — `ready`
Deps: none.
`tenant.PadKey` (`internal/tenant/secrets.go:76`) zero-pads a short key to 32 bytes with no KDF and no salt, and `internal/config/config.go:74` validates only that `BC_SECRET_KEY != ""` — contrast `SessionSecret`, correctly required ≥32 chars at `:78`. `BC_SECRET_KEY=hunter2` yields an AES-256 key of `hunter2` + 25 NUL bytes: ~56 bits, offline-brute-forceable against a stolen DB, with AES-GCM providing a free verification oracle. This key protects every org's S3 credentials (`internal/action/storage_settings.go:59`), GitHub PATs and OAuth tokens (`github_connection.go:81`, `internal/auth/handler.go:261`), and skill secrets (`skills.go:207`).
Separately, `secrets.go:35` seals with `nil` associated data. AEAD choice, nonce generation (`crypto/rand`, full `NonceSize()`, `:30`), the nonce-prepend framing, and the `len(key) != 32` guard are all **correct** — but with no AAD binding the ciphertext to its row, an attacker with DB write access can copy org A's encrypted S3 blob into org B's `org_secrets` row and have the server decrypt and use it.
AC: `BC_SECRET_KEY` is required at ≥32 chars (fatal in `config.Load`, matching `SessionSecret`) and run through HKDF rather than zero-padded; `Seal`/`Open` bind `org_id||key` as associated data; a migration or documented re-encryption path handles existing ciphertexts; test asserts a blob moved between org rows fails to decrypt.

### WU-537 · Session lifecycle: logout, revoke scoping, rotation — `ready`
Deps: none.
- **There is no logout endpoint at all.** `setupRoutes` (`internal/server/server.go:209`) registers only the four `/auth/*` OAuth routes; `SessionStore.Revoke` (`internal/auth/session.go:184`) has no HTTP caller anywhere in the tree. Users cannot end a session; it lives 14 days sliding / 90 days absolute.
- **`session.revoke` has no ownership check.** `internal/web/user_settings.go:87` and `internal/action/user.go:84` both call `DeleteSession(ctx, input.TokenHash)` with a caller-supplied hash and no `AND user_id = ?`. Exploitability is limited (hashes are sha256 of 32 random bytes and are not exposed cross-user), so this is a missing-authorization defect rather than a live takeover.
- **`Rotate` is never called.** `session.go:167` is a correct fixation-defeating implementation; login uses `Create` (`handler.go:192,272`). Since `Create` mints a fresh token this is not exploitable fixation, but pre-existing sessions are not invalidated on re-login.
- **API keys never expire.** `migrations/0016_api_keys.up.sql` has `revoked_at` but no `expires_at`. Revocation itself is correctly enforced at the query level (`internal/db/sqlc/api_keys.sql.go:78`).
- **Org admins cannot revoke keys.** `internal/action/apikeys.go:107` ignores `input.OrgID`/`input.UserID` and revokes with `UserID: ac.Actor.ID`, so only the creator can revoke — an org owner cannot kill a departed employee's key. `apikey.list` (`:120`) and `internal/web/apikeys.go:27` have the same bug.
- **Non-constant-time key compare.** `internal/auth/apikey.go:61` uses `!=` on hex digests; use `subtle.ConstantTimeCompare`. Low impact (it compares sha256 outputs) but free to fix.
AC: `POST /auth/logout` revokes the current session, clears the cookie, and is CSRF-protected; `session.revoke` is scoped to `ac.Actor.ID`; `Rotate` is called on login; `api_keys` gains `expires_at` with enforcement; org admins with `org.permissions` can list and revoke org keys; constant-time compare; tests for each.

### WU-538 · Agent loop bounds and cancellation — `ready`
Deps: 530.
The step cap works — `MaxStepsPerRun = 25` (`internal/agentrt/tools.go:26`), enforced at `:132` and `:228`. Everything else is missing:
- **No per-turn tool-call cap.** `tools.go:165` and `:298` iterate `choice.ToolCalls` unbounded; a model returning 5,000 tool calls gets 5,000 dispatches, each a DB transaction.
- **No `max_tokens`.** Requests at `tools.go:135` and `:232` set only `Model`, `Messages`, `Tools`; `CompletionRequest.MaxTokens` (`internal/client/client.go:76`) is never populated anywhere.
- **No wall-clock bound.** Per HTTP call the ceiling is 5 minutes (`client.go:199`) and `do` retries 3× with up to 30s backoff (`:255`) — worst case ≈16 min/step × 25 steps ≈ 6.5 hours for one run, holding a pool worker throughout. With `AgentWorkers` such runs, the entire job queue wedges (webhooks and scheduled triggers included).
- **No in-loop budget re-check** — see WU-530; the cap is enqueue-time only.
- **Cancellation is dead code.** `cancelFlag`/`newCancelFlag`/`cancel()` (`engine.go:179-193`) have zero non-test callers; `executeRun` hard-codes `runToolLoop(..., nil)` (`:426`) so the check at `tools.go:129` never fires; `chatStreamLoop` has no cancel parameter; the `CancelRun` query (`internal/db/sqlc/runs.sql.go:69`) has no Go caller and no `run.cancel` action is registered. There is no way to stop a running agent short of `agent.kill-all`, which only sets `active=0` and does not touch in-flight runs.
- The loop never checks `ctx.Err()` between steps (context *is* correctly propagated into HTTP calls, retry sleeps, and `BeginTx`).
AC: per-turn tool-call cap, `MaxTokens` on every request, a per-run wall-clock deadline, and an in-loop spend re-check; a registered `run.cancel` action wired to `cancelFlag` and to `agent.kill-all`; the loop checks `ctx.Err()` between steps; tests cover a tool-call flood, a deadline expiry, and cancellation mid-run.

### WU-539 · MCP endpoint correctness — `ready`
Deps: 523, 534.
- **Fake approvals.** `internal/mcp/server.go:199-205` returns a synthetic `{"status":"approval_pending","approval_id":…}` for any `ImpactHigh` action **without persisting an approvals row** — nothing can ever decide it. High actions are unexecutable over MCP (fails closed) but the response lies to the client.
- **Empty scope on dispatch.** `:210` calls `Dispatch(..., action.Opts{})` with no Org/Team/Proj, even though `Handle` reads `key.OrgID` at `:71` and threads it correctly to `handleResourceRead`. `ScopeOrg` actions therefore fail with `ErrScope`, while `ScopePlatform` actions proceed and record an **empty `Org`** in the audit log and event (`dispatch.go:224,234`) — agent/API-key actions land unattributed to any tenant.
- **Lossy name mapping.** `toolName`/`actionName` (`:141`, `:220`) swap `.`↔`_` unconditionally, so `notif_mark_read` maps to `notif.mark.read` and the real `notif.mark_read` is unreachable.
- **Unbounded body.** `json.NewDecoder(r.Body).Decode(&req)` at `:84` with no `MaxBytesReader` (the 10s `ReadTimeout` at `server.go:147` bounds it in time, not size).
AC: high-impact actions over MCP persist a real approvals row and are resumable, or are refused with an honest error; `Opts.Org` is populated from `key.OrgID`; the name mapping is a lookup table over the registry, not a character swap, and round-trips every registered action in a test; the body is size-limited.

### WU-540 · Agent runtime IDs and the `capAlerted` race — `ready`
Deps: none.
- **`newID()` is `fmt.Sprintf("%d", time.Now().UnixNano())`** (`internal/agentrt/engine.go:568`), used for run, run-step, chat-message, approval, and notification ids. Contrast `internal/action/action.go:260` and `internal/webhook/webhook.go:281`, which correctly use `crypto/rand`. Two consequences: ids are guessable within a narrow window (and the run id doubles as the job id, `:411`), and two `recordStep` calls in the same nanosecond collide on the primary key — the error is swallowed by `_ = eng.recordStep(...)` (`tools.go:148,270`) so a step vanishes from the transcript silently; two runs enqueued in the same nanosecond collide on the job id and the run is dropped.
- **`capAlerted` is an unsynchronised map** — `engine.go:35`, read at `:581`, written at `:586`, with no mutex, while the type comment at `:22` claims "safe for concurrent runs". `EnqueueRun` is called from at least four goroutines (`internal/server/server.go:842,876,916,1037`, launched at `:495-521`), so a concurrent mention-trigger and scheduled trigger for the same org produce `fatal error: concurrent map read and map write` — **not** recoverable by the `recover` middleware. `-race` will not surface it without a test driving two trigger loops simultaneously; none exists.
- `capAlerted` is never reset, so the "once per crossing" threshold alert (`:381`) fires once per **process lifetime**, not once per month.
AC: `newID` uses `crypto/rand` (reuse `action.newID`); `recordStep` errors are logged; `capAlerted` is mutex-guarded or a `sync.Map`, with a test under `-race` driving concurrent `EnqueueRun` from multiple goroutines; the alert resets per billing period.

### WU-541 · Bound untrusted response reads; validate provider `base_url` — `ready`
Deps: none.
`internal/client/client.go:232` does `json.NewDecoder(resp.Body).Decode(&result)` with no `io.LimitReader`/`MaxBytesReader` and no content-type check; the only bound is the 5-minute timeout, so a malicious or compromised provider streams JSON at line rate and OOMs the worker. `internal/auth/github.go:127` and `internal/auth/oidc.go:111` do this correctly with `io.ReadAll(io.LimitReader(resp.Body, 1<<16))` and are the model. Streaming is only partially bounded: `readStream` caps one SSE line at 64 KiB (`client.go:305`) but `result.Content += d.Delta.Content` (`:324`) accumulates unbounded and is O(n²) in copies, as do `sb`/`toolCalls` in `tools.go:250`.
Separately, `prov.BaseUrl` flows into `client.New` (`engine.go:104`) with no SSRF validation — `provider.create`/`update` (`internal/action/providers.go:118-160`) store `input.BaseURL` verbatim and `validateMcpEndpointURL` is never applied to it — and `Authorization: Bearer <key>` is then sent there (`client.go:262`). Mitigating: both actions are `ScopePlatform` + `ImpactHigh`, so this needs platform-admin rights.
Note `internal/action/ssrf.go` has the same pre-resolution-only design as WU-533 but is validate-at-registration only and nothing dials those endpoints; fold it into the WU-533 helper.
AC: all outbound response bodies are size-limited; accumulated stream content has a cap that ends the run cleanly; provider `base_url` goes through the shared SSRF validator; tests cover an oversized response and a private-IP base URL.

### WU-542 · Query hygiene: archived tasks, kill-switch, NULL-org — `ready`
Deps: none.
- **Archived tasks are never filtered out.** `internal/db/queries/tasks.sql:42` — `ListTasksByProject` selects `WHERE project_id = ?` with no `AND archived = 0`, though `ArchiveTask`/`UnarchiveTask` (`:48-54`) maintain the column. `grep archived internal/db/queries/*.sql` shows the flag is written but **never read as a predicate**. At `internal/action/sprints.go:143` the result is bound to a variable literally named `openTasks` and used for sprint rollover, so archived tasks are carried into the next sprint and counted in scope.
- **The agent kill-switch can fail silently.** `internal/action/killswitch.go:16` — `DeactivateAllAgentsByOrg` is `UPDATE agents SET active = 0 WHERE org_id = ?` (`agents.sql:43`); with a NULL/empty org, SQL three-valued logic matches zero rows and returns nil, and the handler still returns `"disabled": true, "message": "all agents disabled"` (`:19-23`). `ScopeOrg` should guarantee a non-empty org, so this is defence-in-depth — but a safety control that cannot fail loudly is the wrong shape.
- Same NULL-org pattern at `internal/action/skills.go:258,295,305,316,338,350`.

Correctly handled: `audit_log.org_id` is genuinely nullable by design (documented at `migrations/0002_action_infra.up.sql:2`) with a dedicated `ListAuditLogsPlatform … WHERE org_id IS NULL` (`audit_log.sql:23`), as has `ListPlatformSkills` (`skills.sql:17`). The NULL semantics were understood in the query layer; the Go call sites are where it leaks.
AC: `ListTasksByProject` (and the sprint rollover path) exclude archived tasks, with an explicit query for the archive view; `killswitch` checks `RowsAffected` and errors when zero; empty-org guards on the `skills.go` call sites; tests for each.

### WU-543 · `hx-vals` payloads destroyed by `templ.URL` — `ready`
Deps: none.
`templ.URL` treats everything before the first `:` as a scheme when it contains no `/`. For `{"id":"abc"}` that is `{"id"`, which is not in the allowlist, so it returns `FailedSanitizationURL` and the attribute renders as `about:invalid#TemplFailedSanitizationURL` — **HTMX sends no values at all**. Affected: `internal/web/views/people.templ:28`, `sprint_list.templ:46`, `webhooks.templ:77,85`, `task_detail.templ:94,225`, `scheduled_triggers.templ:58,68`, `invite.templ:14`. Delete, toggle, remove, and accept controls are silently broken in the shipped UI.
`scripts/smoke.sh` drives those routes over HTTP directly, which is exactly why it passes — see WU-545.
Silver lining: the string-concatenated JSON is therefore not an injection vector today; keep it that way by building the payload with `templ.JSONString` rather than concatenation.
AC: `hx-vals` is emitted through a correct JSON helper, not `templ.URL`; no rendered attribute contains `TemplFailedSanitizationURL` (assert in a views test across every affected template); a browser-level or DOM-asserting test covers at least one delete and one toggle round-trip.

### WU-544 · `schema.sql` drift from migrations — `ready`
Deps: none.
Applying all 32 `.up.sql` to a scratch DB and diffing against `migrations/schema.sql` shows they do not match. All 32 apply cleanly, but:
- **Column order differs on every ALTERed table** (`ALTER TABLE ADD COLUMN` appends; `schema.sql` was hand-edited to insert mid-list): `orgs` (`monthly_cap_usd`, `cap_alert_pct` vs `created_at`), `runs` (`project_id` last vs mid-table), `board_columns` (`trigger_prompt`/`created_at`).
- `wiki_fts` (migration 0031) is **entirely absent** from `schema.sql` — which is why `internal/search/search.go:205` and `internal/wiki/store.go` hand-write raw SQL for it: sqlc cannot see the table.
- `tasks_fts`/`comments_fts` are declared at `schema.sql:375-388` as plain `CREATE TABLE`, not `CREATE VIRTUAL TABLE … USING fts5`, so sqlc's model of them has no relationship to the real external-content tables.

This matters because `sqlc.yaml:4` uses `schema.sql` as the codegen source of truth: sqlc expands `SELECT *`/`RETURNING *` using its ordering and generates positional `rows.Scan`. Today the only star-expansions are `internal/db/queries/jobs.sql:6,17,40`, and `jobs` has no ALTERs — so this is **latent, not currently firing**. It becomes silent data corruption the moment anyone adds a column to `jobs` or writes `SELECT * FROM runs`; TEXT-into-TEXT mismatches will not even error.
Also `migrations/0005_roles.down.sql` is missing (32 up, 31 down); golang-migrate treats an absent down as a nil migration so `MigrateDown` still passes (`internal/db/db_test.go:94`), but it leaves the seeded sentinel org and system roles behind.
AC: `schema.sql` is regenerated from the migrations (not hand-edited) and matches byte-for-byte; FTS tables are declared as virtual tables or excluded from sqlc with the raw-SQL dependency documented; `0005_roles.down.sql` added; a `make` target regenerates it and CI fails on drift (see WU-545).

### WU-545 · CI gates — close the holes that let all of this land — `ready`
Deps: none.
The review found ~30 defects against a fully green build. The gates do not cover what broke:
- **`scripts/check-scope.sh` never runs in CI** — `grep -rn 'check-scope\|make check' .github/` returns nothing. It exists only in `make check`. Same for `scripts/smoke.sh`.
- **Tests do not run on PRs.** `.github/workflows/test.yml` triggers on `push: branches: [main]` only; `lint.yml` is the sole PR gate and runs gofmt/templ/golangci-lint with no tests.
- **`make check` and CI have diverged** — `make check` also verifies sqlc output is diff-clean and `go.mod` is tidy; `lint.yml` checks only templ output.
- **The scope gate has a structural blind spot worth documenting in the script:** `tasks`, `comments`, and the wiki tables have **no `org_id` column** (they are scoped via `project_id`), so they cannot be in `TENANT_TABLES` and the gate passes cleanly while not covering the highest-traffic entities. Scoping for them rests entirely on application-layer joins — which WU-520 and WU-523 show were not always present.
- Coverage: `internal/auth` 26.2%, `internal/web` 28.5%, `internal/job`/`schedule`/`notify`/`client` **0.0%** — the security-critical packages are the least tested.
AC: CI runs `make check` (or at minimum check-scope + sqlc diff + `go mod tidy` diff) on PRs; `test.yml` gains `pull_request`; smoke runs in CI against the compose image; a `schema.sql` drift check (WU-544); the `check-scope.sh` header documents the project-scoped-table blind spot and points at the join-level tests that cover it; coverage floor for `internal/auth` raised with tests for the WU-526 and WU-537 paths.

### WU-546 · Docs and changelog catch-up — `ready`
Deps: none.
- `CHANGELOG.md` `[Unreleased]` stops at WU-508. WU-509 – WU-518 (notifications centre, task templates, webhooks UI, role editor, S3 config route, public website, in-app docs, API/MCP reference) are all undocumented — ten shipped work units.
- `README.md` links `[Documentation](/website)`, `[Getting started](/website/content/getting-started.md)`, `[Deployment](…)`, `[Concepts](…)` with a **leading slash**, which GitHub resolves against `github.com/` rather than the repo — all four 404. Use repo-relative paths.
- README's "Repository layout" lists `public/ app favicon`, but there is no `public/` directory at the repo root (removed in WU-516 when the favicon became an SVG served from `internal/web/static`).
- QUESTIONS.md Q3 (SQLite driver) has no `**Answer:**` line; an assumption was recorded and is non-blocking. Close it for the record.
- The Dockerfile installs `ca-certificates` **and** copies `/etc/ssl/certs/ca-certificates.crt` from the builder — redundant; and the build carries no `-trimpath` or version ldflags, so `bc` reports no version.
AC: CHANGELOG covers WU-509 – WU-518 and the Phase 6 fixes; README links resolve on GitHub (CI link-check if cheap); the `public/` line is corrected; Q3 answered; Dockerfile deduplicated and stamped with a version.
