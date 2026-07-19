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

### WU-004 · App shell (templ + HTMX, responsive) — `ready`
Deps: 002.
templ base layout: header, sidebar (desktop) / bottom-nav + drawer (mobile), main slot; embedded static assets with cache-busting hashes; vendored htmx, Alpine, app.js (SSE helper stub); `app.css` design tokens, dark/light via `data-theme` + `prefers-color-scheme`; breakpoints 640/1024.
AC: layout renders (templ unit test on rendered HTML: nav present, nonce attr present); static served with immutable cache headers (handler test); `make check` includes templ generate diff-clean. Manual: shell verified at 375px and 1280px widths.

### WU-005 · Sessions, CSRF, CSP — `ready`
Deps: 003, 004.
Server-side session store (sessions table) with `__Host-bc_session` cookie; CSRF per-session token, middleware rejecting mutating requests without it, token injected into base layout `hx-headers`; nonce-based CSP middleware; security headers (nosniff, frame-ancestors none, referrer-policy).
AC: tests — mutation without CSRF → 403, with → 200; CSP header carries fresh nonce per request; session create/rotate/expiry covered.

### WU-006 · Action registry + dispatch — `ready`
Deps: 003.
`internal/action` per SPEC §4: Definition, Register (panic on dup), Dispatch pipeline (schema validate → scope resolve → perm hook interface → approval hook interface [no-op impl for now] → tx execute → idempotency store → event emit → audit hook); `ErrApprovalPending`, `ErrForbidden`; dry-run mode; migration: `idempotency_keys`, `audit_log`.
AC: unit tests for every pipeline branch: invalid input, unknown action, dup register panic, idempotent replay returns stored result, dry-run does not execute, high-impact emits audit via hook, event emitted with actor.

### WU-007 · Event bus + SSE hub — `ready`
Deps: 002, 006.
`internal/event` typed pub/sub (buffered, non-blocking, drop-with-metric on slow consumer); `internal/sse` hub keyed by user with topic filter; `/events` endpoint (session auth stub interface), heartbeat, Last-Event-ID ring buffer.
AC: bus delivery + slow-consumer tests; SSE handler test asserts event framing, heartbeat, replay from ring buffer.

### WU-008 · Dockerfile + CI — `ready`
Deps: 001.
Multi-stage Dockerfile (distroless nonroot, /data volume); workflows: `lint.yml` (PR→main: golangci-lint, gofmt, templ gen check), `test.yml` (push→main: `go test -race ./...`), `release.yml` (tag `*-rc.*` matching `^\d+\.\d+\.\d+-rc\.\d+$`: build image, no push; tag `^\d+\.\d+\.\d+$`: buildx, push ghcr `X.Y.Z` + `latest`).
AC: `docker build` succeeds locally; workflows lint clean (actionlint if available); tag-pattern filtering covered by workflow-level `if` conditions reviewed against both tag shapes. Manual: build run recorded in note below.

### WU-009 · Landing page — `ready`
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
