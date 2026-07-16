# Boardchestrator — Technical Specification

**Status:** v1, governs implementation. PRD.md governs scope; if they conflict, PRD wins and the conflict goes in QUESTIONS.md.
**Reading order for workers:** WORKER.md → this file (§1–§5 always; the domain section for your work unit) → BACKLOG.md.

---

## 1. Architecture Overview

One Go binary. One SQLite database. Everything embedded.

```
                       ┌────────────────────────────────────────────┐
 Browser (templ/HTMX) ─┤                                            │
 REST client ──────────┤  chi router → middleware → handlers        │
 MCP client ───────────┤        │                                   │
                       │        ▼                                   │
                       │  ACTION DISPATCH (internal/action)         │
                       │  authn → tenant scope → permission →       │
                       │  approval gate → execute → event → audit   │
                       │        │                        │          │
 Agent tool loop ──────┤────────┘                        ▼          │
 (internal/agentrt)    │                          event bus         │
                       │                     ┌──────┼──────┬─────┐  │
                       │                    SSE  notify  webhook activity
                       │                                            │
                       │  sqlc data layer (org-scoped) → SQLite WAL │
                       └────────────────────────────────────────────┘
```

Rules that must never be violated:

1. **All mutations go through action dispatch.** Handlers never write to the DB directly. Reads may use the data layer directly but must pass an org scope.
2. **The data layer requires scope.** Every sqlc query touching tenant data takes an `org_id` (and narrower ids where relevant) parameter. A CI grep-gate (`make check-scope`) fails on tenant-table queries without it.
3. **Actors are polymorphic.** `Actor{Type: user|agent|apikey, ID}` flows through dispatch; nothing downstream may assume a human.

## 2. Repository Layout

```
cmd/bc/                 main; subcommands: serve, backup, gen-key
internal/config/        env loading (BC_*), validation
internal/server/        chi router assembly, middleware (reqid, log, recover, csrf, csp, session)
internal/db/            sqlite open (WAL, foreign_keys, busy_timeout), embedded migrations, sqlc out
internal/action/        registry, dispatch pipeline, impact classes, idempotency, dry-run
internal/event/         in-process event bus, typed events
internal/perm/          permission engine, role resolution
internal/auth/          oauth (google oidc, github), sessions, api keys, bootstrap
internal/tenant/        orgs, teams, projects, memberships, roles, invites, org settings, audit log
internal/task/          tasks, labels, relations, custom fields, comments, sprints, boards, filters,
                        templates, recurring, archive, activity
internal/storage/       attachment backend interface; local/, s3/
internal/notify/        notification engine + prefs
internal/sse/           per-user/per-project SSE hub
internal/search/        FTS5 index maintenance + query
internal/agentrt/       providers, agents, skills, job queue, runs, tool loop, approvals, cost
internal/chat/          chat sessions, streaming
internal/restapi/       /api/v1 from registry, OpenAPI generation
internal/mcp/           /mcp streamable HTTP server from registry
internal/ghub/          github oauth link, inbound webhooks, PR↔task transitions
internal/wiki/          go-git checkout cache, render, edit-commit, history
internal/report/        burndown, cycle time, agent usage, CSV export
internal/web/           handlers + templ views (views/), static assets (static/: vendored htmx,
                        alpine, sortablejs, mermaid; app.css tokens; sw.js; manifest)
migrations/             NNNN_name.up.sql / .down.sql (append-only once merged)
```

## 3. Conventions

- **Go**: latest stable; `gofmt`; `golangci-lint` (default set + errcheck, gosec); wrap errors with `%w`; no panics in request paths; context first arg everywhere.
- **IDs**: 16-byte random, hex-encoded TEXT primary keys (portable, no autoincrement leakage). Task numbers are per-project sequences (§5, `projects.next_task_num`) presented as `KEY-<n>`.
- **Time**: store UTC ISO-8601 TEXT (`strftime('%Y-%m-%dT%H:%M:%fZ')`-compatible); render in the user's timezone.
- **Migrations**: append-only after merge to main; every up has a down; no data-destructive downs.
- **templ/HTMX**: pages are full templ layouts; HTMX endpoints return partial templ components. Use `hx-boost` for nav, explicit `hx-*` for interactions. All state-changing requests carry the CSRF token (hx-headers on `<body>`). SSE via native `EventSource` in a small vendored JS helper; server sends named events (`task-updated`, `notification`, `chat-delta`, `run-status`).
- **JS policy**: Alpine for local component state; no build step, no npm. Vendored libs pinned by version in `internal/web/static/vendor/`.
- **CSS**: single `app.css`, design tokens as custom properties (`--bc-*`), `data-theme` attribute for dark/light, mobile-first with breakpoints 640/1024.
- **UI copy**: Australian English (organisation, customisable, colour).
- **Testing**: table-driven unit tests; handler tests with `httptest` against a real temp-file SQLite with migrations applied (helper in `internal/db/dbtest`); no mocking the DB. Race detector always on in CI.
- **Make targets**: `make gen` (templ + sqlc), `make check` (gen + git-diff-clean check, gofmt check, vet, golangci-lint, check-scope, `go test -race ./...`), `make dev` (serve with local .env), `make build`.
- **Commits**: `WU-NNN: imperative summary` (one WU per commit unless a WU explicitly allows more).

## 4. Action Registry (internal/action)

```go
type Impact int // ImpactRead, ImpactLow, ImpactHigh

type Definition struct {
    Name       string            // "task.create" — stable, never renamed
    Impact     Impact
    Permission string            // perm key checked against actor's effective grants
    Scope      ScopeKind         // platform|org|team|project — what id the input must carry
    Input      *Schema           // JSON schema (compiled once)
    Output     *Schema
    Handle     HandlerFunc       // func(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error)
    Preview    HandlerFunc       // optional; nil ⇒ dry-run returns validated input echo
}

type ActionCtx struct {
    Actor    Actor              // user | agent | apikey (with owning user)
    Org, Team, Project string   // resolved scope ids ("" where n/a)
    DryRun   bool
    Idem     string             // idempotency key ("" = none)
}
```

- `Register(def)` at package init; duplicate names panic at startup.
- `Dispatch(ctx, actorRef, name, input, opts)` runs: resolve actor → validate input schema → resolve+verify scope (ids exist, actor is member) → permission check → **approval gate**: if actor is an agent and its policy for `def.Impact` is `require-approval`, persist an `approvals` row and return `ErrApprovalPending{ID}`; `forbid` returns `ErrForbidden` → idempotency check (return stored result on hit) → execute in a tx → store idempotent result → emit `event.Event{Name, Org, Actor, Subject, Payload}` → append audit row for ImpactHigh (all actors) and all agent actions.
- **Derivation surfaces** (REST §11, MCP §12, agent tools §10) iterate `action.All()`; they never hand-register endpoints for registered actions.
- Approval resume: `approval.decide(id, approve|reject)` (itself an action, ImpactHigh) re-dispatches the stored call as the original agent actor with the gate satisfied, then wakes the owning run.

Action naming: `<resource>.<verb>`: `org.create`, `team.update`, `project.archive`, `member.invite`, `member.remove`, `role.create`, `role.assign`, `task.create/update/move/assign/label/relate/archive`, `comment.create/update/delete`, `sprint.create/update/close`, `label.create`, `filter.save`, `attachment.upload/delete`, `agent.create/update`, `skill.create/import/attach`, `run.cancel`, `approval.decide`, `wiki.edit`, `webhook.create`, `apikey.create/revoke`, `search.query` (read), `notification.markread`, `settings.update` per scope.

## 5. Data Model

Compact notation: `table(col…)`; all tables carrying tenant data include `org_id` even when reachable via joins (denormalised on purpose for the scope gate). PKs are `id TEXT` unless noted. Encrypted columns end `_enc` (AES-GCM via `BC_SECRET_KEY`).

**Identity & access**
```
users(id, email UNIQUE, name, avatar_url, theme, timezone, created_at, deleted_at)
identities(id, user_id, provider, subject, email, token_enc, UNIQUE(provider,subject))
sessions(token_hash PK, user_id, ip, ua, created_at, last_seen_at, expires_at)
api_keys(id, user_id, name, prefix, key_hash, scope_json, last_used_at, revoked_at, created_at)
platform_settings(id=1, context, bootstrap_done, settings_json)
```

**Tenancy**
```
orgs(id, name, slug UNIQUE, context, settings_json, created_at)         -- settings: attachment limits, spend cap
org_secrets(org_id, kind, value_enc)                                    -- s3 creds, github bot token
teams(id, org_id, name, context, created_at)
projects(id, org_id, team_id, key, name, context, visibility, swimlane_json,
         next_task_num INT, archived_at, UNIQUE(org_id,key))
roles(id, org_id NULL, name, permissions_json, system BOOL)             -- org_id NULL = platform default
memberships(id, org_id, scope_type, scope_id, actor_type, actor_id, role_id,
            UNIQUE(scope_type,scope_id,actor_type,actor_id))            -- actor_type: user|agent
invites(id, org_id, email, role_id, token_hash, invited_by, expires_at, accepted_at)
audit_log(id, org_id NULL, actor_type, actor_id, action, subject, detail_json, ip, created_at)
idempotency_keys(key PK, actor, action, result_json, created_at)
```

**Tasks & boards**
```
tasks(id, org_id, project_id, num INT, title, description, state, priority, points,
      due_date, sprint_id NULL, position REAL, archived_at, created_by, created_at,
      updated_at, UNIQUE(project_id,num))
task_assignees(task_id, user_id) ; task_watchers(task_id, user_id)
labels(id, org_id, name, colour) ; task_labels(task_id, label_id)
task_relations(id, org_id, from_task, to_task, kind)                    -- blocks|relates|duplicates
custom_field_defs(id, project_id, org_id, name, kind, options_json, position)
custom_field_values(task_id, field_id, value, PK(task_id,field_id))
comments(id, org_id, task_id, author_type, author_id, body, edited_at, deleted_at, created_at)
task_activity(id, org_id, task_id, actor_type, actor_id, kind, detail_json, created_at)
attachments(id, org_id, task_id, uploader_id, filename, mime, size, storage_key, created_at)
sprints(id, org_id, project_id, name, starts_on, ends_on, state)
board_columns(id, org_id, project_id, name, colour, position, wip_limit, state,
              move_roles_json NULL, trigger_agent_id NULL, trigger_prompt NULL)
saved_filters(id, org_id, project_id, owner_id, name, query_json, shared BOOL, pinned BOOL)
task_templates(id, org_id, project_id, name, template_json)
recurring_rules(id, org_id, project_id, template_id, cron, next_at, active)
```

**Notify / integrate**
```
notifications(id, org_id, user_id, kind, actor_type, actor_id, subject_kind, subject_id,
              body, read_at, created_at)
notification_prefs(user_id, kind, enabled, PK(user_id,kind))
webhooks(id, org_id, team_id NULL, url, secret_enc, events_json, active)
webhook_deliveries(id, webhook_id, event_json, attempts, status, last_code, next_retry_at)
github_links(id, org_id, task_id, kind, repo, ref, url, state, UNIQUE(task_id,url))
project_github(project_id PK, org_id, repo, transitions_json, webhook_secret_enc)
```

**Agent runtime**
```
providers(id, kind, name, base_url, api_key_enc, models_json, created_at)   -- kind: openai_compat|codex_sso
provider_orgs(provider_id, org_id)
agents(id, org_id NULL, template_id NULL, name, provider_id, model, context,
       role_id, retry_max, backoff_secs, runs_per_hour, token_budget,
       approval_policy_json, active, UNIQUE(org_id,name))                    -- org_id NULL = platform template
skills(id, org_id NULL, name, version INT, description, instructions,
       allowed_actions_json, param_schema_json, mcp_endpoints_enc, created_at)
agent_skills(agent_id, skill_id)
jobs(id, kind, payload_json, run_at, attempts, max_attempts, status, locked_by, locked_at)
runs(id, org_id, agent_id, trigger, task_id NULL, chat_session_id NULL, initiated_by NULL,
     status, error, prompt_tokens INT, completion_tokens INT, created_at, started_at, finished_at)
     -- status: queued|running|awaiting_approval|succeeded|failed|cancelled
run_steps(id, run_id, seq INT, kind, request_json, response_json, tokens INT, created_at)
approvals(id, org_id, run_id, action_name, input_json, status, requested_at,
          decided_by NULL, decided_at NULL)
chat_sessions(id, org_id, user_id, scope_type, scope_id, agent_id, created_at)
chat_messages(id, session_id, role, content, cards_json, run_id NULL, created_at)
scheduled_triggers(id, org_id, project_id, agent_id, cron, prompt, next_at, active)
```

**Wiki & search**
```
wiki_configs(project_id PK, org_id, repo_url, ref, path, updated_by, updated_at)
search_index  -- FTS5: (kind, org_id UNINDEXED, ref UNINDEXED, title, body); app-maintained
```

## 6. Permission Engine (internal/perm)

- A permission is a string key = action name (plus a few UI-only reads like `report.view`).
- Roles carry `permissions_json` (list, `*` wildcard suffix allowed: `task.*`).
- Resolution for actor A on scope S: gather memberships for A on S and S's ancestors (project → team → org); union grants; nearest-scope membership wins where roles conflict is unnecessary — grants are additive; absence = deny.
- Agents: effective = role grants ∩ union of attached skills' `allowed_actions`.
- Column move restriction: `board_columns.move_roles_json` checked inside `task.move`.
- Seeded system roles per PRD table; system roles are copy-on-edit (editing creates an org-owned copy).

## 7. Auth Flows (internal/auth)

- Google OIDC (discovery, `state`+`nonce`+PKCE) and GitHub OAuth (`state`); callback path `/auth/{provider}/callback`.
- Link-by-verified-email: existing user with the same verified email gains the identity; otherwise a user row is created.
- **Bootstrap**: if `platform_settings.bootstrap_done=0`, a login only becomes Platform Admin when email ∈ `BC_ADMIN_EMAILS` or the login request carries the `BC_BOOTSTRAP_TOKEN` (token printed to log at startup while unclaimed). All other logins before bootstrap are rejected with a friendly page.
- Sessions: 32-byte token, SHA-256 stored, cookie `__Host-bc_session` Secure HttpOnly SameSite=Lax; rotated at login; sliding + absolute expiry.
- API keys: format `bc_<prefix>_<secret>`; prefix stored plain for lookup, secret SHA-256 hashed; scope JSON `{org_id?, team_id?, project_id?, actions?[]}` intersected with the owner's live permissions at request time.

## 8. Realtime (internal/sse)

- `/events` (session auth) and per-project `/events?project=` streams; hub keyed by user id with topic filters; heartbeat every 25s; `Last-Event-ID` replay from a small ring buffer (best effort).
- Event bus subscribers: sse hub, notification engine, webhook dispatcher, search indexer, activity writer, github transition engine.

## 9. Storage (internal/storage)

```go
type Store interface {
    Put(ctx, key string, r io.Reader, size int64, mime string) error
    Get(ctx, key string) (io.ReadCloser, error)
    Delete(ctx, key string) error
}
```
`local` (files under `BC_DATA_DIR/attachments`, key = `<org>/<task>/<id>`), `s3` (AWS SDK v2, custom endpoint). Selected per org (org_secrets) falling back to local. Upload path: validate size/type per org settings → images re-encoded (png/jpeg) via stdlib image; SVG passed through sanitiser (strip scripts/foreignObject/event attrs) → store → attachment row.

## 10. Agent Runtime (internal/agentrt)

- **Queue**: `jobs` polled by N workers (default 4, `BC_AGENT_WORKERS`); claim via `UPDATE … WHERE status='queued' … RETURNING`; exponential backoff to `max_attempts` = agent `retry_max`.
- **Run lifecycle**: trigger (mention/column/chat/schedule) → create `runs` row + job. Worker: assemble context → tool loop → finish. Cancellation sets a flag checked between steps.
- **Context assembly order**: platform context → org → team → project → agent context → skill instructions (each attached skill) → trigger payload (task snapshot: fields, comments, relations, attachment names; or chat history). Each block labelled with its source.
- **Tool loop**: chat-completions with `tools` = registry actions filtered to the agent's effective permission set (schemas from action Input), plus external MCP tools from skills (namespaced `mcp_<skill>_<tool>`). Execute via Dispatch as the agent actor; `ErrApprovalPending` → persist state, set run `awaiting_approval`, stop; on decision, resume with the approval result appended. Cap steps per run (default 25).
- **Provider client**: OpenAI-compatible chat completions with streaming; retries with jitter on 429/5xx; token usage recorded per step. `codex_sso` kind is stubbed behind the same interface (see QUESTIONS.md).
- **Budgets**: pre-run check org monthly spend vs cap (hard stop + notification at threshold); per-agent `runs_per_hour` and `token_budget` enforced at claim time.
- **Mention parsing**: `@name` in saved description/comment where name matches an active org agent → job. Column trigger: `task.move` handler enqueues when target column has `trigger_agent_id`.

## 11. REST API (internal/restapi)

- Router generated from registry: `POST /api/v1/actions/{name}` (uniform RPC) **plus** resource-style aliases for the common reads (`GET /api/v1/projects/{key}/tasks` etc. — thin wrappers over read actions).
- Bearer API keys; scope enforcement in dispatch; `Idempotency-Key` header → `ActionCtx.Idem`; problem+json errors with `code`; cursor pagination on list reads; ETag/If-Match on task update.
- OpenAPI 3.1 document generated at startup from registry schemas, served at `/api/v1/openapi.json` + embedded viewer at `/api/docs`.
- Per-key token-bucket rate limit (default 120/min) with `RateLimit-*` headers.

## 12. MCP Server (internal/mcp)

- Streamable HTTP at `/mcp`; auth `Authorization: Bearer <api key>`.
- **Tools**: from registry filtered to key scope ∩ owner permissions; unauthorized tools omitted from `tools/list`. Names: dots→underscores (`task_create`).
- **Resources**: `bc://project/{key}`, `bc://task/{key}-{n}`, `bc://project/{key}/context`, `bc://wiki/{key}/{path}`; `resources/list` scoped; subscriptions via list-changed where cheap.
- **Prompts**: `decompose_task(task)`, `summarise_sprint(project, sprint)`, `triage_backlog(project)`.
- High-impact tool call by a key whose policy requires approval → tool result `{"status":"approval_pending","approval_id":…}` (never silent execution).
- Implementation: `modelcontextprotocol/go-sdk` if it satisfies streamable HTTP + auth hooks; otherwise minimal in-repo JSON-RPC implementation. Decide at WU-403 and record in BACKLOG notes.

## 13. Wiki (internal/wiki)

- Per-project checkout cache under `BC_DATA_DIR/wiki/<project>` (go-git, shallow, single ref); refreshed on read if older than 60s (config) or on webhook.
- Render: goldmark (GFM, task lists) + `mermaid` fenced blocks → client-side render; SVG through the shared sanitiser; relative links/images resolved within the configured path (no traversal above it).
- Edit: UI editor (textarea + preview) → commit to `ref` using the editor's GitHub identity token; fallback org bot token with `Co-authored-by` the user; push; on non-fast-forward, re-pull and retry once, else surface conflict.
- History: `git log` for the file; render any revision read-only.

## 14. Search (internal/search)

- FTS5 table maintained by the event-bus indexer (task created/updated, comment, wiki refresh walk).
- Query API: `search.query(q, org, filters)` → grouped results (tasks, wiki, attachments-by-name), permission-filtered post-query by project visibility.
- Command palette endpoint returns top-N mixed results + matching registered actions the user may perform.

## 15. Security Requirements (gate for every WU)

CSRF token on all mutating browser requests; nonce CSP (`default-src 'self'`) with zero inline script except nonced bootstrap; `__Host-` cookies; org-scope on every tenant query (`make check-scope`); secrets only in `_enc` columns; attachments `Content-Disposition: attachment` + nosniff; sanitised SVG/mermaid output; SSRF guard on webhook/MCP-endpoint URLs (deny private ranges, resolve-then-connect pinning); rate limits on auth and API; audit rows for ImpactHigh.

## 16. Verification Gates

A work unit is **done** only when:
1. `make check` passes (gen diff-clean, fmt, vet, lint, scope-gate, tests with race).
2. Every acceptance criterion in its BACKLOG entry has a corresponding automated test, or an explicit `Manual:` note in the BACKLOG entry saying how it was verified with `bc serve`.
3. BACKLOG.md status updated with date + commit subject in the same commit.
