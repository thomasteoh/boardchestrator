# Boardchestrator — Product Requirements Document

**Repo:** `github.com/thomasteoh/boardchestrator`
**Status:** Draft for review (v2)
**Last updated:** 2026-07-15

Boardchestrator is a self-hostable, agent-native project management platform. It provides a fully customisable board interface (agile-like defaults, simplified Azure DevOps functionality) where AI agents are first-class actors alongside humans. The web UI, the REST API, the MCP server, and agents themselves are all clients of one internal action layer with one permission model.

This document governs scope. Anything not in here is out of scope until added here.

---

## 1. Core Principles

1. **Agent-native.** Every action a human can take (create task, invite user, configure a team) is expressible as an internal action an agent can also invoke, subject to scoped permissions. The web UI, REST API, and MCP server are thin clients over this action layer.
2. **Single binary, single container.** Go binary with embedded templates and static assets, SQLite backend, runs in one container with a data volume.
3. **Configuration cascades.** Platform → Organisation → Team → Project. Context, agent availability, and settings flow downward; lower levels extend or override where permitted.
4. **Shared multi-tenancy.** One SQLite database, tenant scoping via organisation ID columns enforced in the data layer.
5. **Responsive and accessible by default.** Every surface works on phone, tablet, and desktop, and is operable by keyboard and screen reader.

---

## 2. Tech Stack

| Concern | Choice |
|---|---|
| Language | Go (latest stable) |
| HTTP router | chi |
| Templates | templ |
| Frontend interactivity | HTMX + Alpine.js |
| Drag and drop | SortableJS (pointer + touch), with a non-drag menu fallback |
| Realtime | Server-Sent Events (SSE) |
| Styling | Mobile-first CSS, design tokens for theming (dark/light/system) |
| PWA | Web app manifest + service worker (app-shell caching) |
| Database | SQLite (WAL mode), `modernc.org/sqlite` (pure Go, no CGO) |
| Migrations | golang-migrate, embedded, run on startup |
| Query layer | sqlc |
| Markdown | goldmark, mermaid rendered client-side, sanitised SVG |
| Git operations (wiki) | go-git |
| Sessions | Secure cookie sessions, server-side session store in SQLite |
| Secrets at rest | AES-GCM, key from `BC_SECRET_KEY` |
| Logging | slog, structured JSON, level via env |
| Metrics | Prometheus `/metrics` |
| Container | Distroless or alpine base, published to ghcr.io |

All frontend libraries are vendored and embedded. No CDN dependencies at runtime.

### Configuration

12-factor: all config via environment variables (`BC_` prefix). Key vars: `BC_DB_PATH`, `BC_DATA_DIR` (attachments, wiki checkouts), `BC_BASE_URL`, `BC_GOOGLE_CLIENT_ID/SECRET`, `BC_GITHUB_CLIENT_ID/SECRET`, `BC_SESSION_SECRET`, `BC_SECRET_KEY`, `BC_BOOTSTRAP_TOKEN`, `BC_ADMIN_EMAILS`, `BC_LOG_LEVEL`.

---

## 3. Action Layer & Events

The action layer is the architectural spine. It exists before any client.

- **Action registry.** Every mutation and query is a registered action with: a stable name (e.g. `task.create`, `member.invite`), an input JSON schema, an output schema, the permission it requires, and an **impact class** (`read`, `low`, `high`). `high` covers deletes, permission and role changes, member add/remove, integration and secret changes, and any spend-incurring operation.
- **One definition, four surfaces.** The web handlers, REST routes, MCP tools, and the agent tool-loop are all derived from the registry. Adding an action exposes it everywhere with one permission rule and one schema.
- **Every call is checked and recorded.** Dispatch runs: authenticate actor (human or agent) → resolve tenant scope → permission check → optional approval gate (§8) → execute → emit event → append to audit/activity log with actor, args summary, and result.
- **Idempotency.** Mutating actions accept an idempotency key so retries (agent or network) do not double-apply.
- **Dry-run / preview.** Any action can be invoked in preview mode returning the intended effect without committing. This powers the chat "propose then apply" flow and MCP approval results.
- **Events.** Actions emit typed events consumed by: SSE fanout (realtime UI), the notification engine, outbound webhooks, and the activity timeline. This is the single source of "what happened".

---

## 4. Identity & Auth

- **SSO only**: Google OIDC and GitHub OAuth. No passwords, no separate MFA; the identity provider handles auth strength.
- Account linking: the same verified email across providers maps to one user.
- **First user bootstrap.** The first login can claim Platform Admin only when it matches `BC_ADMIN_EMAILS` or presents `BC_BOOTSTRAP_TOKEN` (printed to logs on first start). This stops a public instance being hijacked by the first random visitor.
- OIDC `state` and `nonce` validated; sessions rotated on login; login attempts rate-limited.
- Session management: users view and revoke their active sessions.
- **API keys**: users generate scoped, revocable keys (hashed at rest) for the REST API and MCP server. A key may be narrowed to an org/team/project and to a subset of the user's permissions. Agents get their own internal service credentials.

---

## 5. Tenancy & RBAC

### Hierarchy

**Platform** → **Organisation** → **Team** → **Project**

- Platform Admin manages platform settings, platform-wide agent templates, provider integrations, and organisation creation.
- Each level has configurable **context** (freeform markdown) injected into agent prompts, concatenated top-down.

### Roles

Roles are **configurable**: a role is a named set of permission grants. Permissions are fine-grained verbs on resource types (`task.create`, `task.move`, `member.invite`, `agent.configure`, `wiki.edit`, `org.settings`, and so on). Ship with generic defaults:

| Role | Summary |
|---|---|
| Org Owner | Everything in the org, including integrations, agents, roles |
| Team Admin | Manage team, its projects, boards, wiki config |
| Member | Create/edit tasks, comment, use agents |
| Viewer | Read-only |
| Guest | Read and comment on explicitly shared projects |

- Roles assigned per org, overridable per team/project.
- Project visibility: org-wide, team-only, private.
- **Agents hold roles too.** An agent's effective permissions = assigned role ∩ attached skills' allowed actions. Same enforcement path as humans.

### Membership

- Invite by email; invitee completes signup via SSO.
- Agents can invite and manage members if their permissions allow it.

---

## 6. Boards & Tasks

### Structure

- **Flat task hierarchy + labels.** No epic/story nesting. Labels are org-scoped, coloured, filterable.
- **Task keys.** Each project has a short uppercase KEY; tasks are numbered sequentially per project as `KEY-<n>` (stable, human-referenceable, used in GitHub links).
- Task relationships: `blocks` / `blocked-by`, `relates-to`, `duplicates`.
- Fields: title, description (markdown), state, multiple **assignees**, labels, story points, sprint, priority, due date, watchers, custom fields (per-project: text, number, select, date, checkbox).

### Boards

- Fully configurable columns (name, colour, WIP limit, mapped state) with agile defaults (Backlog / To Do / In Progress / Review / Done).
- Optional swimlanes (by assignee, label, or custom field).
- Drag-and-drop between and within columns (SortableJS + HTMX patch), with a card menu "move to" fallback for touch and keyboard.
- Column-level move permissions (e.g. only certain roles move to Done).
- **Column agent triggers**: dropping a task into a configured column fires a configured agent with a configured prompt template (§8).

### Views

- Board view and backlog view (ordered flat list) per project.
- Saved filters (assignee, label, sprint, state, text), shareable within a team, pinnable as board tabs.
- Bulk operations: multi-select then assign / label / move / sprint.
- Archive for closed tasks and projects.

### Sprints

- Per-project sprints: name, date range; assign tasks in/out; active-sprint board filter.

### Task detail

- Comments (markdown, @mention users and agents), with edit/delete and preview.
- **Agent thread**: prompts, tool calls, and responses of agent runs stored on the task, rendered distinctly from human comments.
- Activity timeline: every field change, move, and assignment with actor (human or agent) and timestamp.
- Attachments: images and documents, inline image preview, size/type limits configurable per org.
- Task templates per project.
- Recurring tasks (schedule spawns a fresh copy).
- All dates rendered in the viewer's timezone (user setting, default from browser).

### Attachments storage

- Default: local volume under `BC_DATA_DIR`.
- Org-configurable S3-compatible backend (endpoint, bucket, credentials). Storage is abstracted from day one so backends are pluggable.

---

## 7. Notifications

- **In-app notification centre** only (no email): assigned, @mentioned, watched-task state change, agent run finished/failed, approval requested.
- Per-user preferences: toggle each trigger type; grouping to avoid noise.
- Realtime delivery via SSE; unread badge.
- **Outbound webhooks** (org/team level) on events, HMAC-signed, with retry and dead-letter. Egress is SSRF-guarded (internal ranges blocked).

---

## 8. Agent Harness

### Providers

- Configured by **Platform Admin**: providers are either **Codex SSO** (OAuth to an OpenAI/ChatGPT account) or any **OpenAI-compatible API** (base URL + key + model list).
- Org owners select from providers made available to their org.
- *(Open item: confirm Codex SSO auth flow is permitted for programmatic use; see review notes.)*

### Agents

- **Platform-wide agent templates** defined by Platform Admin, allocated to organisations. Orgs customise allocated agents: skills, additional context, name.
- Org-defined agents also supported.
- Each agent has a **unique @-mentionable name** within its org.
- Agent config: provider/model, system context, attached skills, role (permissions), retry policy (configurable max retries + backoff), rate limits (runs/hour, token budget), and **approval policy** per impact class.

### Skills Hub

- A **skill** = versioned definition: name, description, instructions (markdown), the set of **allowed actions** it grants, an optional parameter schema, and optionally **external MCP endpoints/tools** the skill authorises the agent to call (credentials stored as encrypted org/skill secrets). Model similar to pi agent skills.
- Skills can be created in-app, imported (JSON/markdown bundle), and attached to agents.
- Scoped as platform skills (allocatable) and org skills.
- An agent can only perform actions granted by role ∩ attached skills.

### Approval gates (human-in-the-loop)

- Each agent/skill sets, per impact class, one of `auto` / `require-approval` / `forbid`.
- When an autonomous run hits a `require-approval` action, it creates a **pending approval** surfaced on the task and in notifications. A permitted human approves or rejects; on approval the action executes and the run resumes.
- In the chat sidebar, approval is inline (propose → approve/apply).
- High-impact actions default to `require-approval`.

### Triggers

1. **@mention in a task** (description or comment): the agent is prompted to action work within that task.
2. **Column drop**: dragging a task into a configured column triggers a configured agent with a configurable prompt.
3. **Chat sidebar**: conversational; create projects/tasks, decompose a task into subtasks, make updates. The agent proposes or executes via the action layer.
4. **Scheduled**: cron-style per-project triggers (e.g. weekly summary of open tasks).

### Execution

- Runs are first-class entities with states: `queued`, `running`, `awaiting-approval`, `succeeded`, `failed`, `cancelled`. Viewable and cancellable.
- SQLite-backed job queue with bounded concurrency.
- **Context assembly**: platform + org + team + project context, then skill instructions, then task content (title, description, comments, attachment metadata, relations).
- **Tool loop**: the model receives the action layer (filtered to effective permissions) as tools plus any authorised external MCP tools; each call is permission-checked, approval-gated, and recorded.
- Agents act **as themselves** (agent actor) in the activity log; chat runs also note the initiating user.
- Full transcript (prompts, tool calls, results, token counts) stored against the task or chat session.
- Failure: retry per policy, then mark failed and notify the trigger's owner.
- **Cost controls**: per-run token accounting; per-agent budget; per-org monthly spend cap with alert threshold and hard stop; org dashboard aggregates tokens/cost by agent and project.

---

## 9. Chat Sidebar

- Persistent sidebar on desktop; on mobile a full-screen drawer toggled from a floating button.
- Conversation scoped to the current project (widenable to team/org for permitted users).
- Streams responses and intermediate steps (SSE).
- Agent actions render as structured cards ("Created BC-142") with links; high-impact proposals show a **diff/preview with approve or discard**.
- Chat history persisted per user per scope.
- Slash commands (`/assign`, `/label`, `/decompose`) as shortcuts to common actions.

---

## 10. REST API & MCP Server

### Action layer as single source

REST, MCP, and the agent tool-loop all derive from the action registry (§3). One action definition, one permission rule, all surfaces.

### REST API

- Base `/api/v1`, JSON. OpenAPI 3.1 generated from the registry, served at `/api/v1/openapi.json` with a browsable UI.
- Auth: `Authorization: Bearer <api-key>`; the key's scope bounds every request.
- Idempotency via `Idempotency-Key`; cursor pagination (`?cursor=&limit=`); optimistic concurrency via ETag + `If-Match`.
- Errors: RFC 9457 problem+json with stable machine-readable codes.
- Per-key rate limiting with `RateLimit-*` headers.

### MCP server

Boardchestrator is both an **agent host** (consumes providers) and an **MCP host** (exposes tools to external agents). This covers the outward-facing server.

- **Transport**: streamable HTTP MCP at `/mcp`, authenticated with the same user API keys. The key's scope bounds every call.
- **Tools**: generated from the action registry, filtered to the key's permitted subset, grouped by resource (`task_*`, `board_*`, `sprint_*`, `comment_*`, `label_*`, `wiki_*`, `member_*`, `agent_*`, `search`). Each tool's schema derives from the action's input schema. Unauthorized tools are omitted, not merely denied.
- **Resources**: read-only context at stable URIs: `bc://project/{key}`, `bc://task/{key}-{n}`, `bc://wiki/{project}/{path}`, `bc://project/{key}/context` (the assembled cascade). Change subscriptions where practical.
- **Prompts**: reusable operations mirroring built-in agent flows: `decompose_task`, `summarise_sprint`, `triage_backlog`, parameterised.
- **Approvals**: high-impact tool calls return an "approval required" result with a pending-approval id instead of executing, so the external agent can surface it to its user.

---

## 11. GitHub Integration

- Per-user GitHub connection (OAuth token from SSO, or PAT in user settings).
- Link commits/PRs to tasks via `KEY-<n>` references in branch names, commit messages, or PR bodies.
- **Inbound webhooks** from GitHub: PR opened/merged events transition linked tasks (configurable mapping per project), signature-verified.
- Auto-close/transition on PR merge (configurable).

---

## 12. Wiki

- Per **project**, backed by a git repo. Org owners set the repo; **team admins set the branch/ref and path** the wiki reads from.
- Markdown rendering with **mermaid** and sanitised **SVG**; relative links and images resolved from the repo.
- **Edit through the UI**: edits commit back using the editing user's GitHub credentials, falling back to an org-configured bot token (required for Google-only users who have no GitHub link). Commit message auto-generated, user-overridable.
- Version history from git log; view any revision.
- Full-text searchable (§13).
- Wiki pages link to tasks (`KEY-<n>`) and tasks link to wiki pages.

---

## 13. Search

- Global full-text search (SQLite FTS5) across tasks (title, description, comments), wiki pages, and attachment filenames.
- Scoped by the caller's permissions.
- Quick-open command palette (keyboard-driven) for tasks, pages, and actions.

---

## 14. Reporting

- Per-sprint burndown/burnup.
- Cycle time / lead time per task; project-level distributions.
- Agent usage report: runs, tokens, estimated cost, actions taken, by agent/project/timeframe.
- CSV export of reports and filtered task lists.

---

## 15. User Settings

- Theme: dark / light / system.
- Timezone and locale (date formatting).
- GitHub integration (connect account / PAT).
- API keys (create, scope, revoke).
- Notification preferences.
- Active sessions (view, revoke).
- Account: data export (JSON) and account deletion (PII removed, authored content anonymised per org policy).

---

## 16. Responsive, Mobile & Accessibility

### Responsive & mobile

- Mobile-first, fluid layouts with defined breakpoints for phone / tablet / desktop.
- **Board on small screens**: single-column focus with horizontal swipe between columns and a sticky column header; tap a card to open the task as a sheet. Drag uses long-press; the card "move to" menu is the primary touch path.
- **Chat** collapses to a bottom-sheet / full-screen drawer.
- **Tables** (backlog, reports) reflow to stacked cards.
- **Bottom navigation** on mobile for Boards / Backlog / Chat / Search / Notifications.
- **Installable PWA**: manifest + icons + service worker caching the app shell and static assets (not data). Offline shows the cached shell with a reconnect notice; no offline writes in v1.

### Accessibility (target WCAG 2.2 AA)

- Full keyboard operation, including a keyboard equivalent for every drag (grab, move, drop via menu/shortcuts).
- ARIA semantics on columns and cards; live regions for realtime updates and toasts.
- Focus management in dialogs and sheets; visible focus rings.
- Colour is never the only signal (states/labels carry text or icons); contrast verified in both themes.
- Respects `prefers-reduced-motion` and `prefers-color-scheme`.

---

## 17. Security & Privacy

- **Tenant isolation**: all data access goes through a scoped data layer that requires an org context; a test/lint gate asserts no unscoped cross-tenant query. A single missing scope is a data leak, so this is enforced structurally, not by convention.
- **CSRF**: SameSite=Lax cookies plus a per-session token on all state-changing HTMX requests.
- **CSP**: strict, nonce-based; no un-nonced inline script; `frame-ancestors 'none'`.
- **Attachments**: served with `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`, ideally from a distinct origin; images validated/re-encoded; SVG sanitised (scripts and `foreignObject` stripped) before render.
- **Secrets** (provider keys, S3 creds, GitHub bot token, webhook secrets) encrypted at rest with `BC_SECRET_KEY`.
- **Org audit log**: security-relevant events (logins, role/permission changes, API key create/revoke, integration and agent config changes, member add/remove, high-impact agent actions) with actor, IP, timestamp; exportable; distinct from per-task activity.
- **Webhook/SSRF**: outbound URLs validated and internal ranges blocked.
- **Privacy**: per-user and per-org data export; account deletion.

---

## 18. Landing Page

- Static HTML (embedded, served at `/` for unauthenticated users) with dynamic over-the-top flair (CSS/JS animations, respecting reduced-motion), showcasing features with screenshots.
- Responsive and installable (shares the PWA manifest).
- OpenGraph/Twitter meta and favicon set for link previews and SEO.
- Links to app login and to `github.com/thomasteoh/boardchestrator`.

---

## 19. Infrastructure & Ops

- SQLite in WAL mode; single-writer discipline via the data layer.
- `/healthz` (liveness) and `/readyz` (readiness) endpoints.
- Prometheus `/metrics`.
- Structured JSON logs, level via `BC_LOG_LEVEL`.
- Backup: `bc backup` subcommand (online `VACUUM INTO`) plus documented volume-snapshot guidance. Restore documented.
- Schema kept portable (no SQLite-only exotica in the model) to keep a future PostgreSQL path open.
- Graceful shutdown; agent runs checkpointed or failed cleanly on stop.

### CI/CD (GitHub Actions)

| Event | Action |
|---|---|
| PR to `main` | Lint (golangci-lint, `templ generate` check, gofmt) |
| Push to `main` | Tests (`go test ./...`, race detector) |
| Tag `X.Y.Z-rc.N` | Dry-run container build (no push) |
| Tag `X.Y.Z` (pure semver) | Build container, push to ghcr.io, tagged `X.Y.Z` + `latest` |

---

## 20. Out of Scope (v1)

- Email notifications.
- Password auth, MFA, SAML.
- Data import from Jira/Linear/ADO.
- Nested task hierarchy (epics).
- Native mobile apps (the PWA covers mobile).
- Multi-node/HA deployment.
- Offline writes.

---

## 21. Build Phases

**Phase 0 — Foundation.** Repo scaffold, Go module, chi + templ + HTMX skeleton, responsive app shell + PWA manifest/service worker, SQLite + migrations + sqlc, session store, config loading, logging, healthz/readyz/metrics, CSP/CSRF baseline, action-registry skeleton, Dockerfile, CI workflows, landing page.

**Phase 1 — Identity & Tenancy.** Google/GitHub SSO, hardened first-user bootstrap, orgs/teams/projects CRUD, configurable roles + permission engine, membership & invites, org audit log, user settings (theme, timezone, sessions, API keys, data export/deletion).

**Phase 2 — Boards & Tasks.** Task model (flat + labels, keys, relations, custom fields, multi-assignee), board with configurable columns/swimlanes/WIP, drag-and-drop + touch/keyboard fallback, backlog view, sprints, saved filters, bulk ops, comments + @mentions, attachments (local volume, sanitised), activity timeline, in-app notifications + SSE, FTS search, task templates, recurring tasks, archive.

**Phase 3 — Agent Harness.** Action layer formalised as tool registry with impact classes and approval gates, providers (OpenAI-compatible + Codex SSO), platform agent templates + org allocation, skills hub (incl. external MCP endpoints), agent CRUD, run entities + job queue + retries + rate limits + spend caps, @mention and column-drop triggers, chat sidebar with streaming and approve/apply, run transcripts, context cascade, cost tracking.

**Phase 4 — API Surface.** REST API + OpenAPI, MCP server (tools/resources/prompts/approvals), API-key auth + rate limiting, outbound webhooks (retry/DLQ/SSRF guard), GitHub integration (links, inbound webhooks, transitions), scheduled agent triggers.

**Phase 5 — Wiki & Reporting.** Wiki (read, render, edit-commits, history, per-team ref config, bot-token fallback), sprint charts, cycle/lead time, agent usage dashboard, CSV export, S3 attachment backend, backup subcommand.

Each phase lands as PRs to `main` for review.
