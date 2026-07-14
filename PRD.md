# Boardchestrator — Product Requirements Document

**Repo:** `github.com/thomasteoh/boardchestrator`
**Status:** Draft for review
**Last updated:** 2026-07-14

Boardchestrator is a self-hostable, agent-native project management platform. It provides a fully customisable board interface (agile-like defaults, simplified Azure DevOps functionality) where AI agents are first-class actors alongside humans. The web UI, the MCP server, and agents themselves are all clients of one internal action layer with one permission model.

This document governs scope. Anything not in here is out of scope until added here.

---

## 1. Core Principles

1. **Agent-native.** Every action a human can take (create task, invite user, configure a team) is expressible as an internal action that an agent can also invoke, subject to scoped permissions. The web UI and the MCP server are thin clients over this action layer.
2. **Single binary, single container.** Go binary with embedded templates and static assets, SQLite backend, runs in one container with a data volume.
3. **Configuration cascades.** Platform → Organisation → Team → Project. Context, agent availability, and settings flow downward; lower levels can extend or override where permitted.
4. **Shared multi-tenancy.** One SQLite database, tenant scoping via organisation ID columns enforced in the data layer.

---

## 2. Tech Stack

| Concern | Choice |
|---|---|
| Language | Go (latest stable) |
| HTTP router | chi |
| Templates | templ |
| Frontend interactivity | HTMX + Alpine.js |
| Drag and drop | SortableJS |
| Realtime | Server-Sent Events (SSE) |
| Database | SQLite (WAL mode), `modernc.org/sqlite` (pure Go, no CGO) |
| Migrations | golang-migrate, embedded, run on startup |
| Query layer | sqlc |
| Markdown | goldmark (+ mermaid client-side render, sanitised SVG rendering) |
| Git operations (wiki) | go-git |
| Sessions | Secure cookie sessions, server-side session store in SQLite |
| Logging | slog, structured JSON, level via env |
| Metrics | Prometheus `/metrics` |
| Container | Distroless or alpine base, published to ghcr.io |

All frontend libraries vendored/embedded; no CDN dependencies at runtime.

### Configuration

12-factor: all config via environment variables (`BC_` prefix). Key vars: `BC_DB_PATH`, `BC_DATA_DIR` (attachments, wiki checkouts), `BC_BASE_URL`, `BC_GOOGLE_CLIENT_ID/SECRET`, `BC_GITHUB_CLIENT_ID/SECRET`, `BC_SESSION_SECRET`, `BC_LOG_LEVEL`.

---

## 3. Identity & Auth

- **SSO only**: Google OIDC and GitHub OAuth. No passwords, no separate MFA; identity provider handles auth strength.
- Account linking: same verified email across providers maps to one user.
- **First user to log in becomes Platform Admin.**
- Session management: users can view and revoke their active sessions.
- **API keys**: users generate personal API keys (scoped, revocable, hashed at rest) for the REST API and MCP server. Agents get their own service credentials internally.

---

## 4. Tenancy & RBAC

### Hierarchy

**Platform** → **Organisation** → **Team** → **Project**

- Platform Admin: manages platform settings, platform-wide agent templates, and organisation creation.
- Each level has configurable **context** (freeform markdown) injected into agent prompts, concatenated top-down.

### Roles

Roles are **configurable**: a role is a named set of permission grants. Permissions are fine-grained verbs on resource types (e.g. `task.create`, `task.move`, `member.invite`, `agent.configure`, `wiki.edit`, `org.settings`). Ship with generic defaults:

| Role | Summary |
|---|---|
| Org Owner | Everything in the org, incl. integrations, agents, roles |
| Team Admin | Manage team, its projects, boards, wiki config |
| Member | Create/edit tasks, comment, use agents |
| Viewer | Read-only |
| Guest | Read + comment on explicitly shared projects |

- Roles assigned per org, overridable per team/project.
- Project visibility: org-wide, team-only, private.
- **Agents hold roles too.** An agent's effective permissions = its assigned role ∩ its attached skills' allowed actions. Same enforcement path as humans.

### Membership

- Invite by email; invitee completes signup via SSO.
- Agents can invite/manage members if their permissions allow it.

---

## 5. Boards & Tasks

### Structure

- **Flat task hierarchy + labels.** No epic/story nesting. Labels are org-scoped, coloured, filterable.
- Task relationships: `blocks` / `blocked-by`, `relates-to`, `duplicates`.
- Fields: title, description (markdown), state, multiple **assignees**, labels, story points, sprint, priority, due date, watchers, custom fields (per-project definitions: text, number, select, date, checkbox).

### Boards

- Fully configurable columns (name, colour, WIP limit, mapped task state) with agile-like defaults (Backlog / To Do / In Progress / Review / Done).
- Optional swimlanes (by assignee, label, or custom field).
- Drag-and-drop between columns and within column ordering (SortableJS + HTMX patch).
- Column-level move permissions (e.g. only certain roles can move to Done).
- **Column agent triggers**: dropping a task into a configured column fires a configured agent with a configured prompt template (see §7).

### Views

- Board view and backlog view (ordered flat list) per project.
- Saved filters (assignee, label, sprint, state, text) shareable within a team.
- Bulk operations: multi-select then assign / label / move / sprint.
- Archive for closed tasks and projects.

### Sprints

- Per-project sprints: name, date range; assign tasks in/out; active sprint board filter.

### Task detail

- Comments (markdown, @mention users and agents).
- **Agent thread**: prompts and responses of agent runs stored on the task, rendered distinctly from human comments.
- Activity timeline: every field change, move, assignment with actor (human or agent) and timestamp.
- Attachments: images and documents; inline image preview; size/type limits configurable per org.
- Task templates per project.
- Recurring tasks (schedule spawns a fresh copy).

### Attachments storage

- Default: local volume under `BC_DATA_DIR`.
- Org-configurable S3-compatible backend (endpoint, bucket, credentials). Storage abstraction from day one so backends are pluggable.

---

## 6. Notifications

- **In-app notification centre** only (no email): assigned, @mentioned, task state changed on watched tasks, agent run finished/failed.
- Per-user preferences: toggle each trigger type.
- Realtime delivery via SSE; unread badge.
- **Outbound webhooks** (org/team level) on task events for external automation, HMAC-signed.

---

## 7. Agent Harness

### Providers

- Configured by **Platform Admin**: model providers are either **Codex SSO** (OAuth to OpenAI/ChatGPT account) or any **OpenAI-compatible API** (base URL + key + model list).
- Org owners select from providers made available to their org.

### Agents

- **Platform-wide agent templates** defined by Platform Admin, allocated to organisations. Orgs customise allocated agents: skills, additional context, name.
- Org-defined agents also supported.
- Each agent has a **unique @-mentionable name** within its org.
- Agent config: provider/model, system context, attached skills, role (permissions), retry policy (max retries configurable, backoff), rate limits (runs/hour, token budget).

### Skills Hub

- A **skill** = versioned definition: name, description, instructions (markdown), and the set of **allowed actions** it grants (task.create, member.invite, etc.), plus optional parameter schema. Similar model to pi agent skills.
- Skills can be created in-app, imported (JSON/markdown bundle), and attached to agents.
- Skill library scoped: platform skills (allocatable) and org skills.
- An agent can only perform actions granted by role ∩ attached skills.

### Triggers

1. **@mention in a task** (description or comment): agent is prompted to action work within that task.
2. **Column drop**: task dragged into a configured column triggers a configured agent with a configurable prompt (e.g. "review this task and comment findings").
3. **Chat sidebar**: conversational interface; user asks the model to create projects/tasks, decompose a task into subtasks, make updates. Agent proposes/executes actions via the action layer.
4. **Scheduled**: cron-style per-project triggers (e.g. weekly summary of open tasks).

### Execution

- Agent runs execute in-process with a job queue (SQLite-backed), bounded concurrency.
- **Context assembly**: platform context + org context + team context + project context + skill instructions + task content (title, description, comments, attachments metadata, relations).
- Tool loop: model is given the action layer as tools; each call is permission-checked and recorded.
- Full run transcript (prompts, tool calls, responses, token counts) stored against the task (or chat session).
- Failure handling: retry per policy, then mark run failed and notify the triggering user.
- **Cost visibility**: per-run token usage recorded; org dashboard aggregates tokens/cost per agent and project.

---

## 8. Chat Sidebar

- Persistent sidebar in the app; conversation scoped to the current project (with option to widen to team/org for permitted users).
- Streams responses (SSE).
- Actions taken by the agent are rendered as structured cards (e.g. "Created task #142") with links.
- Chat history persisted per user per scope.

---

## 9. REST API & MCP Server

- **REST API** (`/api/v1`): full CRUD over orgs, teams, projects, tasks, comments, labels, sprints, attachments, agents, skills — the same action layer the UI uses. Auth via API key (Bearer). OpenAPI spec generated and served.
- **MCP server**: exposed over HTTP (streamable) from the same binary, tools mapping to the action layer, authenticated by user API keys. External agents (Claude Code, etc.) can manage boards through it.
- Rate limiting per API key.

---

## 10. GitHub Integration

- Per-user GitHub connection (OAuth token from SSO or PAT in user settings).
- Link commits/PRs to tasks via `BC-<id>` references in branch names / commit messages / PR bodies.
- **Inbound webhooks** from GitHub: PR opened/merged events can transition linked tasks (configurable mapping per project).
- Auto-close/transition task on PR merge (configurable).

---

## 11. Wiki

- Per **project**, backed by a git repo; **org owners set the repo, team admins set branch/ref and path** the wiki reads from.
- Markdown rendering with **mermaid** diagrams and sanitised **SVG** image rendering; relative links and images resolved from the repo.
- **Edit through the UI**: edits commit back to the configured repo/branch using the editing user's GitHub credentials (falls back to an org-configured bot token). Commit message auto-generated, user-overridable.
- Version history from git log; view any revision.
- Full-text searchable (see §12).
- Wiki pages can link to tasks (`#123`) and tasks can link to wiki pages.

---

## 12. Search

- Global full-text search (SQLite FTS5) across tasks (title, description, comments), wiki pages, and attachment filenames.
- Scoped by the caller's permissions.
- Quick-open palette (keyboard-driven) for tasks and pages.

---

## 13. Reporting

- Per-sprint burndown/burnup.
- Cycle time / lead time per task; project-level distributions.
- Agent usage report: runs, tokens, estimated cost, actions taken, by agent/project/timeframe.

---

## 14. User Settings

- Theme: dark / light / system.
- GitHub integration (connect account / PAT).
- API keys (create, scope, revoke).
- Notification preferences.
- Active sessions (view, revoke).

---

## 15. Landing Page

- Static HTML (embedded, served at `/` for unauthenticated users) with dynamic over-the-top flair (CSS/JS animations), showcasing features with screenshots.
- Links to app login and to `github.com/thomasteoh/boardchestrator`.

---

## 16. Infrastructure & Ops

- SQLite in WAL mode; single writer discipline via the data layer.
- `/healthz` (liveness) and `/readyz` endpoints.
- Prometheus `/metrics`.
- Structured JSON logs, level via `BC_LOG_LEVEL`.
- Backup: `bc backup` subcommand (online `VACUUM INTO`), plus documented volume snapshot guidance. Restore documented.
- Schema kept portable (no SQLite-only exotica in the model) to keep a future PostgreSQL path open.
- Graceful shutdown; agent runs checkpointed/failed cleanly on stop.

### CI/CD (GitHub Actions)

| Event | Action |
|---|---|
| PR to `main` | Lint (golangci-lint, templ generate check, gofmt) |
| Push to `main` | Tests (`go test ./...`, race detector) |
| Tag `X.Y.Z-rc.N` | Dry-run container build (no push) |
| Tag `X.Y.Z` (pure semver) | Build container, push to ghcr.io, tagged `X.Y.Z` + `latest` |

---

## 17. Out of Scope (v1)

- Email notifications.
- Password auth, MFA, SAML.
- Data import from Jira/Linear/ADO.
- Nested task hierarchy (epics).
- Mobile apps.
- Multi-node/HA deployment.

---

## 18. Build Phases

**Phase 0 — Foundation.** Repo scaffold, Go module, chi + templ + HTMX skeleton, SQLite + migrations + sqlc, session store, config loading, logging, healthz/metrics, Dockerfile, CI workflows, landing page.

**Phase 1 — Identity & Tenancy.** Google/GitHub SSO, first-user platform admin bootstrap, orgs/teams/projects CRUD, configurable roles + permission engine, membership & invites, user settings (theme, sessions, API keys).

**Phase 2 — Boards & Tasks.** Task model (flat + labels, relations, custom fields, multi-assignee), board with configurable columns/swimlanes/WIP, drag-and-drop, backlog view, sprints, saved filters, bulk ops, comments + @mentions, attachments (local volume), activity timeline, in-app notifications + SSE, FTS search, task templates, recurring tasks, archive.

**Phase 3 — Agent Harness.** Action layer formalised as tool registry, providers (OpenAI-compatible + Codex SSO), platform agent templates + org allocation, skills hub, agent CRUD, job queue + retries + rate limits, @mention trigger, column-drop trigger, chat sidebar with streaming, run transcripts on tasks, context cascade, cost tracking.

**Phase 4 — API Surface.** REST API + OpenAPI, MCP server, API key auth + rate limiting, outbound webhooks, GitHub integration (links, inbound webhooks, transitions), scheduled agent triggers.

**Phase 5 — Wiki & Reporting.** Wiki (read, render, edit-commits, history, per-team ref config), sprint charts, cycle/lead time, agent usage dashboard, S3 attachment backend, backup subcommand.

Each phase lands as PRs to `main` for review.
