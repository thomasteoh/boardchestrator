# WU-104 — Orgs, teams, projects

## Context
Boardchestrator Go project. Main repo: ~/projects/boardchestrator.
Worktree: this directory (wu-104).
Branch: wu-104/phase-1, based on build-phase-1.

## What's already done in this worktree
- Migration 0004 (`migrations/0004_orgs.up/down.sql`) — orgs, org_secrets, teams, projects, roles, memberships tables
- sqlc queries (`internal/db/queries/orgs.sql`) — CRUD for all entities
- Generated sqlc models + queries (`internal/db/sqlc/orgs.sql.go`, models.go updated)
- Action input structs started in `internal/action/orgs.go` (orgCreateInput, orgUpdateInput, teamCreateInput, teamUpdateInput, projectCreateInput, projectUpdateInput)
- Server dispatcher wired in `internal/server/server.go` (disp *action.Dispatcher, created in Start with DBScopeResolver + EventSink)
- check-scope.sh updated with TENANT_TABLES
- db_test.go updated with new table names
- Untracked: .dockerignore, public/favicon.ico (ignore these)

## What remains

### 1. Action handlers in `internal/action/orgs.go`
Complete the action handlers for:
- `org.create` — validate slug uniqueness, create org
- `org.update` — update name/context/visibility
- `team.create` — validate slug unique per org, create team
- `team.update` — update name/context/visibility
- `project.create` — validate KEY format `^[A-Z][A-Z0-9]{1,9}$`, check key uniqueness per org, set next_task_num=1
- `project.update` — update name/context/visibility
- `project.archive` / `project.unarchive`

Each handler needs:
- Input type with JSON tags (already have structs, add `project.archive`/`project.unarchive` input types)
- Schema validation (required fields, slug format, KEY regex)
- Handle function that uses sqlc queries from `internal/db/sqlc` via `action.Queries`
- Register each action in an `init()` or exported `RegisterOrgActions(reg)` function

### 2. Register actions on dispatcher
Wire `RegisterOrgActions` into `cmd/bc/serve.go` where the dispatcher is created, so actions are registered at startup.

### 3. Org secrets helpers
Add encrypt/decrypt helpers for `org_secrets` (AES-GCM with BC_SESSION_SECRET-derived key, or similar). Store and retrieve encrypted secrets.

### 4. Tests
- Action tests: happy path create, duplicate slug/key rejection, archive flow
- Secrets round-trip encrypt/decrypt test
- check-scope covers new tables (already updated, verify it passes)

## Acceptance criteria
- `make check` green
- `go test -race ./internal/action/...` covers all new action handlers
- check-scope passes

## Progress recording
Update BACKLOG.md in this worktree after each meaningful step. Mark WU-104 as `in-progress` at the start. When done, set to `done <date> <commit-subject>`. Commit messages: `WU-104: <summary>`.

## Files to read for context
- PRD.md, SPEC.md, BACKLOG.md, WORKER.md
- internal/action/ (existing action definitions, dispatch.go, action.go for patterns)
- internal/db/sqlc/orgs.sql.go (generated queries)
- internal/action/orgs.go (partial work)
- cmd/bc/serve.go (server wiring)
- internal/config/config.go (for secrets key derivation pattern)
