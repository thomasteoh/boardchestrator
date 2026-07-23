# WU-301: Job Queue

Deps: WU-006 (action registry + dispatch, done in this branch).
SPEC §10, §5 (jobs table), §1 (architecture rules).
Branch: `wu-301/phase-1` (Phase 3 — Agent Harness).

## Acceptance Criteria (from BACKLOG)

- `jobs` migration (0003)
- claim/backoff/max-attempts per SPEC §10
- worker pool with graceful drain
- dead-job status + requeue action
- queue depth/age metrics
- claim contention test (n workers, no double-claim)
- backoff schedule test
- drain-on-shutdown test

## Step 1 — Migration 0003: `jobs` table

- `migrations/0003_jobs.up.sql`: create `jobs` table per SPEC §5 schema
- `migrations/0003_jobs.down.sql`: drop table
- Update `db_test.go` `migratedTables` to include "jobs"
- Verify: `make check` (migration up/down round-trip in dbtest)

```sql
jobs(
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  run_at TEXT NOT NULL DEFAULT (strftime(...)),
  attempts INT NOT NULL DEFAULT 0,
  max_attempts INT NOT NULL DEFAULT 3,
  status TEXT NOT NULL DEFAULT 'queued',
  locked_by TEXT,
  locked_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime(...))
)
```

Indexes: `idx_jobs_status_run_at` for polling, `idx_jobs_locked_by` for cleanup.

## Step 2 — sqlc queries

- `internal/db/queries/jobs.sql`
  - `EnqueueJob` — INSERT
  - `ListQueuedJobs` — SELECT status='queued' AND run_at <= now, ordered by run_at, limited
  - `ClaimJob` — UPDATE WHERE status='queued' AND run_at <= now AND id = ? RETURNING
  - `MarkJobComplete` — UPDATE status='succeeded'
  - `MarkJobFailed` — UPDATE status='failed', increment attempts, set backoff
  - `MarkJobDead` — UPDATE status='dead'
  - `RequeueJob` — UPDATE status='queued', reset attempts/lock
  - `ListDeadJobs` — SELECT status='dead'
  - `GetQueueDepth` — COUNT by status
  - `GetQueueAge` — MIN run_at for queued jobs
- `make gen` → sqlc output diff-clean
- Verify: `make check`

## Step 3 — Queue types and package skeleton

- `internal/agentrt/queue/queue.go`: types (Job, Status const), Queue struct
- Status constants: `queued`, `running`, `succeeded`, `failed`, `dead`
- `Queue` constructor: takes `*sql.DB`, creates sqlc Queries
- `Enqueue(kind, payload)` — generates id, inserts row
- Tests: enqueue + retrieval round-trip
- Verify: `make check`

## Step 4 — Claim logic (UPDATE...RETURNING, atomic)

- `Claim(ctx)` — UPDATE status='running' SET locked_by, locked_at WHERE status='queued' AND run_at <= now ORDER BY run_at ASC LIMIT 1 RETURNING *
- Returns the claimed Job or nil if nothing available
- `MarkComplete(jobID)` — set status='succeeded', clear lock
- `MarkFailed(jobID)` — increment attempts; if >= max_attempts, set status='dead'; else set backoff (status='queued' with future run_at)
- Tests: claim from empty queue returns nil; claim contention (2 workers on 1 job → only one wins)
- Verify: `make check`

## Step 5 — Backoff schedule (exponential with jitter)

- `CalculateBackoff(attempt, maxAttempts)` — exp backoff with random jitter (±25%)
- Used in `MarkFailed` to set `run_at`
- Test: backoff values across attempts 0→max show exponential growth; jitter stays within bounds
- Verify: `make check`

## Step 6 — Worker pool + graceful drain

- `WorkerPool` struct: N workers (configurable, default from `BC_AGENT_WORKERS`)
- Each worker: tick loop (sleep → Claim → Execute handler → MarkComplete/Failed)
- `HandleFunc` — worker receives this to execute jobs; passes Job to caller-defined logic
- `Stop(ctx)` — signals workers to drain: stop accepting new claims, finish in-flight jobs, exit
- `start(ctx)` — spawns workers
- Poll interval configurable (default 1s)
- Tests: N workers process jobs; graceful drain (stop during in-flight, completes before exit)
- Verify: `make check`

## Step 7 — Dead job status + requeue

- `MarkJobDead` already exists from step 4/5 logic
- `Requeue(jobID)` — reset to queued, attempts=0, clear lock
- `ListDead()` — returns dead jobs
- Tests: job exceeds max-attempts → dead; requeue restores to queued with attempts=0
- Verify: `make check`

## Step 8 — Prometheus metrics (queue depth/age)

- `bc_queue_depth{status}` — gauge, count by status
- `bc_queue_oldest_job_age_seconds` — gauge, age of oldest queued job (0 if empty)
- `bc_queue_claimed_total` — counter
- `bc_queue_dead_total` — counter
- `bc_queue_requeued_total` — counter
- Tests: metric values after enqueue/claim/complete
- Verify: `make check`

## Step 9 — Update BACKLOG.md, commit, push

- Mark WU-301 `done` in BACKLOG.md
- Final `make check`
- Commit `WU-301: job queue (migration, claim/backoff, worker pool, dead/requeue, metrics)`
- Push to `wu-301/phase-1`
