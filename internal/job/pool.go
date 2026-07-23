// Package job provides a background worker pool for the job queue (WU-301).
// Workers claim queued jobs, execute the matching action handler, and record
// outcomes.
package job

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// JobStore wraps sqlc for job lifecycle operations.
type JobStore struct {
	q *sqlc.Queries
}

// NewJobStore creates a store backed by the given DB.
func NewJobStore(d *sql.DB) *JobStore {
	return &JobStore{q: sqlc.New(d)}
}

// Enqueue inserts a new job.
func (s *JobStore) Enqueue(ctx context.Context, id, kind, payload, runAt string, maxAttempts int64) error {
	return s.q.EnqueueJob(ctx, sqlc.EnqueueJobParams{
		ID:          id,
		Kind:        kind,
		PayloadJson: payload,
		RunAt:       runAt,
		MaxAttempts: maxAttempts,
	})
}

// Claim attempts to claim a queued job by ID. Returns the claimed job or
// ErrNotQueued if it was already taken.
func (s *JobStore) Claim(ctx context.Context, id, lockedBy, lockedAt string) (*sqlc.Job, error) {
	job, err := s.q.ClaimJob(ctx, sqlc.ClaimJobParams{
		ID:       id,
		LockedBy: sql.NullString{String: lockedBy, Valid: true},
		LockedAt: sql.NullString{String: lockedAt, Valid: true},
	})
	if err != nil {
		return nil, fmt.Errorf("claim: %w", err)
	}
	return &job, nil
}

// Complete marks a job as succeeded.
func (s *JobStore) Complete(ctx context.Context, id string) error {
	return s.q.MarkJobComplete(ctx, id)
}

// Fail marks a job as failed and optionally sets its next run_at for retry.
func (s *JobStore) Fail(ctx context.Context, id, status, runAt string, attempts int64) error {
	return s.q.MarkJobFailed(ctx, sqlc.MarkJobFailedParams{
		ID:       id,
		Status:   status,
		RunAt:    runAt,
		Attempts: attempts,
	})
}

// Dead marks a job as dead (max attempts exhausted).
func (s *JobStore) Dead(ctx context.Context, id string) error {
	return s.q.MarkJobDead(ctx, id)
}

// Requeue resets a job to queued state.
func (s *JobStore) Requeue(ctx context.Context, id string) error {
	return s.q.RequeueJob(ctx, id)
}

// ListQueued returns jobs that are due for processing.
func (s *JobStore) ListQueued(ctx context.Context) ([]sqlc.Job, error) {
	return s.q.ListQueuedJobs(ctx)
}

// ListDead returns all dead jobs.
func (s *JobStore) ListDead(ctx context.Context) ([]sqlc.Job, error) {
	return s.q.ListDeadJobs(ctx)
}

// QueueDepth returns per-status counts for queued+running+dead.
func (s *JobStore) QueueDepth(ctx context.Context) ([]sqlc.GetQueueDepthRow, error) {
	return s.q.GetQueueDepth(ctx)
}

// QueueOldestAge returns the run_at of the oldest queued job.
func (s *JobStore) QueueOldestAge(ctx context.Context) (string, error) {
	return s.q.GetQueueOldestAge(ctx)
}

// ErrNotQueued is returned when a job cannot be claimed because its status
// is not 'queued'.
var ErrNotQueued = errors.New("job: not queued — already claimed or cancelled")

// NoopHandler is a placeholder handler that does nothing. Used when the
// server starts but no action dispatcher has been wired yet (WU-104).
func NoopHandler(_ context.Context, _ sqlc.Job) error { return nil }

// JobHandler is a function that processes a single job.
type JobHandler func(ctx context.Context, job sqlc.Job) error

// Pool runs a configurable number of worker goroutines that poll the job
// queue and execute handlers.
type Pool struct {
	store        *JobStore
	handler      JobHandler
	maxWorkers   int
	pollInterval time.Duration
	claimTimeout time.Duration
	workerID     string

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// PoolConfig configures the worker pool.
type PoolConfig struct {
	Store        *JobStore
	Handler      JobHandler
	MaxWorkers   int
	PollInterval time.Duration
	ClaimTimeout time.Duration
}

// NewPool creates a started pool. Call Stop to shut down.
func NewPool(ctx context.Context, cfg PoolConfig) *Pool {
	ctx, cancel := context.WithCancel(ctx)
	p := &Pool{
		store:        cfg.Store,
		handler:      cfg.Handler,
		maxWorkers:   cfg.MaxWorkers,
		pollInterval: cfg.PollInterval,
		claimTimeout: cfg.ClaimTimeout,
		workerID:     fmt.Sprintf("pool-%d", time.Now().UnixNano()),
		ctx:          ctx,
		cancel:       cancel,
	}
	for i := 0; i < cfg.MaxWorkers; i++ {
		p.wg.Add(1)
		go p.worker(i)
	}
	return p
}

// Stop gracefully shuts down the pool, waiting for in-flight jobs.
func (p *Pool) Stop() {
	p.cancel()
	p.wg.Wait()
}

func (p *Pool) worker(id int) {
	defer p.wg.Done()
	workerName := fmt.Sprintf("%s-%d", p.workerID, id)

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-time.After(p.pollInterval):
		}

		jobs, err := p.store.ListQueued(p.ctx)
		if err != nil {
			slog.Error("job: list queued", "worker", workerName, "err", err)
			continue
		}
		if len(jobs) == 0 {
			continue
		}

		for _, job := range jobs {
			select {
			case <-p.ctx.Done():
				return
			default:
			}

			lockedAt := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
			lockedBy := fmt.Sprintf("%s/%s", workerName, job.ID)

			claimed, err := p.store.Claim(p.ctx, job.ID, lockedBy, lockedAt)
			if err != nil {
				// Job was already claimed or has a conflicting status — skip.
				continue
			}

			slog.Info("job: claim", "worker", workerName, "job", claimed.ID, "kind", claimed.Kind)

			if err := p.handler(p.ctx, *claimed); err != nil {
				slog.Error("job: handler failed", "worker", workerName, "job", claimed.ID, "err", err)

				// Handle retry logic: if attempts < max_attempts, fail with
				// retry; otherwise mark dead.
				nextAttempts := claimed.Attempts + 1
				if nextAttempts < claimed.MaxAttempts {
					runAt := time.Now().UTC().Add(30 * time.Second).Format("2006-01-02T15:04:05.000Z")
					_ = p.store.Fail(p.ctx, claimed.ID, "queued", runAt, nextAttempts)
				} else {
					_ = p.store.Dead(p.ctx, claimed.ID)
				}
				continue
			}

			if err := p.store.Complete(p.ctx, claimed.ID); err != nil {
				slog.Error("job: complete failed", "worker", workerName, "job", claimed.ID, "err", err)
			}
		}
	}
}
