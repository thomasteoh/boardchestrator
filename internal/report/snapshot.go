package report

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// RunSprintSnapshot takes a daily snapshot of an active sprint's task totals
// (WU-504 AC1). It is idempotent per (sprint_id, taken_on): re-running on the
// same UTC day updates the same row instead of inserting a duplicate.
func RunSprintSnapshot(ctx context.Context, db *sql.DB, sprintID string) error {
	q := sqlc.New(db)
	s, err := q.FindSprintByID(ctx, sprintID)
	if err != nil {
		return fmt.Errorf("snapshot: find sprint %s: %w", sprintID, err)
	}
	totals, err := q.SprintTaskTotals(ctx, sqlc.SprintTaskTotalsParams{
		SprintID:  sql.NullString{String: sprintID, Valid: true},
		ProjectID: s.ProjectID,
	})
	if err != nil {
		return fmt.Errorf("snapshot: totals %s: %w", sprintID, err)
	}
	taken := time.Now().UTC().Format("2006-01-02")
	open := totals.TotalCount - Int64(totals.DoneCount)
	if open < 0 {
		open = 0
	}
	_, err = q.UpsertSprintSnapshot(ctx, sqlc.UpsertSprintSnapshotParams{
		ID:          sprintID + ":" + taken,
		SprintID:    sprintID,
		ProjectID:   s.ProjectID,
		OrgID:       s.OrgID,
		TakenOn:     taken,
		TotalPoints: Int64(totals.TotalPoints),
		DonePoints:  Int64(totals.DonePoints),
		OpenCount:   open,
		DoneCount:   Int64(totals.DoneCount),
	})
	if err != nil {
		return fmt.Errorf("snapshot: upsert %s: %w", sprintID, err)
	}
	return nil
}
