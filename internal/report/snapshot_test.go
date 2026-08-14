package report

import (
	"context"
	"database/sql"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

func TestRunSprintSnapshotIdempotent(t *testing.T) {
	ctx := context.Background()
	db := dbtest.New(t)

	oid := "org000000000000000000000000001"
	mustExec(t, db, `INSERT INTO orgs (id, name, slug, context, visibility) VALUES (?, 'O', 'o', '', 'private')`, oid)
	pid := "proj00000000000000000000000001"
	mustExec(t, db, `INSERT INTO projects (id, org_id, name, key, context, visibility) VALUES (?, ?, 'P', 'p', '', 'private')`, pid, oid)
	spid := "spr000000000000000000000000001"
	mustExec(t, db, `INSERT INTO sprints (id, org_id, project_id, name, starts_on, ends_on, state) VALUES (?, ?, ?, 'S1', '2026-01-01', '2026-01-14', 'active')`, spid, oid, pid)

	// 2 done tasks (3 pts each) + 1 open task (5 pts).
	mustExec(t, db, `INSERT INTO tasks (id, project_id, key, title, status, points, sprint_id) VALUES (?, ?, 'D-1', 'done1', 'done', 3, ?)`, "task-d1", pid, spid)
	mustExec(t, db, `INSERT INTO tasks (id, project_id, key, title, status, points, sprint_id) VALUES (?, ?, 'D-2', 'done2', 'done', 3, ?)`, "task-d2", pid, spid)
	mustExec(t, db, `INSERT INTO tasks (id, project_id, key, title, status, points, sprint_id) VALUES (?, ?, 'O-1', 'open1', 'todo', 5, ?)`, "task-o1", pid, spid)

	q := sqlc.New(db)
	// Run twice on the same UTC day: must be idempotent (one row).
	if err := RunSprintSnapshot(ctx, db, spid); err != nil {
		t.Fatalf("snapshot 1: %v", err)
	}
	if err := RunSprintSnapshot(ctx, db, spid); err != nil {
		t.Fatalf("snapshot 2: %v", err)
	}
	snaps, err := q.ListSprintSnapshots(ctx, spid)
	if err != nil {
		t.Fatalf("list snapshots: %v", err)
	}
	if len(snaps) != 1 {
		t.Fatalf("snapshot rows = %d, want 1 (idempotent)", len(snaps))
	}
	if snaps[0].DonePoints != 6 || snaps[0].DoneCount != 2 {
		t.Errorf("done = %d/%d, want 6/2", snaps[0].DonePoints, snaps[0].DoneCount)
	}
	if snaps[0].OpenCount != 1 {
		t.Errorf("open_count = %d, want 1", snaps[0].OpenCount)
	}
	if snaps[0].TotalPoints != 11 {
		t.Errorf("total = %d, want 11", snaps[0].TotalPoints)
	}
}

func mustExec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}
