package report

import (
	"strings"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

func TestBuildBurndownGolden(t *testing.T) {
	// Sprint of 5 days, total 10 points. Snapshots on day 2 (3 done) and day 4
	// (6 done) reconstruct remaining as total-done.
	snaps := []sqlc.SprintSnapshot{
		{ID: "s1:d2", SprintID: "s1", ProjectID: "p1", TakenOn: "2026-08-11", TotalPoints: 10, DonePoints: 3},
		{ID: "s1:d4", SprintID: "s1", ProjectID: "p1", TakenOn: "2026-08-13", TotalPoints: 10, DonePoints: 6},
	}
	b := BuildBurndown("s1", "p1", Day("2026-08-10"), Day("2026-08-14"), 10, snaps)
	if len(b.Days) != 5 {
		t.Fatalf("days = %d, want 5", len(b.Days))
	}
	wantRem := []int64{10, 7, 7, 4, 4} // total on day1, then done-deducted
	for i, want := range wantRem {
		if b.Remaining[i] != want {
			t.Errorf("remaining[%d] = %d, want %d", i, b.Remaining[i], want)
		}
	}
	wantDone := []int64{0, 3, 3, 6, 6}
	for i, want := range wantDone {
		if b.Done[i] != want {
			t.Errorf("done[%d] = %d, want %d", i, b.Done[i], want)
		}
	}
	if b.Ideal[0] != 10 || b.Ideal[4] != 0 {
		t.Errorf("ideal endpoints = %d..%d, want 10..0", b.Ideal[0], b.Ideal[4])
	}
}

func TestFlowMetricsGolden(t *testing.T) {
	rows := []sqlc.ListProjectTaskActivityRow{
		{TaskID: "t1", Action: "task.create", CreatedAt: "2026-08-01T08:00:00Z"},
		{TaskID: "t1", Action: "task.move", DetailJson: `{"to_status":"doing"}`, CreatedAt: "2026-08-02T10:00:00Z"},
		{TaskID: "t1", Action: "task.move", DetailJson: `{"to_status":"done"}`, CreatedAt: "2026-08-04T16:00:00Z"},
		{TaskID: "t2", Action: "task.create", CreatedAt: "2026-08-01T09:00:00Z"},
		{TaskID: "t2", Action: "task.move", DetailJson: `{"to_status":"done"}`, CreatedAt: "2026-08-02T11:00:00Z"},
	}
	m := FlowMetrics(rows, "done")
	if m.DoneCount != 2 {
		t.Fatalf("done_count = %d, want 2", m.DoneCount)
	}
	// t1 lead = 08-01 08:00 → 08-04 16:00 = 3d8h = 80h; t2 lead = 08-01 09:00 → 08-02 11:00 = 1d2h = 26h.
	// avg = (80+26)/2 = 53h.
	if want := 53.0; m.LeadAvgHours != want {
		t.Errorf("lead_avg = %.2f, want %.1f", m.LeadAvgHours, want)
	}
	// t1 cycle = 2d6h (08-02 10:00 → 08-04 16:00) = 54h; t2 cycle = 0 (no doing).
	// avg = 54h.
	if want := 54.0; m.CycleAvgHours != want {
		t.Errorf("cycle_avg = %.2f, want %.1f", m.CycleAvgHours, want)
	}
}

func TestBuildDistributionsGolden(t *testing.T) {
	rows := []sqlc.ProjectDistributionsRow{
		{ProjectID: "p2", Name: "b", TaskCount: 3, TotalPoints: 9, DoneCount: 1},
		{ProjectID: "p1", Name: "a", TaskCount: 5, TotalPoints: 12, DoneCount: 2},
	}
	d := BuildDistributions(rows)
	if len(d) != 2 {
		t.Fatalf("len = %d, want 2", len(d))
	}
	if d[0].Project != "a" || d[0].TaskCount != 5 {
		t.Errorf("first = %s/%d, want a/5", d[0].Project, d[0].TaskCount)
	}
	if d[1].Project != "b" {
		t.Errorf("second = %s, want b", d[1].Project)
	}
}

func TestCSVGoldens(t *testing.T) {
	b := Burndown{SprintID: "s1", ProjectID: "p1",
		Days: []Day{"2026-08-10", "2026-08-11"}, Remaining: []int64{10, 7}, Done: []int64{0, 3}, Ideal: []int64{10, 5}, Total: 10}
	wantB := "date,remaining,done,ideal\n2026-08-10,10,0,10\n2026-08-11,7,3,5\n"
	if got := CSVBurndown(b); got != wantB {
		t.Errorf("CSVBurndown:\n%q\nwant:\n%q", got, wantB)
	}
	m := FlowMetric{LeadAvgHours: 57.0, CycleAvgHours: 54.0, DoneCount: 2}
	wantF := "metric,value\nlead_avg_hours,57.0\ncycle_avg_hours,54.0\ndone_count,2\n"
	if got := CSVFlow(m); got != wantF {
		t.Errorf("CSVFlow:\n%q\nwant:\n%q", got, wantF)
	}
	dists := []Distribution{{Project: "a,b", TaskCount: 5, TotalPts: 12, DoneCount: 2}}
	wantD := "project,task_count,total_points,done_count\n\"a,b\",5,12,2\n"
	if got := CSVDistributions(dists); got != wantD {
		t.Errorf("CSVDistributions:\n%q\nwant:\n%q", got, wantD)
	}
	tasks := []CSVTaskRow{{Key: "A-1", Title: "hello, world", Status: "done", Points: 3, Priority: 1, ProjectID: "p1", CreatedAt: "c", UpdatedAt: "u"}}
	wantT := "key,title,status,points,priority,project_id,created_at,updated_at\nA-1,\"hello, world\",done,3,1,p1,c,u\n"
	if got := CSVTasks(tasks); got != wantT {
		t.Errorf("CSVTasks:\n%q\nwant:\n%q", got, wantT)
	}
}

func TestCSVQuote(t *testing.T) {
	if got := csvQuote(`he said "hi"`); got != `"he said ""hi"""` {
		t.Errorf("csvQuote = %q", got)
	}
	if got := csvQuote("plain"); got != "plain" {
		t.Errorf("csvQuote(plain) = %q", got)
	}
}

var _ = strings.Contains
