// Package report computes sprint/flow metrics and renders SVG charts and CSV
// exports for WU-504 (Sprint & flow reports). All functions are pure: they
// consume sqlc rows and produce data, so they are unit-testable without a DB.
package report

import (
	"sort"
	"strings"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// Day is an ISO-8601 UTC date (YYYY-MM-DD).
type Day string

// Burndown is a sprint's daily open/done progression.
type Burndown struct {
	SprintID  string
	ProjectID string
	Days      []Day   // each sprint day from starts_on..today
	Remaining []int64 // remaining points per day (open)
	Done      []int64 // done points per day
	Ideal     []int64 // ideal remaining line (total → 0)
	Total     int64
}

// FlowMetric aggregates cycle/lead time over a project's activity history.
type FlowMetric struct {
	LeadAvgHours  float64 // create → first done
	CycleAvgHours float64 // first in-progress → first done
	DoneCount     int64
}

// Distribution is a per-project task/point tally in an org.
type Distribution struct {
	ProjectID string
	Project   string
	TaskCount int64
	TotalPts  int64
	DoneCount int64
}

// BuildBurndown turns a sprint's date range + snapshot/aggregate rows into a
// daily burndown series. snapshots may be empty (fresh sprint): the series is
// then derived from total only (remaining = total until today).
func BuildBurndown(sprintID, projectID string, startsOn, endsOn Day, total int64, snaps []sqlc.SprintSnapshot) Burndown {
	b := Burndown{SprintID: sprintID, ProjectID: projectID, Total: total}
	// Walk each calendar day in [startsOn, endsOn] clamped to today.
	start := parseDay(startsOn)
	end := parseDay(endsOn)
	if end.Before(start) {
		end = start
	}
	today := time.Now().UTC().Truncate(24 * time.Hour)
	if end.After(today) {
		end = today
	}
	// Snapshot lookup by day.
	byDay := map[string]sqlc.SprintSnapshot{}
	for _, s := range snaps {
		byDay[s.TakenOn] = s
	}
	remaining := total
	done := int64(0)
	for d := start; !d.After(end); d = d.AddDate(0, 0, 1) {
		ds := d.Format("2006-01-02")
		day := Day(ds)
		// Reconstruct from the latest snapshot on/before this day: remaining is
		// monotonic (total - done) and done carries forward across days.
		if s, ok := byDay[ds]; ok {
			remaining = s.TotalPoints - s.DonePoints
			done = s.DonePoints
		}
		b.Days = append(b.Days, day)
		b.Remaining = append(b.Remaining, remaining)
		b.Done = append(b.Done, done)
	}
	// Ideal line: linear descent from total to 0 across the sprint length.
	n := len(b.Days)
	if n > 1 {
		ideal := make([]int64, n)
		for i := 0; i < n; i++ {
			ideal[i] = total - total*int64(i)/(int64(n-1))
		}
		b.Ideal = ideal
	} else {
		b.Ideal = []int64{total}
	}
	return b
}

// FlowMetrics computes average lead/cycle time (hours) from a project's
// activity history. doneStatus is the column status treated as terminal.
func FlowMetrics(rows []sqlc.ListProjectTaskActivityRow, doneStatus string) FlowMetric {
	// Group activity by task.
	type taskEvents struct {
		createAt   time.Time
		firstDoing time.Time
		doneAt     time.Time
	}
	byTask := map[string]*taskEvents{}
	order := []string{}
	for _, r := range rows {
		t, ok := byTask[r.TaskID]
		if !ok {
			t = &taskEvents{}
			byTask[r.TaskID] = t
			order = append(order, r.TaskID)
		}
		at := parseTime(r.CreatedAt)
		switch r.Action {
		case "task.create":
			t.createAt = at
		case "task.move":
			var to string
			// detail_json holds to_status for task.move.
			to = detailStatus(r.DetailJson)
			if to == doneStatus {
				if t.doneAt.IsZero() {
					t.doneAt = at
				}
			} else if to != "" && to != "backlog" {
				if t.firstDoing.IsZero() {
					t.firstDoing = at
				}
			}
		}
	}
	var leadSum, cycleSum float64
	var leadN, cycleN, done int64
	for _, id := range order {
		t := byTask[id]
		if !t.doneAt.IsZero() {
			done++
			if !t.createAt.IsZero() {
				leadSum += t.doneAt.Sub(t.createAt).Hours()
				leadN++
			}
			if !t.firstDoing.IsZero() {
				cycleSum += t.doneAt.Sub(t.firstDoing).Hours()
				cycleN++
			}
		}
	}
	m := FlowMetric{DoneCount: done}
	if leadN > 0 {
		m.LeadAvgHours = leadSum / float64(leadN)
	}
	if cycleN > 0 {
		m.CycleAvgHours = cycleSum / float64(cycleN)
	}
	return m
}

// BuildDistributions turns project-distribution rows into a sorted list.
func BuildDistributions(rows []sqlc.ProjectDistributionsRow) []Distribution {
	out := make([]Distribution, 0, len(rows))
	for _, r := range rows {
		out = append(out, Distribution{
			ProjectID: r.ProjectID,
			Project:   r.Name,
			TaskCount: r.TaskCount,
			TotalPts:  Int64(r.TotalPoints),
			DoneCount: Int64(r.DoneCount),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TaskCount != out[j].TaskCount {
			return out[i].TaskCount > out[j].TaskCount
		}
		return out[i].Project < out[j].Project
	})
	return out
}

// Int64 coerces an sqlc SUM aggregate (interface{} or int64) to int64.
func Int64(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case int:
		return int64(x)
	case float64:
		return int64(x)
	case nil:
		return 0
	}
	return 0
}

func parseDay(d Day) time.Time {
	t, err := time.Parse("2006-01-02", string(d))
	if err != nil {
		return time.Now().UTC().Truncate(24 * time.Hour)
	}
	return t
}

func parseTime(s string) time.Time {
	for _, layout := range []string{
		"2006-01-02T15:04:05.000Z",
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
	} {
		t, err := time.Parse(layout, s)
		if err == nil {
			return t
		}
	}
	return time.Time{}
}

// detailStatus extracts to_status from a task.move detail_json (or "").
func detailStatus(detail string) string {
	// detail_json: {"to_status":"done","sort_order":0}
	idx := strings.Index(detail, `"to_status":"`)
	if idx < 0 {
		return ""
	}
	rest := detail[idx+len(`"to_status":"`):]
	if end := strings.IndexByte(rest, '"'); end >= 0 {
		return rest[:end]
	}
	return ""
}
