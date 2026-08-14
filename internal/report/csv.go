package report

import (
	"fmt"
	"strings"
)

// csvQuote wraps a field in double quotes if it contains a comma, quote, or
// newline, doubling embedded quotes per RFC 4180.
func csvQuote(s string) string {
	if strings.ContainsAny(s, ",\"\n") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

// CSVBurndown returns a CSV table of the burndown series (RFC 4180).
func CSVBurndown(b Burndown) string {
	var sb strings.Builder
	sb.WriteString("date,remaining,done,ideal\n")
	for i, d := range b.Days {
		rem := int64(0)
		if i < len(b.Remaining) {
			rem = b.Remaining[i]
		}
		done := int64(0)
		if i < len(b.Done) {
			done = b.Done[i]
		}
		ideal := int64(0)
		if i < len(b.Ideal) {
			ideal = b.Ideal[i]
		}
		fmt.Fprintf(&sb, "%s,%d,%d,%d\n", d, rem, done, ideal)
	}
	return sb.String()
}

// CSVFlow returns a one-row CSV of flow metrics.
func CSVFlow(m FlowMetric) string {
	return fmt.Sprintf("metric,value\nlead_avg_hours,%.1f\ncycle_avg_hours,%.1f\ndone_count,%d\n",
		m.LeadAvgHours, m.CycleAvgHours, m.DoneCount)
}

// CSVDistributions returns a CSV table of project distributions.
func CSVDistributions(dists []Distribution) string {
	var sb strings.Builder
	sb.WriteString("project,task_count,total_points,done_count\n")
	for _, d := range dists {
		fmt.Fprintf(&sb, "%s,%d,%d,%d\n", csvQuote(d.Project), d.TaskCount, d.TotalPts, d.DoneCount)
	}
	return sb.String()
}

// CSVTasks renders filtered tasks as CSV (report.csv).
func CSVTasks(tasks []CSVTaskRow) string {
	var sb strings.Builder
	sb.WriteString("key,title,status,points,priority,project_id,created_at,updated_at\n")
	for _, t := range tasks {
		fmt.Fprintf(&sb, "%s,%s,%s,%d,%d,%s,%s,%s\n",
			csvQuote(t.Key), csvQuote(t.Title), csvQuote(t.Status), t.Points, t.Priority, t.ProjectID, t.CreatedAt, t.UpdatedAt)
	}
	return sb.String()
}

// CSVTaskRow mirrors a filtered task row for CSV export.
type CSVTaskRow struct {
	Key       string
	Title     string
	Status    string
	Points    int64
	Priority  int64
	ProjectID string
	CreatedAt string
	UpdatedAt string
}
