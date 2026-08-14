package action

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/report"
)

// reportBurndownInput selects a sprint for a burndown report.
type reportBurndownInput struct {
	SprintID  string `json:"sprint_id"`
	ProjectID string `json:"project_id"`
}

// reportFlowInput selects a project for flow (cycle/lead) metrics.
type reportFlowInput struct {
	ProjectID  string `json:"project_id"`
	DoneStatus string `json:"done_status"` // column status treated as done
}

// reportDistributionsInput selects an org for project distributions.
type reportDistributionsInput struct {
	OrgID string `json:"org_id"`
}

// reportCSVInput selects a project + optional status filter for CSV export.
type reportCSVInput struct {
	ProjectID string `json:"project_id"`
	Status    string `json:"status"`
}

func init() {
	Register(Definition{
		Name:       "report.burndown",
		Impact:     ImpactRead,
		Permission: "report.read",
		Scope:      ScopeProject,
		Input: ObjectSchema{Fields: []Field{
			{Name: "sprint_id", Kind: KindString, Required: true},
			{Name: "project_id", Kind: KindString, Required: true},
		}},
		Handle: handleReportBurndown,
	})
	Register(Definition{
		Name:       "report.flow",
		Impact:     ImpactRead,
		Permission: "report.read",
		Scope:      ScopeProject,
		Input: ObjectSchema{Fields: []Field{
			{Name: "project_id", Kind: KindString, Required: true},
			{Name: "done_status", Kind: KindString, Required: false},
		}},
		Handle: handleReportFlow,
	})
	Register(Definition{
		Name:       "report.distributions",
		Impact:     ImpactRead,
		Permission: "report.read",
		Scope:      ScopeOrg,
		Input: ObjectSchema{Fields: []Field{
			{Name: "org_id", Kind: KindString, Required: true},
		}},
		Handle: handleReportDistributions,
	})
	Register(Definition{
		Name:       "report.csv",
		Impact:     ImpactRead,
		Permission: "report.read",
		Scope:      ScopeProject,
		Input: ObjectSchema{Fields: []Field{
			{Name: "project_id", Kind: KindString, Required: true},
			{Name: "status", Kind: KindString, Required: false},
		}},
		Handle: handleReportCSV,
	})
}

func handleReportBurndown(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input reportBurndownInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("report.burndown: %w", err)
	}
	q := sqlc.New(ac.DB)
	sp, err := q.FindSprint(ctx, sqlc.FindSprintParams{ID: input.SprintID, ProjectID: input.ProjectID})
	if err != nil {
		return nil, fmt.Errorf("report.burndown: %w", err)
	}
	snaps, err := q.ListSprintSnapshots(ctx, input.SprintID)
	if err != nil {
		return nil, fmt.Errorf("report.burndown: %w", err)
	}
	totals, err := q.SprintTaskTotals(ctx, sqlc.SprintTaskTotalsParams{
		SprintID:  sql.NullString{String: sp.ID, Valid: true},
		ProjectID: sp.ProjectID,
	})
	if err != nil {
		return nil, fmt.Errorf("report.burndown: %w", err)
	}
	b := report.BuildBurndown(sp.ID, sp.ProjectID, report.Day(sp.StartsOn), report.Day(sp.EndsOn),
		report.Int64(totals.TotalPoints), snaps)
	return map[string]any{
		"svg": report.SVGBurndown(b),
		"csv": report.CSVBurndown(b),
	}, nil
}

func handleReportFlow(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input reportFlowInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("report.flow: %w", err)
	}
	done := input.DoneStatus
	if done == "" {
		done = "done"
	}
	rows, err := sqlc.New(ac.DB).ListProjectTaskActivity(ctx, input.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("report.flow: %w", err)
	}
	m := report.FlowMetrics(rows, done)
	return map[string]any{
		"lead_avg_hours":  m.LeadAvgHours,
		"cycle_avg_hours": m.CycleAvgHours,
		"done_count":      m.DoneCount,
		"csv":             report.CSVFlow(m),
	}, nil
}

func handleReportDistributions(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input reportDistributionsInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("report.distributions: %w", err)
	}
	rows, err := sqlc.New(ac.DB).ProjectDistributions(ctx, input.OrgID)
	if err != nil {
		return nil, fmt.Errorf("report.distributions: %w", err)
	}
	dists := report.BuildDistributions(rows)
	return map[string]any{
		"svg":      report.SVGDistributions(dists),
		"csv":      report.CSVDistributions(dists),
		"projects": dists,
	}, nil
}

func handleReportCSV(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input reportCSVInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("report.csv: %w", err)
	}
	q := sqlc.New(ac.DB)
	rows, err := q.ListTasksByProjectStatus(ctx, sqlc.ListTasksByProjectStatusParams{
		ProjectID: input.ProjectID,
		Status:    input.Status,
	})
	if err != nil {
		return nil, fmt.Errorf("report.csv: %w", err)
	}
	tasks := make([]report.CSVTaskRow, 0, len(rows))
	for _, t := range rows {
		tasks = append(tasks, report.CSVTaskRow{
			Key:       t.Key,
			Title:     t.Title,
			Status:    t.Status,
			Points:    t.Points,
			Priority:  t.Priority,
			ProjectID: t.ProjectID,
			CreatedAt: t.CreatedAt,
			UpdatedAt: t.UpdatedAt,
		})
	}
	return map[string]string{"csv": report.CSVTasks(tasks)}, nil
}
