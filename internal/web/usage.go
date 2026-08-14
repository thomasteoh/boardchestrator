package web

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/web/views"
)

// monthStartUTC returns the UTC start-of-month timestamp for the current month
// in the canonical format (WU-310 usage window).
func monthStartUTC() string {
	now := time.Now().UTC()
	return time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).Format("2006-01-02T15:04:05.000Z")
}

// usageWindowUTC resolves the [from, to) window from query params (RFC3339),
// defaulting to the current UTC month.
func usageWindowUTC(from, to string) (string, string) {
	if from == "" && to == "" {
		m := monthStartUTC()
		return m, monthEndUTC(m)
	}
	f, ferr := time.Parse("2006-01-02T15:04:05.000Z", from)
	t, terr := time.Parse("2006-01-02T15:04:05.000Z", to)
	if ferr != nil || terr != nil || !t.After(f) {
		m := monthStartUTC()
		return m, monthEndUTC(m)
	}
	return f.UTC().Format("2006-01-02T15:04:05.000Z"), t.UTC().Format("2006-01-02T15:04:05.000Z")
}

func monthEndUTC(m string) string {
	t, _ := time.Parse("2006-01-02T15:04:05.000Z", m)
	next := time.Date(t.Year(), t.Month()+1, 1, 0, 0, 0, 0, time.UTC)
	return next.Format("2006-01-02T15:04:05.000Z")
}

// handleUsage renders the org usage dashboard (WU-310 + WU-505): totals with
// runs/actions, per-agent and per-project aggregates (with action counts), a
// timeframe selector, and an optional drill-down run list filtered by
// agent/project.
func handleUsage(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	s := shellData(r, "Usage", "/usage")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	db := disp.DB()
	if db == nil {
		RenderErrorPage(w, r, http.StatusServiceUnavailable, "Database unavailable", "Usage is not wired yet.")
		return
	}
	q := sqlc.New(db)
	ctx := r.Context()

	from, to := usageWindowUTC(r.URL.Query().Get("from"), r.URL.Query().Get("to"))
	agentF := r.URL.Query().Get("agent")
	projF := r.URL.Query().Get("project")

	org, err := q.FindOrgByID(ctx, orgID)
	if err != nil {
		RenderErrorPage(w, r, http.StatusInternalServerError, "Could not load org", err.Error())
		return
	}
	fromN := sql.NullString{String: from, Valid: true}
	toN := sql.NullString{String: to, Valid: true}

	orgUsage, err := q.OrgUsageInWindow(ctx, sqlc.OrgUsageInWindowParams{OrgID: orgID, FinishedAt: fromN, FinishedAt_2: toN})
	if err != nil {
		RenderErrorPage(w, r, http.StatusInternalServerError, "Could not total usage", err.Error())
		return
	}
	byAgent, err := q.AgentUsageInWindow(ctx, sqlc.AgentUsageInWindowParams{OrgID: orgID, FinishedAt: fromN, FinishedAt_2: toN})
	if err != nil {
		RenderErrorPage(w, r, http.StatusInternalServerError, "Could not load by-agent usage", err.Error())
		return
	}
	byProject, err := q.ProjectUsageInWindow(ctx, sqlc.ProjectUsageInWindowParams{OrgID: orgID, FinishedAt: fromN, FinishedAt_2: toN})
	if err != nil {
		RenderErrorPage(w, r, http.StatusInternalServerError, "Could not load by-project usage", err.Error())
		return
	}
	alerts, err := q.ListOrgCapAlerts(ctx, orgID)
	if err != nil {
		RenderErrorPage(w, r, http.StatusInternalServerError, "Could not load cap alerts", err.Error())
		return
	}

	agents := make([]views.UsageAgentRow, 0, len(byAgent))
	for _, a := range byAgent {
		agents = append(agents, views.UsageAgentRow{
			AgentID:   a.AgentID,
			AgentName: a.AgentName,
			Runs:      a.Runs,
			Tokens:    a.Tokens,
			Actions:   a.Actions,
			TotalUSD:  a.TotalUsd,
		})
	}
	projects := make([]views.UsageProjectRow, 0, len(byProject))
	for _, p := range byProject {
		projects = append(projects, views.UsageProjectRow{
			ProjectID: p.ProjectID,
			Runs:      p.Runs,
			Tokens:    p.Tokens,
			Actions:   p.Actions,
			TotalUSD:  p.TotalUsd,
		})
	}
	alertRows := make([]views.UsageCapAlert, 0, len(alerts))
	for _, al := range alerts {
		alertRows = append(alertRows, views.UsageCapAlert{
			ID:       al.ID,
			SpendUSD: al.SpendUsd,
			CapUSD:   al.CapUsd,
			At:       al.CreatedAt,
		})
	}

	// Drill-down run list when filtered by agent or project.
	runs := make([]views.UsageRunRow, 0)
	if agentF != "" || projF != "" {
		projN := sql.NullString{String: projF, Valid: projF != ""}
		rs, err := q.ListRunsInWindow(ctx, sqlc.ListRunsInWindowParams{
			OrgID: orgID, FinishedAt: fromN, FinishedAt_2: toN,
			Column4: agentF, AgentID: agentF, Column6: projF, ProjectID: projN, Limit: 100,
		})
		if err == nil {
			for _, run := range rs {
				runs = append(runs, views.UsageRunRow{
					ID:         run.ID,
					AgentID:    run.AgentID,
					Trigger:    run.Trigger,
					Status:     run.Status,
					TaskID:     run.TaskID.String,
					ProjectID:  run.ProjectID.String,
					Tokens:     run.PromptTokens + run.CompletionTokens,
					Cost:       runCost(run.PromptTokens, run.CompletionTokens, q, run.AgentID, ctx),
					CreatedAt:  run.CreatedAt,
					FinishedAt: run.FinishedAt.String,
				})
			}
		}
	}

	_ = views.UsagePage(s, orgID, orgUsage.TotalUsd, orgUsage.TotalTokens, orgUsage.Runs, orgUsage.Actions,
		org.MonthlyCapUsd, from, to, agents, projects, runs, alertRows).Render(ctx, w)
}

// handleUsageCSV exports the usage aggregates for the current window as CSV.
func handleUsageCSV(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	db := disp.DB()
	if db == nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	q := sqlc.New(db)
	ctx := r.Context()
	from, to := usageWindowUTC(r.URL.Query().Get("from"), r.URL.Query().Get("to"))
	fromN := sql.NullString{String: from, Valid: true}
	toN := sql.NullString{String: to, Valid: true}

	byAgent, err := q.AgentUsageInWindow(ctx, sqlc.AgentUsageInWindowParams{OrgID: orgID, FinishedAt: fromN, FinishedAt_2: toN})
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	byProject, err := q.ProjectUsageInWindow(ctx, sqlc.ProjectUsageInWindowParams{OrgID: orgID, FinishedAt: fromN, FinishedAt_2: toN})
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	kind := chi.URLParam(r, "kind") // "agents" | "projects" | "runs"
	var csv string
	switch kind {
	case "agents":
		csv = webCSVAgents(byAgent)
	case "projects":
		csv = webCSVProjects(byProject)
	case "runs":
		var rs []sqlc.Run
		agentF := r.URL.Query().Get("agent")
		projF := r.URL.Query().Get("project")
		rs, err = q.ListRunsInWindow(ctx, sqlc.ListRunsInWindowParams{
			OrgID: orgID, FinishedAt: fromN, FinishedAt_2: toN,
			Column4: agentF, AgentID: agentF, Column6: projF,
			ProjectID: sql.NullString{String: projF, Valid: projF != ""},
			Limit:     500,
		})
		if err == nil {
			csv = webCSVRuns(rs)
		}
	default:
		http.Error(w, "bad kind", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="usage-`+kind+`.csv"`)
	_, _ = w.Write([]byte(csv))
}

// runCost prices a run via the agent's provider+model pricing (WU-505).
// Returns $0 when the agent has no pricing row.
func runCost(prompt, completion int64, q *sqlc.Queries, agentID string, ctx context.Context) float64 {
	p, err := q.GetRunPricing(ctx, agentID)
	if err != nil {
		return 0
	}
	return (float64(prompt)/1e6)*p.InputPerMtok + (float64(completion)/1e6)*p.OutputPerMtok
}

// webCSVQuote quotes a field per RFC 4180 when it contains a comma, quote, or
// newline, doubling embedded quotes.
func webCSVQuote(s string) string {
	if strings.ContainsAny(s, ",\"\n") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

// webCSVAgents serializes per-agent usage rows as RFC 4180 CSV.
func webCSVAgents(rows []sqlc.AgentUsageInWindowRow) string {
	var b strings.Builder
	b.WriteString("agent_id,agent_name,runs,tokens,cost_usd,actions\n")
	for _, r := range rows {
		_, _ = fmt.Fprintf(&b, "%s,%s,%d,%d,%.2f,%d\n",
			webCSVQuote(r.AgentID), webCSVQuote(r.AgentName), r.Runs, r.Tokens, r.TotalUsd, r.Actions)
	}
	return b.String()
}

// webCSVProjects serializes per-project usage rows as RFC 4180 CSV.
func webCSVProjects(rows []sqlc.ProjectUsageInWindowRow) string {
	var b strings.Builder
	b.WriteString("project_id,runs,tokens,cost_usd,actions\n")
	for _, r := range rows {
		_, _ = fmt.Fprintf(&b, "%s,%d,%d,%.2f,%d\n",
			webCSVQuote(r.ProjectID), r.Runs, r.Tokens, r.TotalUsd, r.Actions)
	}
	return b.String()
}

// webCSVRuns serializes the drill-down run list as RFC 4180 CSV.
func webCSVRuns(rows []sqlc.Run) string {
	var b strings.Builder
	b.WriteString("id,agent_id,trigger,status,task_id,project_id,prompt_tokens,completion_tokens,created_at,finished_at\n")
	for _, r := range rows {
		_, _ = fmt.Fprintf(&b, "%s,%s,%s,%s,%s,%s,%d,%d,%s,%s\n",
			webCSVQuote(r.ID), webCSVQuote(r.AgentID), webCSVQuote(r.Trigger), webCSVQuote(r.Status),
			webCSVQuote(r.TaskID.String), webCSVQuote(r.ProjectID.String),
			r.PromptTokens, r.CompletionTokens, webCSVQuote(r.CreatedAt), webCSVQuote(r.FinishedAt.String))
	}
	return b.String()
}
