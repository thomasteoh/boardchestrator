package web

import (
	"database/sql"
	"net/http"
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

// handleUsage renders the org usage dashboard (WU-310): monthly total + cap
// status, per-agent and per-project aggregates, and recent cap alerts.
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

	month := monthStartUTC()
	org, err := q.FindOrgByID(ctx, orgID)
	if err != nil {
		RenderErrorPage(w, r, http.StatusInternalServerError, "Could not load org", err.Error())
		return
	}
	finished := sql.NullString{String: month, Valid: true}
	totalUSD, err := q.OrgMonthlySpend(ctx, sqlc.OrgMonthlySpendParams{OrgID: orgID, FinishedAt: finished})
	if err != nil {
		RenderErrorPage(w, r, http.StatusInternalServerError, "Could not total spend", err.Error())
		return
	}
	totalTokens, err := q.OrgMonthlyTokens(ctx, sqlc.OrgMonthlyTokensParams{OrgID: orgID, FinishedAt: finished})
	if err != nil {
		RenderErrorPage(w, r, http.StatusInternalServerError, "Could not total tokens", err.Error())
		return
	}
	byAgent, err := q.AgentUsageByMonth(ctx, sqlc.AgentUsageByMonthParams{OrgID: orgID, FinishedAt: finished})
	if err != nil {
		RenderErrorPage(w, r, http.StatusInternalServerError, "Could not load by-agent usage", err.Error())
		return
	}
	byProject, err := q.ProjectUsageByMonth(ctx, sqlc.ProjectUsageByMonthParams{OrgID: orgID, FinishedAt: finished})
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
			TotalUSD:  a.TotalUsd,
		})
	}
	projects := make([]views.UsageProjectRow, 0, len(byProject))
	for _, p := range byProject {
		projects = append(projects, views.UsageProjectRow{
			ProjectID: p.ProjectID.String,
			Runs:      p.Runs,
			Tokens:    p.Tokens,
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

	_ = views.UsagePage(s, orgID, totalUSD, totalTokens, org.MonthlyCapUsd, month, agents, projects, alertRows).Render(ctx, w)
}
