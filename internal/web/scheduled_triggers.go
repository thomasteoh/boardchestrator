package web

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/web/views"
)

// handleScheduledTriggers renders the per-project scheduled trigger settings
// (WU-309). Lists the project's triggers and the add form (cron, agent, prompt).
func handleScheduledTriggers(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	projectID := chi.URLParam(r, "projectID")
	s := shellData(r, "Scheduled Triggers", "/triggers")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	db := disp.DB()
	if db == nil {
		RenderErrorPage(w, r, http.StatusServiceUnavailable, "Database unavailable", "The scheduler is not wired yet.")
		return
	}
	q := sqlc.New(db)
	triggers, err := q.ListScheduledTriggersByProject(r.Context(), sqlc.ListScheduledTriggersByProjectParams{
		OrgID:     orgID,
		ProjectID: projectID,
	})
	if err != nil {
		RenderErrorPage(w, r, http.StatusInternalServerError, "Could not load triggers", err.Error())
		return
	}
	rows := make([]views.ScheduledTriggerView, 0, len(triggers))
	for _, t := range triggers {
		rows = append(rows, views.ScheduledTriggerView{
			ID:       t.ID,
			AgentID:  t.AgentID,
			CronExpr: t.CronExpr,
			Prompt:   t.Prompt,
			NextAt:   t.NextAt,
			Enabled:  t.Enabled == 1,
		})
	}
	if err := views.ScheduledTriggersPage(s, orgID, projectID, rows).Render(r.Context(), w); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}
