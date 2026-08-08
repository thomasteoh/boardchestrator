package web

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/web/views"
)

// handleOrgAgents renders the agent management page for an org.
func handleOrgAgents(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	s := shellData(r, "Agents", "/agents")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	q := sqlc.New(disp.DB())

	agents, err := q.ListAgentsByOrg(r.Context(), sql.NullString{String: orgID, Valid: orgID != ""})
	if err != nil {
		slog.Error("list agents", "error", err)
		agents = nil
	}

	// List platform templates for the "create from template" UI
	templates, err := q.ListAgents(r.Context())
	if err != nil {
		slog.Error("list templates", "error", err)
		templates = nil
	}
	var platformTemplates []views.AgentRow
	for _, t := range templates {
		if !t.OrgID.Valid {
			platformTemplates = append(platformTemplates, views.AgentRow{
				ID:         t.ID,
				Name:       t.Name,
				ProviderID: t.ProviderID,
				Model:      t.Model,
			})
		}
	}

	rows := make([]views.AgentRow, 0, len(agents))
	for _, a := range agents {
		rows = append(rows, views.AgentRow{
			ID:         a.ID,
			Name:       a.Name,
			ProviderID: a.ProviderID,
			Model:      a.Model,
			Active:     a.Active == 1,
		})
	}

	if err := views.OrgAgentsPage(s, orgID, rows, platformTemplates).Render(r.Context(), w); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// handleAgentCreateAction handles POST /api/agents/create
func handleAgentCreateAction(w http.ResponseWriter, r *http.Request) {
	var input struct {
		OrgID      string `json:"org_id"`
		Name       string `json:"name"`
		ProviderID string `json:"provider_id"`
		Model      string `json:"model"`
		TemplateID string `json:"template_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	raw, _ := json.Marshal(map[string]any{
		"org_id":      input.OrgID,
		"name":        input.Name,
		"provider_id": input.ProviderID,
		"model":       input.Model,
	})
	actor, ok := auth.APIKeyActorFrom(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	result, err := disp.Dispatch(r.Context(), actor, "agent.create", raw, action.Opts{})
	if err != nil {
		slog.Error("agent.create", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		slog.Error("agent.create encode", "error", err)
	}
}

// handleAgentDeleteAction handles POST /api/agents/delete
func handleAgentDeleteAction(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ID    string `json:"id"`
		OrgID string `json:"org_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	raw, _ := json.Marshal(map[string]string{"id": input.ID, "org_id": input.OrgID})
	actor, ok := auth.APIKeyActorFrom(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	_, err := disp.Dispatch(r.Context(), actor, "agent.delete", raw, action.Opts{})
	if err != nil {
		slog.Error("agent.delete", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}
