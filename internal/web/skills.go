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

// handleOrgSkills renders the skills management page for an org.
func handleOrgSkills(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	s := shellData(r, "Skills", "/skills")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	q := sqlc.New(disp.DB())

	skills, err := q.ListSkills(r.Context(), sql.NullString{String: orgID, Valid: orgID != ""})
	if err != nil {
		slog.Error("list skills", "error", err)
		skills = nil
	}

	rows := make([]views.SkillRow, 0, len(skills))
	for _, sk := range skills {
		rows = append(rows, views.SkillRow{
			ID:          sk.ID,
			Name:        sk.Name,
			Version:     sk.Version,
			Description: sk.Description,
			Actions:     sk.AllowedActionsJson,
		})
	}

	if err := views.OrgSkillsPage(s, orgID, rows).Render(r.Context(), w); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// handleSkillCreateAction handles POST /api/skills/create
func handleSkillCreateAction(w http.ResponseWriter, r *http.Request) {
	var input struct {
		OrgID          string   `json:"org_id"`
		Name           string   `json:"name"`
		Description    string   `json:"description"`
		Instructions   string   `json:"instructions"`
		AllowedActions []string `json:"allowed_actions"`
		ParamSchema    string   `json:"param_schema"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	raw, _ := json.Marshal(map[string]any{
		"org_id":          input.OrgID,
		"name":            input.Name,
		"description":     input.Description,
		"instructions":    input.Instructions,
		"allowed_actions": input.AllowedActions,
		"param_schema":    input.ParamSchema,
	})
	actor, ok := auth.APIKeyActorFrom(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	result, err := disp.Dispatch(r.Context(), actor, "skill.create", raw, action.Opts{})
	if err != nil {
		slog.Error("skill.create", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		slog.Error("skill.create encode", "error", err)
	}
}

// handleSkillUpdateAction handles POST /api/skills/update (version bump).
func handleSkillUpdateAction(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ID             string   `json:"id"`
		OrgID          string   `json:"org_id"`
		Description    string   `json:"description"`
		Instructions   string   `json:"instructions"`
		AllowedActions []string `json:"allowed_actions"`
		ParamSchema    string   `json:"param_schema"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	raw, _ := json.Marshal(map[string]any{
		"id":              input.ID,
		"org_id":          input.OrgID,
		"description":     input.Description,
		"instructions":    input.Instructions,
		"allowed_actions": input.AllowedActions,
		"param_schema":    input.ParamSchema,
	})
	actor, ok := auth.APIKeyActorFrom(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	result, err := disp.Dispatch(r.Context(), actor, "skill.update", raw, action.Opts{})
	if err != nil {
		slog.Error("skill.update", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		slog.Error("skill.update encode", "error", err)
	}
}

// handleSkillDeleteAction handles POST /api/skills/delete
func handleSkillDeleteAction(w http.ResponseWriter, r *http.Request) {
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
	_, err := disp.Dispatch(r.Context(), actor, "skill.delete", raw, action.Opts{})
	if err != nil {
		slog.Error("skill.delete", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}
