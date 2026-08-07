package web

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/web/views"
)

// handleProviders renders the platform admin provider management page.
func handleProviders(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	sess, ok := auth.SessionFrom(r.Context())
	if !ok || sess.UserID == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	q := sqlc.New(disp.DB())

	// List all providers (platform-wide).
	providers, err := q.ListProviders(r.Context())
	if err != nil {
		slog.Error("list providers", "error", err)
		providers = nil
	}

	rows := make([]views.ProviderRow, 0, len(providers))
	for _, p := range providers {
		// Load allocations for this provider.
		orgs, err := q.ListProviderOrgsByProvider(r.Context(), p.ID)
		allocated := ""
		if err == nil {
			for _, po := range orgs {
				if allocated != "" {
					allocated += ", "
				}
				allocated += po.OrgID
			}
		}
		rows = append(rows, views.ProviderRow{
			ID:            p.ID,
			Kind:          p.Kind,
			Name:          p.Name,
			BaseURL:       p.BaseUrl,
			Models:        p.ModelsJson,
			AllocatedOrgs: allocated,
		})
	}

	s := shellData(r, "Providers", "/admin/providers")
	if err := views.ProviderPage(s, rows).Render(r.Context(), w); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// handleProviderCreateAction handles POST /api/providers/create
func handleProviderCreateAction(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Kind    string   `json:"kind"`
		Name    string   `json:"name"`
		BaseURL string   `json:"base_url"`
		Models  []string `json:"models"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	raw, _ := json.Marshal(map[string]any{
		"kind":     input.Kind,
		"name":     input.Name,
		"base_url": input.BaseURL,
		"models":   input.Models,
	})
	actor, ok := auth.APIKeyActorFrom(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	result, err := disp.Dispatch(r.Context(), actor, "provider.create", raw, action.Opts{})
	if err != nil {
		slog.Error("provider.create", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// handleProviderDeleteAction handles POST /api/providers/delete
func handleProviderDeleteAction(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	raw, _ := json.Marshal(map[string]string{"id": input.ID})
	actor, ok := auth.APIKeyActorFrom(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	_, err := disp.Dispatch(r.Context(), actor, "provider.delete", raw, action.Opts{})
	if err != nil {
		slog.Error("provider.delete", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// handleProviderAllocateAction handles POST /api/providers/allocate
func handleProviderAllocateAction(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ProviderID string `json:"provider_id"`
		OrgID      string `json:"org_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	raw, _ := json.Marshal(map[string]string{
		"provider_id": input.ProviderID,
		"org_id":      input.OrgID,
	})
	actor, ok := auth.APIKeyActorFrom(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	_, err := disp.Dispatch(r.Context(), actor, "provider-org.allocate", raw, action.Opts{})
	if err != nil {
		slog.Error("provider-org.allocate", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}
