package web

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/web/views"
)

// handleAPIKeys renders the API keys management page for an org.
func handleAPIKeys(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	s := shellData(r, "API Keys", "/settings")

	sess, ok := auth.SessionFrom(r.Context())
	if !ok || sess.UserID == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	q := sqlc.New(disp.DB())
	keys, err := q.ListAPIKeysByUser(r.Context(), sess.UserID)
	if err != nil {
		slog.Error("list api keys", "error", err)
		// Render empty page on DB error rather than failing hard.
		keys = nil
	}

	rows := make([]views.APIKeyRow, 0, len(keys))
	for _, k := range keys {
		lastUsed := ""
		if k.LastUsedAt.Valid {
			lastUsed = k.LastUsedAt.String
		}
		rows = append(rows, views.APIKeyRow{
			ID:        k.ID,
			Name:      k.Name,
			Prefix:    k.Prefix,
			Scope:     k.ScopeJson,
			CreatedAt: k.CreatedAt,
			LastUsed:  lastUsed,
		})
	}

	if err := views.APIKeysPage(s, orgID, rows).Render(r.Context(), w); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}
