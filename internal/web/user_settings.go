package web

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/web/views"
)

// handleUserSettings renders the user settings page.
func handleUserSettings(w http.ResponseWriter, r *http.Request) {
	s := shellData(r, "User Settings", "/settings")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	sess, ok := auth.SessionFrom(r.Context())
	if !ok || sess.UserID == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	q := sqlc.New(disp.DB())
	user, err := q.GetUser(r.Context(), sess.UserID)
	if err != nil {
		slog.Error("get user", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if err := views.UserSettingsPage(s, user.Theme, user.Timezone).Render(r.Context(), w); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// handleSessionsList returns the sessions list fragment for the current user.
func handleSessionsList(w http.ResponseWriter, r *http.Request) {
	sess, ok := auth.SessionFrom(r.Context())
	if !ok || sess.UserID == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	q := sqlc.New(disp.DB())
	sessions, err := q.ListSessionsByUser(r.Context(), sess.UserID)
	if err != nil {
		slog.Error("list sessions", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	rows := make([]views.SessionRow, 0, len(sessions))
	for _, s := range sessions {
		rows = append(rows, views.SessionRow{
			TokenHash:  s.TokenHash,
			IP:         s.Ip,
			UA:         s.Ua,
			CreatedAt:  s.CreatedAt,
			LastSeenAt: s.LastSeenAt,
			ExpiresAt:  s.ExpiresAt,
		})
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := views.SessionsList(rows).Render(r.Context(), w); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// handleSessionRevoke revokes one of the session user's own sessions through
// the session.revoke action (ScopeSelf: the delete is scoped to the caller).
func handleSessionRevoke(w http.ResponseWriter, r *http.Request) {
	sess, ok := auth.SessionFrom(r.Context())
	if !ok || sess.UserID == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var input struct {
		TokenHash string `json:"token_hash"`
	}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form body", http.StatusBadRequest)
			return
		}
		input.TokenHash = r.PostFormValue("token_hash")
	} else if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	raw, err := json.Marshal(input)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	actor := action.Actor{Type: action.ActorUser, ID: sess.UserID, IP: auth.ClientIP(r)}
	if _, err := disp.Dispatch(r.Context(), actor, "session.revoke", raw, action.Opts{}); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "session not found", http.StatusNotFound)
			return
		}
		slog.Error("revoke session", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
