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

// handleSessionsList returns the sessions list fragment for the current
// user through session.list (WU-613).
func handleSessionsList(w http.ResponseWriter, r *http.Request) {
	sess, ok := auth.SessionFrom(r.Context())
	if !ok || sess.UserID == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	renderSessionsList(w, r, sessionActor(r, sess))
}

func renderSessionsList(w http.ResponseWriter, r *http.Request, actor action.Actor) {
	out, err := disp.Dispatch(r.Context(), actor, action.ActionSessionList, json.RawMessage(`{}`), action.Opts{})
	if err != nil {
		slog.Error("list sessions", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	m, _ := out.(map[string]any)
	list, _ := m["sessions"].([]action.SessionView)
	rows := make([]views.SessionRow, 0, len(list))
	for _, s := range list {
		rows = append(rows, views.SessionRow{
			ID: s.ID, IP: s.IP, UA: s.UserAgent, Method: s.Method, Provider: s.Provider,
			CreatedAt: displayDate(s.CreatedAt), LastSeenAt: displayDate(s.LastSeenAt), Current: s.Current,
		})
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := views.SessionsList(auth.CSRFFrom(r.Context()), rows).Render(r.Context(), w); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// readFormOrJSON decodes a form-urlencoded or JSON body into a flat map.
func readFormOrJSON(r *http.Request) (map[string]any, bool) {
	in := map[string]any{}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		if err := r.ParseForm(); err != nil {
			return nil, false
		}
		for k, vs := range r.PostForm {
			in[k] = vs[0]
		}
		return in, true
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		return nil, false
	}
	return in, true
}

// signedOut ends the browser's session after the current session was
// revoked: the cookie is cleared and HTMX follows HX-Redirect to /login.
func signedOut(w http.ResponseWriter) {
	auth.ClearSessionCookie(w)
	w.Header().Set("HX-Redirect", auth.LoginURL+"?signed_out=1")
	w.WriteHeader(http.StatusOK)
}

// handleSessionRevoke revokes one of the session user's own sessions through
// the session.revoke action (ScopeSelf: the delete is scoped to the caller).
// Pages name the session by its opaque id; the API also accepts token_hash.
func handleSessionRevoke(w http.ResponseWriter, r *http.Request) {
	sess, ok := auth.SessionFrom(r.Context())
	if !ok || sess.UserID == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	in, ok := readFormOrJSON(r)
	if !ok {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	input := map[string]string{}
	for _, k := range []string{"id", "token_hash"} {
		if v, ok := in[k].(string); ok {
			input[k] = v
		}
	}
	raw, err := json.Marshal(input)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	actor := sessionActor(r, sess)
	out, err := disp.Dispatch(r.Context(), actor, action.ActionSessionRevoke, raw, action.Opts{})
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			http.Error(w, "session not found", http.StatusNotFound)
		case errors.Is(err, action.ErrInvalidInput):
			http.Error(w, "choose a session to revoke", http.StatusBadRequest)
		default:
			slog.Error("revoke session", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
		return
	}
	if m, ok := out.(map[string]any); ok && m["current"] == true {
		signedOut(w)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// handleSessionRevokeAll signs the user out everywhere else (keep_current)
// or everywhere (WU-613).
func handleSessionRevokeAll(w http.ResponseWriter, r *http.Request) {
	sess, ok := auth.SessionFrom(r.Context())
	if !ok || sess.UserID == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	in, ok := readFormOrJSON(r)
	if !ok {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	keep := false
	switch v := in["keep_current"].(type) {
	case bool:
		keep = v
	case string:
		keep = v == "1" || v == "true" || v == "on"
	}
	raw, err := json.Marshal(map[string]bool{"keep_current": keep})
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	actor := sessionActor(r, sess)
	if _, err := disp.Dispatch(r.Context(), actor, action.ActionSessionRevokeAll, raw, action.Opts{}); err != nil {
		slog.Error("revoke all sessions", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if !keep {
		signedOut(w)
		return
	}
	renderSessionsList(w, r, actor)
}
