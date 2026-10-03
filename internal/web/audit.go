package web

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/web/views"
)

// auditRows dispatches a read-only audit action as the session user, so the
// permission engine decides who may read which log (WU-605: the org pages
// used to read any org's rows for any signed-in user). ok is false once a
// response has been written.
func auditRows(w http.ResponseWriter, r *http.Request, name, orgID string, in any) ([]sqlc.AuditLog, bool) {
	sess, ok := auth.SessionFrom(r.Context())
	if !ok || sess.UserID == "" {
		if r.Method == http.MethodGet {
			http.Redirect(w, r, auth.LoginURLFor(r.URL.RequestURI()), http.StatusSeeOther) //nolint:gosec // G710: fixed /login target; the path is only a SafeReturnTo-validated query value
			return nil, false
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return nil, false
	}
	if disp == nil {
		http.Error(w, "dispatcher not configured", http.StatusInternalServerError)
		return nil, false
	}
	raw, err := json.Marshal(in)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return nil, false
	}
	actor := action.Actor{Type: action.ActorUser, ID: sess.UserID, IP: auth.ClientIP(r)}
	out, err := disp.Dispatch(r.Context(), actor, name, raw, action.Opts{Org: orgID})
	switch {
	case errors.Is(err, action.ErrForbidden), errors.Is(err, action.ErrScope):
		w.WriteHeader(http.StatusForbidden)
		RenderErrorPage(w, r, http.StatusForbidden, "Forbidden", "You don't have permission to view this audit log.")
		return nil, false
	case err != nil:
		slog.Error("audit log", "action", name, "org", orgID, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return nil, false
	}
	rows, _ := out.([]sqlc.AuditLog)
	return rows, true
}

func toAuditRows(rows []sqlc.AuditLog, withDetail bool) []views.AuditRow {
	out := make([]views.AuditRow, 0, len(rows))
	for _, r := range rows {
		row := views.AuditRow{
			ID:        r.ID,
			ActorType: r.ActorType,
			ActorID:   r.ActorID,
			Action:    r.Action,
			Subject:   r.Subject,
			IP:        r.Ip,
			CreatedAt: r.CreatedAt,
		}
		// Only the sign-in rows' detail, which this codebase writes with
		// fixed, secret-free keys; action rows may carry free-form input.
		if withDetail && (strings.HasPrefix(r.Action, "auth.") || strings.HasPrefix(r.Action, "identity.")) {
			row.Detail = r.DetailJson
		}
		out = append(out, row)
	}
	return out
}

func handleAuditLog(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	rows, ok := auditRows(w, r, "audit.log.list", orgID, map[string]any{"org_id": orgID, "limit": 200})
	if !ok {
		return
	}
	s := shellData(r, "Audit Log", "/settings")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := views.AuditPage(s, orgID, toAuditRows(rows, false)).Render(r.Context(), w); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

func handleAuditExport(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	rows, ok := auditRows(w, r, "audit.log.export", orgID, map[string]any{"org_id": orgID})
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=audit.csv")
	if _, err := w.Write([]byte("id,actor_type,actor_id,action,subject,ip,created_at\n")); err != nil {
		slog.Error("audit csv write", "error", err)
		return
	}
	for _, r := range rows {
		if _, err := w.Write([]byte(r.ID + "," + r.ActorType + "," + r.ActorID + "," + r.Action + "," + r.Subject + "," + r.Ip + "," + r.CreatedAt + "\n")); err != nil {
			slog.Error("audit csv write", "error", err)
			return
		}
	}
}

// handlePlatformAudit is Platform Admin -> Audit log (GET /admin/audit):
// the rows with no org, including every sign-in event.
func handlePlatformAudit(w http.ResponseWriter, r *http.Request) {
	rows, ok := auditRows(w, r, "audit.platform.list", "", map[string]any{"limit": 200})
	if !ok {
		return
	}
	s := shellData(r, "Platform audit log", "")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := views.PlatformAuditPage(s, toAuditRows(rows, true)).Render(r.Context(), w); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}
