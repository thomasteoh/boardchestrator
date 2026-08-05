package web

import (
	"database/sql"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/web/views"
)

func handleAuditLog(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	s := shellData(r, "Audit Log", "/settings")

	sess, ok := auth.SessionFrom(r.Context())
	if !ok || sess.UserID == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	q := sqlc.New(disp.DB())
	org := sql.NullString{String: orgID, Valid: orgID != ""}
	limit := int64(200)
	rows, err := q.ListAuditLogsByOrg(r.Context(), sqlc.ListAuditLogsByOrgParams{
		OrgID:  org,
		Limit:  limit,
		Offset: 0,
	})
	if err != nil {
		slog.Error("list audit log", "org", orgID, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	auditRows := make([]views.AuditRow, 0, len(rows))
	for _, r := range rows {
		auditRows = append(auditRows, views.AuditRow{
			ID:        r.ID,
			ActorType: r.ActorType,
			ActorID:   r.ActorID,
			Action:    r.Action,
			Subject:   r.Subject,
			IP:        r.Ip,
			CreatedAt: r.CreatedAt,
		})
	}

	if err := views.AuditPage(s, orgID, auditRows).Render(r.Context(), w); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

func handleAuditExport(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	sess, ok := auth.SessionFrom(r.Context())
	if !ok || sess.UserID == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	q := sqlc.New(disp.DB())
	org := sql.NullString{String: orgID, Valid: orgID != ""}
	rows, err := q.ListAuditLogsByOrg(r.Context(), sqlc.ListAuditLogsByOrgParams{
		OrgID:  org,
		Limit:  50000,
		Offset: 0,
	})
	if err != nil {
		slog.Error("export audit", "org", orgID, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=audit.csv")
	w.Write([]byte("id,actor_type,actor_id,action,subject,ip,created_at\n"))
	for _, r := range rows {
		w.Write([]byte(r.ID + "," + r.ActorType + "," + r.ActorID + "," + r.Action + "," + r.Subject + "," + r.Ip + "," + r.CreatedAt + "\n"))
	}
}
