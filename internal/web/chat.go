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

// handleChatPage renders the /chat sidebar page (WU-308): scope selector,
// agent picker, session list, and the transcript + composer. The user's org is
// resolved from memberships; scopes are project (default), team, and org —
// each is offered only when the user has a grant (the page lists what the user
// can reach rather than enumerating every org).
func handleChatPage(w http.ResponseWriter, r *http.Request) {
	s := shellData(r, "Chat", "/chat")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	sess, ok := auth.SessionFrom(r.Context())
	if !ok || sess.UserID == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	db := disp.DB()
	if db == nil {
		RenderErrorPage(w, r, http.StatusServiceUnavailable, "Database unavailable", "The chat engine is not wired yet.")
		return
	}
	q := sqlc.New(db)
	ctx := r.Context()

	// The user's orgs (org-scope memberships).
	orgs, err := q.FindOrgsByActor(ctx, sess.UserID)
	if err != nil {
		RenderErrorPage(w, r, http.StatusInternalServerError, "Could not load orgs", err.Error())
		return
	}
	if len(orgs) == 0 {
		RenderErrorPage(w, r, http.StatusForbidden, "No org access", "You are not a member of any org.")
		return
	}
	orgID := orgs[0].ID

	// Agents for the org (agent picker).
	agents, err := q.ListAgentsByOrg(ctx, sql.NullString{String: orgID, Valid: true})
	if err != nil {
		RenderErrorPage(w, r, http.StatusInternalServerError, "Could not load agents", err.Error())
		return
	}
	chatAgents := make([]views.ChatAgent, 0, len(agents))
	for _, a := range agents {
		chatAgents = append(chatAgents, views.ChatAgent{ID: a.ID, Name: a.Name, Model: a.Model})
	}

	// Scopes: project (default) for each project, team, then org. We show the
	// org's projects + teams; deeper grant checks are enforced server-side on
	// the chat.* actions themselves (scope resolution).
	projects, err := q.ListProjectsByOrg(ctx, orgID)
	if err != nil {
		RenderErrorPage(w, r, http.StatusInternalServerError, "Could not load projects", err.Error())
		return
	}
	teams, err := q.ListTeamsByOrg(ctx, orgID)
	if err != nil {
		RenderErrorPage(w, r, http.StatusInternalServerError, "Could not load teams", err.Error())
		return
	}
	scopes := make([]views.ChatScope, 0, len(projects)+len(teams)+1)
	for _, p := range projects {
		scopes = append(scopes, views.ChatScope{Kind: "project", OrgID: orgID, ProjectID: p.ID, Label: p.Name})
	}
	for _, t := range teams {
		scopes = append(scopes, views.ChatScope{Kind: "team", OrgID: orgID, TeamID: t.ID, Label: "Team: " + t.Name})
	}
	scopes = append(scopes, views.ChatScope{Kind: "org", OrgID: orgID, Label: "Org-wide"})

	// Sessions for the default (first) scope.
	active := scopes[0]
	sessions, err := q.ListChatSessionsByProject(ctx, sqlc.ListChatSessionsByProjectParams{
		OrgID:     orgID,
		ProjectID: sql.NullString{String: active.ProjectID, Valid: true},
		Limit:     50,
	})
	if err != nil {
		RenderErrorPage(w, r, http.StatusInternalServerError, "Could not load sessions", err.Error())
		return
	}
	sessionRows := make([]views.ChatSessionRow, 0, len(sessions))
	for _, s := range sessions {
		sessionRows = append(sessionRows, views.ChatSessionRow{ID: s.ID, Name: s.Name, UpdatedAt: s.UpdatedAt})
	}

	activeAgent := ""
	if len(chatAgents) > 0 {
		activeAgent = chatAgents[0].ID
	}
	if err := views.ChatPage(s, scopes, chatAgents, sessionRows, active, activeAgent).Render(ctx, w); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// handleChatHistoryPartial renders the transcript fragment for a chat session
// (SSE + history load). The chat_id is read from the query; the org scope
// comes from the authenticated user so a cross-org chatID yields no rows.
func handleChatHistoryPartial(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	sess, ok := auth.SessionFrom(r.Context())
	if !ok || sess.UserID == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	db := disp.DB()
	if db == nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	chatID := chi.URLParam(r, "chatID")
	q := sqlc.New(db)

	// Resolve the user's org (the chat history read is org-scoped through the
	// parent session).
	orgs, err := q.FindOrgsByActor(r.Context(), sess.UserID)
	if err != nil || len(orgs) == 0 {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	msgs, err := q.ListChatMessages(r.Context(), sqlc.ListChatMessagesParams{
		ChatID: chatID,
		OrgID:  orgs[0].ID,
	})
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	// Resolve the session's project for card propose/approve scope.
	projectID := ""
	if sess, err := q.FindChatSessionByID(r.Context(), sqlc.FindChatSessionByIDParams{ID: chatID, OrgID: orgs[0].ID}); err == nil && sess.ProjectID.Valid {
		projectID = sess.ProjectID.String
	}
	rows := make([]views.ChatMessageRow, 0, len(msgs))
	for _, m := range msgs {
		rows = append(rows, views.ChatMessageRow{
			ID:          m.ID,
			Role:        m.Role,
			Content:     m.Content,
			RunID:       m.RunID.String,
			ActionName:  m.ActionName,
			ActionInput: m.ActionInput,
			OrgID:       orgs[0].ID,
			ProjectID:   projectID,
		})
	}
	if err := views.ChatMessagesPartial(rows).Render(r.Context(), w); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

var _ = slog.Debug // keep slog import for future chat handlers
