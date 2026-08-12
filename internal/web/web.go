package web

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/github"
	"github.com/thomasteoh/boardchestrator/internal/mcp"
	"github.com/thomasteoh/boardchestrator/internal/search"
	"github.com/thomasteoh/boardchestrator/internal/storage"
	"github.com/thomasteoh/boardchestrator/internal/web/views"
)

// disp is the action dispatcher, set by SetDispatcher at startup.
var disp actionDispatcher

type actionDispatcher interface {
	Dispatch(ctx context.Context, actor action.Actor, name string, input json.RawMessage, opts action.Opts) (any, error)
	DB() *sql.DB
}

func SetDispatcher(d actionDispatcher) { disp = d }

// RenderErrorPage renders an HTML error page via the error_pages templ component.
// It is exported for use by the server package (404/405 handlers).
func RenderErrorPage(w http.ResponseWriter, r *http.Request, status int, title, message string) {
	s := shellData(r, title, "")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := views.ErrorPage(s, status, title, message).Render(r.Context(), w); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	s := shellData(r, "Home", "")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if auth.IsAuthenticated(r.Context()) {
		http.Redirect(w, r, "/app", http.StatusSeeOther)
		return
	}
	// Unauthenticated users see the landing page
	if err := views.LandingPage(s).Render(r.Context(), w); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// shellData assembles the layout inputs for a request. The nonce and CSRF
// token are sourced from the request context, populated by the CSP and session
// middleware (WU-005).
func shellData(r *http.Request, title, active string) views.Shell {
	return views.Shell{
		Title: title,
		Nonce: auth.Nonce(r.Context()),
		CSRF:  auth.CSRFFrom(r.Context()),
		Assets: views.ShellAssets{
			AppCSS:   AssetURL("app.css"),
			HTMX:     AssetURL("vendor/htmx.min.js"),
			Alpine:   AssetURL("vendor/alpine-csp.min.js"),
			AppJS:    AssetURL("app.js"),
			Sortable: AssetURL("vendor/sortable.min.js"),
			// Served at the stable root path (not content-hashed) so the
			// worker's scope is the whole origin, not just /static/. A
			// hashed URL would also orphan the previous worker each build.
			SW: "/sw.js",
		},
		Active: active,
	}
}

func handleAppShell(w http.ResponseWriter, r *http.Request) {
	s := shellData(r, "Home", "")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := views.Home(s).Render(r.Context(), w); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

func handleOrgPeople(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	s := shellData(r, "People", "/people")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Stub: return empty member/invite lists until the DB-backed handler is wired.
	if err := views.PeoplePage(s, orgID, "org", orgID, orgID, nil, nil).Render(r.Context(), w); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

func handleTeamPeople(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	teamID := chi.URLParam(r, "teamID")
	s := shellData(r, "People", "/people")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := views.PeoplePage(s, orgID, "team", teamID, teamID, nil, nil).Render(r.Context(), w); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

func handleProjectPeople(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	projectID := chi.URLParam(r, "projectID")
	s := shellData(r, "People", "/people")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := views.PeoplePage(s, orgID, "project", projectID, projectID, nil, nil).Render(r.Context(), w); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

func handleOrgSettings(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	s := shellData(r, "Org Settings", "/settings")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	breadcrumbs := []views.Breadcrumb{
		{Label: orgID, Href: "/app/org/" + orgID + "/settings"},
	}
	if err := views.OrgSettingsPage(s, orgID, orgID, "", "", breadcrumbs).Render(r.Context(), w); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

func handleTeamSettings(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	teamID := chi.URLParam(r, "teamID")
	s := shellData(r, "Team Settings", "/settings")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	breadcrumbs := []views.Breadcrumb{
		{Label: orgID, Href: "/app/org/" + orgID + "/settings"},
		{Label: teamID, Href: ""},
	}
	if err := views.TeamSettingsPage(s, orgID, teamID, teamID, "", "", breadcrumbs).Render(r.Context(), w); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

func handleProjectSettings(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	projectID := chi.URLParam(r, "projectID")
	s := shellData(r, "Project Settings", "/settings")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	breadcrumbs := []views.Breadcrumb{
		{Label: orgID, Href: "/app/org/" + orgID + "/settings"},
		{Label: projectID, Href: ""},
	}
	if err := views.ProjectSettingsPage(s, orgID, projectID, projectID, "", "", "", breadcrumbs).Render(r.Context(), w); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

func handleOrgRoles(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	s := shellData(r, "Roles", "/settings")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	breadcrumbs := []views.Breadcrumb{
		{Label: orgID, Href: "/app/org/" + orgID + "/settings"},
		{Label: "Roles", Href: ""},
	}
	if err := views.RolesEditorPage(s, orgID, nil, breadcrumbs).Render(r.Context(), w); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

func handleOrgRoleNew(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

func handleOrgRoleEdit(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

// handleAction dispatches an action via the injected dispatcher.
func handleAction(w http.ResponseWriter, r *http.Request) {
	if disp == nil {
		http.Error(w, "dispatcher not configured", http.StatusInternalServerError)
		return
	}
	name := r.URL.Path[len("/api/action/"):]
	var input json.RawMessage
	// Accept both JSON bodies (tool dispatches) and form-urlencoded bodies
	// (htmx forms). Form values are stringified into a flat JSON object.
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form body", http.StatusBadRequest)
			return
		}
		obj := map[string]string{}
		for k, vs := range r.PostForm {
			obj[k] = vs[0]
		}
		b, err := json.Marshal(obj)
		if err != nil {
			http.Error(w, "invalid form body", http.StatusBadRequest)
			return
		}
		input = b
	} else if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	actor := action.Actor{Type: action.ActorUser, ID: "placeholder", IP: r.RemoteAddr}
	if sess, ok := auth.SessionFrom(r.Context()); ok && sess.UserID != "" {
		actor.ID = sess.UserID
	}
	// X-Dry-Run: chat propose→approve (WU-308) runs the inner action in dry-run
	// mode to render a preview without mutating anything. X-Org-Id/X-Project-Id/
	// X-Team-Id carry the chat session's scope so the inner action re-dispatches
	// in the session's project/team rather than the actor's default scope.
	opts := action.Opts{}
	if r.Header.Get("X-Dry-Run") == "true" {
		opts.DryRun = true
	}
	if v := r.Header.Get("X-Org-Id"); v != "" {
		opts.Org = v
	}
	if v := r.Header.Get("X-Project-Id"); v != "" {
		opts.Proj = v
	}
	if v := r.Header.Get("X-Team-Id"); v != "" {
		opts.Team = v
	}
	result, err := disp.Dispatch(r.Context(), actor, name, input, opts)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

func handleInviteAccept(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	s := shellData(r, "Accept Invite", "")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := views.InviteAcceptPage(s, token).Render(r.Context(), w); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// handleMCP serves the WU-403 MCP endpoint. The dispatcher is read lazily from
// the package var (set by SetDispatcher after Routes registration) so the route
// can be mounted before startup wiring completes.
func handleMCP(w http.ResponseWriter, r *http.Request) {
	if disp == nil {
		http.Error(w, "dispatcher not configured", http.StatusInternalServerError)
		return
	}
	mcp.New(disp.DB(), disp).Handle(w, r)
}

// handleGithubHook is the inbound GitHub webhook receiver (WU-405). It is
// mounted without API-key/session auth — GitHub signs payloads with the
// per-repo webhook secret, verified inside the receiver.
func handleGithubHook(w http.ResponseWriter, r *http.Request) {
	if disp == nil {
		http.Error(w, "dispatcher not configured", http.StatusInternalServerError)
		return
	}
	github.New(disp.DB(), disp).Handle(w, r)
}

// handleTaskDetail renders the kanban task detail view including the agent
// thread (runs + steps) for the task (WU-307).
func handleTaskDetail(w http.ResponseWriter, r *http.Request) {
	s := shellData(r, "Task Detail", "/tasks")
	orgID := chi.URLParam(r, "orgID")
	projectID := chi.URLParam(r, "projectID")
	taskID := chi.URLParam(r, "taskID")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	db := disp.DB()
	if db == nil {
		RenderErrorPage(w, r, http.StatusServiceUnavailable, "Database unavailable", "The task engine is not wired yet.")
		return
	}
	q := sqlc.New(db)
	ctx := r.Context()

	task, err := q.FindTaskByID(ctx, sqlc.FindTaskByIDParams{ID: taskID, ProjectID: projectID})
	if err != nil {
		RenderErrorPage(w, r, http.StatusNotFound, "Task not found", err.Error())
		return
	}
	view := views.TaskDetail{
		ID:          task.ID,
		ProjectID:   task.ProjectID,
		Key:         task.Key,
		Title:       task.Title,
		Description: task.Description,
		Points:      int(task.Points),
		Priority:    int(task.Priority),
		Status:      task.Status,
		DueAt:       task.DueAt,
	}

	// Agent thread: runs for this task, newest first, with their steps.
	runs, err := q.FindRunByTaskAndOrg(ctx, sqlc.FindRunByTaskAndOrgParams{
		TaskID: sql.NullString{String: taskID, Valid: taskID != ""},
		OrgID:  orgID,
	})
	if err != nil {
		RenderErrorPage(w, r, http.StatusInternalServerError, "Could not load runs", err.Error())
		return
	}
	for _, run := range runs {
		agentName := run.AgentID
		if ag, aerr := q.FindAgentByID(ctx, run.AgentID); aerr == nil {
			agentName = ag.Name
		}
		row := views.RunThreadRow{
			ID:        run.ID,
			AgentName: agentName,
			Trigger:   run.Trigger,
			Status:    run.Status,
			Error:     run.Error,
		}
		steps, serr := q.ListRunSteps(ctx, sqlc.ListRunStepsParams{RunID: run.ID, OrgID: orgID})
		if serr == nil {
			for _, st := range steps {
				row.Steps = append(row.Steps, views.ThreadStepRow{
					Seq:      st.Seq,
					Kind:     st.Kind,
					Request:  st.RequestJson,
					Response: st.ResponseJson,
				})
			}
		}
		view.Runs = append(view.Runs, row)
	}

	if err := views.TaskDetailPage(s, view, nil, nil).Render(ctx, w); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// handleRunDetail renders the agent run detail view: run metadata plus the
// full model/tool step transcript (SPEC §10 run_steps). The route is linked
// from the task detail view.
func handleRunDetail(w http.ResponseWriter, r *http.Request) {
	s := shellData(r, "Run Detail", "/tasks")
	orgID := chi.URLParam(r, "orgID")
	runID := chi.URLParam(r, "runID")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	db := disp.DB()
	if db == nil {
		RenderErrorPage(w, r, http.StatusServiceUnavailable, "Database unavailable", "The run engine is not wired yet.")
		return
	}
	q := sqlc.New(db)
	ctx := r.Context()

	run, err := q.FindRunByID(ctx, sqlc.FindRunByIDParams{ID: runID, OrgID: orgID})
	if err != nil {
		RenderErrorPage(w, r, http.StatusNotFound, "Run not found", err.Error())
		return
	}
	agent, err := q.FindAgentByID(ctx, run.AgentID)
	if err != nil {
		RenderErrorPage(w, r, http.StatusInternalServerError, "Agent lookup failed", err.Error())
		return
	}
	steps, err := q.ListRunSteps(ctx, sqlc.ListRunStepsParams{RunID: run.ID, OrgID: orgID})
	if err != nil {
		RenderErrorPage(w, r, http.StatusInternalServerError, "Steps lookup failed", err.Error())
		return
	}
	approvals, err := q.ListApprovalsByRun(ctx, sqlc.ListApprovalsByRunParams{RunID: run.ID, OrgID: orgID})
	if err != nil {
		RenderErrorPage(w, r, http.StatusInternalServerError, "Approvals lookup failed", err.Error())
		return
	}

	row := views.RunRow{
		ID:               run.ID,
		AgentID:          agent.ID,
		AgentName:        agent.Name,
		Trigger:          run.Trigger,
		Status:           run.Status,
		TaskID:           run.TaskID.String,
		TaskKey:          "",
		CreatedAt:        run.CreatedAt,
		StartedAt:        run.StartedAt.String,
		FinishedAt:       run.FinishedAt.String,
		Error:            run.Error,
		PromptTokens:     run.PromptTokens,
		CompletionTokens: run.CompletionTokens,
	}
	stepRows := make([]views.RunStepRow, 0, len(steps))
	for _, st := range steps {
		stepRows = append(stepRows, views.RunStepRow{
			Seq:      st.Seq,
			Kind:     st.Kind,
			Request:  st.RequestJson,
			Response: st.ResponseJson,
			Tokens:   st.Tokens,
		})
	}
	approvalRows := make([]views.ApprovalRow, 0, len(approvals))
	for _, ap := range approvals {
		approvalRows = append(approvalRows, views.ApprovalRow{
			ID:         ap.ID,
			ActionName: ap.ActionName,
			Input:      ap.InputJson,
			Status:     ap.Status,
			Requested:  ap.RequestedAt,
		})
	}

	if err := views.RunDetailPage(s, row, stepRows, approvalRows).Render(ctx, w); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// handleBoardView renders the kanban board for a project.
func handleBoardView(w http.ResponseWriter, r *http.Request) {
	projectID := chi.URLParam(r, "projectID")
	s := shellData(r, "Board", "/boards")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := views.BoardPage(s, projectID, nil, nil).Render(r.Context(), w); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// handleBoardColumns renders the column configuration page.
func handleBoardColumns(w http.ResponseWriter, r *http.Request) {
	projectID := chi.URLParam(r, "projectID")
	s := shellData(r, "Board Columns", "/boards")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	db := disp.DB()
	if db == nil {
		RenderErrorPage(w, r, http.StatusServiceUnavailable, "Database unavailable", "The board engine is not wired yet.")
		return
	}
	q := sqlc.New(db)
	cols, err := q.ListBoardColumns(r.Context(), projectID)
	if err != nil {
		RenderErrorPage(w, r, http.StatusInternalServerError, "Could not load columns", err.Error())
		return
	}
	viewsCols := make([]views.ColumnView, 0, len(cols))
	for _, c := range cols {
		viewsCols = append(viewsCols, views.ColumnView{
			ID:             c.ID,
			Name:           c.Name,
			Color:          c.Color,
			Status:         c.Status,
			Count:          0,
			WIPLimit:       int(c.WipLimit),
			TriggerAgentID: c.TriggerAgentID.String,
			TriggerPrompt:  c.TriggerPrompt,
		})
	}
	if err := views.ColumnSettingsPage(s, projectID, viewsCols).Render(r.Context(), w); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// handleBacklogView renders the backlog list view for a project.
func handleBacklogView(w http.ResponseWriter, r *http.Request) {
	projectID := chi.URLParam(r, "projectID")
	s := shellData(r, "Backlog", "/backlog")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := views.BacklogPage(s, projectID, nil, nil).Render(r.Context(), w); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// fileStore is the attachment storage backend, set by SetFileStore at startup.
var fileStore storage.Store

// SetFileStore sets the attachment storage backend for the download handler.
func SetFileStore(s storage.Store) { fileStore = s }

// handleAttachmentDownload streams an attachment file with security headers.
func handleAttachmentDownload(w http.ResponseWriter, r *http.Request) {
	if disp == nil {
		http.Error(w, "dispatcher not configured", http.StatusInternalServerError)
		return
	}
	if fileStore == nil {
		http.Error(w, "file store not configured", http.StatusInternalServerError)
		return
	}

	http.Error(w, "attachment download: direct DB query not wired — use action dispatch", http.StatusNotImplemented)
}

// handleSearchPage renders the search page.
func handleSearchPage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	s := shellData(r, "Search", "/search")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var results []views.SearchResultRow
	if q != "" {
		sess, _ := auth.SessionFrom(r.Context())
		r, err := search.Query(r.Context(), disp.DB(), q, sess.UserID, 50)
		if err != nil {
			slog.Error("search", "error", err)
			http.Error(w, "search error", http.StatusInternalServerError)
			return
		}
		for _, res := range r {
			results = append(results, views.SearchResultRow{
				Type:      res.Type,
				ID:        res.ID,
				ProjectID: res.ProjectID,
				Title:     res.Title,
				Key:       res.Key,
				Body:      res.Body,
				Status:    res.Status,
			})
		}
	}
	if err := views.SearchPage(s, q, results).Render(r.Context(), w); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// handleSearchAPI handles HTMX search queries via GET /api/search?q=...
func handleSearchAPI(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	sess, _ := auth.SessionFrom(r.Context())

	results, err := search.Query(r.Context(), disp.DB(), q, sess.UserID, 50)
	if err != nil {
		slog.Error("search", "error", err)
		http.Error(w, "search error", http.StatusInternalServerError)
		return
	}

	// Return JSON for API consumers
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(map[string]any{
		"results": results,
	}); err != nil {
		slog.Error("search json encode", "error", err)
	}
}

// handleBoardPartial renders the board columns and cards fragment for SSE-driven
// partial refresh (used by bc.sse.refresh("task-updated", "#board-{id}", ...)).
func handleBoardPartial(w http.ResponseWriter, r *http.Request) {
	projectID := chi.URLParam(r, "projectID")
	// Stub: return empty board fragment until DB-backed handler is wired.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := views.BoardColumnsPartial(projectID, nil, nil).Render(r.Context(), w); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// handleCommentsPartial renders the comments list fragment for a task (SSE-driven).
func handleCommentsPartial(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Stub: return empty comments list until DB-backed handler is wired.
	if err := views.CommentsListPartial(nil).Render(r.Context(), w); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// handleNotifUnreadCount returns the unread notification count for the current user
// as JSON. Used by the notification badge SSE refresh.
func handleNotifUnreadCount(w http.ResponseWriter, r *http.Request) {
	sess, ok := auth.SessionFrom(r.Context())
	if !ok || sess.UserID == "" {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"count":0}`))
		return
	}
	// Stub: return zero until DB-backed query is wired.
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"count":0}`))
}

// handleSprintList renders the sprints list page for a project.
func handleSprintList(w http.ResponseWriter, r *http.Request) {
	projectID := chi.URLParam(r, "projectID")
	s := shellData(r, "Sprints", "/sprints")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := views.SprintListPage(s, projectID, nil).Render(r.Context(), w); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// serveEmbedded copies an embedded static file to the response, reporting a
// 500 on read failure. Used for the small set of assets served at fixed root
// paths (manifest, service worker) rather than the content-hashed /static tree.
func serveEmbedded(w http.ResponseWriter, name string) {
	f, err := staticFS.Open(name)
	if err != nil {
		http.Error(w, "not found", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	if _, err := io.Copy(w, f); err != nil {
		// Client went away mid-stream; nothing useful to do but stop.
		return
	}
}

// handleManifest serves the PWA manifest with the correct MIME type.
// Browsers require application/manifest+json for installation.
func handleManifest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/manifest+json")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	// manifest.json is served unhashed at /manifest.json — the conventional
	// path browsers expect for the manifest link.
	serveEmbedded(w, "static/manifest.json")
}

// handleServiceWorker serves the service worker at the stable root path
// /sw.js. Serving from the origin root (rather than a hashed /static/ URL)
// gives the worker default scope of "/", so it can intercept navigations to
// every page, not just assets under /static/. Service-Worker-Allowed is set
// defensively for callers that register with an explicit wider scope.
func handleServiceWorker(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	// Revalidate every load so a new worker ships promptly; the browser's
	// own byte-comparison update check does the rest.
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Service-Worker-Allowed", "/")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	serveEmbedded(w, "static/sw.js")
}

// Routes mounts the browser-facing routes: embedded static assets, the
// app shell, people management, invite acceptance, and tenancy UI.
func Routes(r chi.Router) {
	r.Handle("/static/*", StaticHandler())
	r.Get("/manifest.json", handleManifest)
	r.Get("/sw.js", handleServiceWorker)
	r.Get("/", handleRoot)
	r.Get("/app", handleAppShell)
	r.Get("/app/org/{orgID}/people", handleOrgPeople)
	r.Get("/app/org/{orgID}/team/{teamID}/people", handleTeamPeople)
	r.Get("/app/org/{orgID}/project/{projectID}/people", handleProjectPeople)
	r.Get("/invite/accept", handleInviteAccept)
	// User settings
	r.Get("/app/settings", handleUserSettings)
	r.Get("/api/sessions", handleSessionsList)

	// Tenancy UI pages
	r.Get("/app/org/{orgID}/settings", handleOrgSettings)
	r.Get("/app/org/{orgID}/team/{teamID}/settings", handleTeamSettings)
	r.Get("/app/org/{orgID}/project/{projectID}/settings", handleProjectSettings)
	r.Get("/app/org/{orgID}/roles", handleOrgRoles)
	r.Get("/app/org/{orgID}/roles/new", handleOrgRoleNew)
	r.Get("/app/org/{orgID}/roles/{roleID}/edit", handleOrgRoleEdit)
	r.Post("/api/action/org.update", handleAction)
	r.Post("/api/action/team.update", handleAction)
	r.Post("/api/action/project.update", handleAction)
	r.Post("/api/action/member.invite", handleAction)
	r.Post("/api/action/member.remove", handleAction)
	r.Post("/api/action/invite.accept", handleAction)
	r.Post("/api/action/role.create", handleAction)
	r.Post("/api/action/role.update", handleAction)
	// API key routes (WU-109)
	r.Get("/app/org/{orgID}/apikeys", handleAPIKeys)
	r.Get("/app/org/{orgID}/usage", handleUsage)
	r.Post("/api/action/apikey.create", handleAction)
	r.Post("/api/action/apikey.revoke", handleAction)
	r.Post("/api/v1/actions/{name}", handleRPCv1(rateLimiter))
	r.Get("/api/v1/openapi.json", handleOpenAPI)
	r.Get("/api/v1/orgs/{orgID}/projects", handleResourceProjects)
	r.Get("/api/v1/orgs/{orgID}/projects/{projectKey}/tasks/{taskKey}", handleResourceTaskByKey)
	r.Put("/api/v1/orgs/{orgID}/projects/{projectID}/tasks/{taskID}", handleResourceTaskUpdate)
	r.Get("/api/v1/orgs/{orgID}/projects/{projectID}/tasks/{taskID}/comments", handleResourceComments)
	r.Get("/api/v1/orgs/{orgID}/projects/{projectID}/sprints", handleResourceSprints)
	r.Get("/api/v1/orgs/{orgID}/labels", handleResourceLabels)
	r.Get("/api/v1/orgs/{orgID}/search", handleResourceSearch)
	r.Get("/app/docs", handleDocsPage)
	// MCP server (WU-403): Streamable HTTP JSON-RPC at /mcp, behind the API-key
	// auth middleware (mounted earlier in the chain).
	r.Post("/mcp", handleMCP)
	// Inbound GitHub webhooks (WU-405): signature-verified, no API-key auth.
	r.Post("/hooks/github", handleGithubHook)
	// User settings actions (WU-108)
	r.Post("/api/action/user.theme.update", handleAction)
	r.Post("/api/action/user.timezone.update", handleAction)
	r.Post("/api/action/session.revoke", handleSessionRevoke)
	// Audit log routes (WU-110)
	r.Get("/app/org/{orgID}/audit", handleAuditLog)
	r.Get("/app/org/{orgID}/audit/export", handleAuditExport)
	r.Post("/api/action/audit.log.list", handleAction)
	r.Post("/api/action/audit.log.export", handleAction)
	// Task detail routes
	r.Get("/app/org/{orgID}/project/{projectID}/task/{taskID}", handleTaskDetail)
	r.Get("/app/org/{orgID}/project/{projectID}/task/{taskID}/run/{runID}", handleRunDetail)
	r.Get("/app/org/{orgID}/run/{runID}", handleRunDetail) // generic run detail (chat runs, WU-308)
	r.Post("/api/action/task.create", handleAction)
	r.Post("/api/action/task.update", handleAction)
	r.Post("/api/action/task.assign", handleAction)
	r.Post("/api/action/task.label", handleAction)
	r.Post("/api/action/task.relate", handleAction)
	r.Post("/api/action/task.archive", handleAction)
	r.Post("/api/action/task.unarchive", handleAction)
	r.Post("/api/action/label.create", handleAction)
	r.Post("/api/action/label.update", handleAction)
	r.Post("/api/action/comment.create", handleAction)
	r.Post("/api/action/comment.update", handleAction)
	r.Post("/api/action/comment.delete", handleAction)
	// Board routes
	r.Get("/app/org/{orgID}/project/{projectID}/board", handleBoardView)
	r.Get("/app/project/{projectID}/board/columns", handleBoardColumns)
	r.Get("/app/org/{orgID}/project/{projectID}/backlog", handleBacklogView)
	r.Get("/app/org/{orgID}/project/{projectID}/triggers", handleScheduledTriggers)
	// Chat routes (WU-308)
	r.Get("/app/chat", handleChatPage)
	r.Get("/app/chat/{chatID}/history", handleChatHistoryPartial)
	r.Post("/api/action/chat.session.create", handleAction)
	r.Post("/api/action/chat.send", handleAction)
	r.Post("/api/action/chat.history", handleAction)
	r.Post("/api/action/chat.session.list", handleAction)
	// Scheduled triggers (WU-309)
	r.Post("/api/action/trigger.create", handleAction)
	r.Post("/api/action/trigger.update", handleAction)
	r.Post("/api/action/trigger.delete", handleAction)
	r.Post("/api/action/trigger.list", handleAction)
	// Cost controls + usage (WU-310)
	r.Post("/api/action/pricing.upsert", handleAction)
	r.Post("/api/action/pricing.delete", handleAction)
	r.Post("/api/action/pricing.list", handleAction)
	r.Post("/api/action/org.cap.set", handleAction)
	r.Post("/api/action/usage.read", handleAction)
	r.Post("/api/action/agent.kill-all", handleAction)
	r.Post("/api/action/board.column.create", handleAction)
	r.Post("/api/action/board.column.update", handleAction)
	r.Post("/api/action/board.column.delete", handleAction)
	r.Post("/api/action/board.column.reorder", handleAction)
	// Task move (drag-and-drop / move-to-menu)
	r.Post("/api/action/task.move", handleAction)
	r.Post("/api/action/task.reorder", handleAction)
	// Saved filters + bulk ops
	r.Post("/api/action/saved_filter.create", handleAction)
	r.Post("/api/action/saved_filter.update", handleAction)
	r.Post("/api/action/saved_filter.delete", handleAction)
	r.Post("/api/action/task.bulk_assign", handleAction)
	r.Post("/api/action/task.bulk_label", handleAction)
	r.Post("/api/action/task.bulk_move", handleAction)
	// Partial-refresh routes (SSE-driven, WU-212)
	r.Get("/app/project/{projectID}/board/partial", handleBoardPartial)
	r.Get("/api/project/{projectID}/task/{taskID}/comments-partial", handleCommentsPartial)
	r.Get("/api/notif/unread-count", handleNotifUnreadCount)

	// Sprint routes
	r.Get("/app/org/{orgID}/project/{projectID}/sprints", handleSprintList)
	r.Post("/api/action/sprint.create", handleAction)
	r.Post("/api/action/sprint.update", handleAction)
	r.Post("/api/action/sprint.close", handleAction)
	r.Post("/api/action/sprint.add_task", handleAction)
	r.Post("/api/action/sprint.remove_task", handleAction)

	// Search routes
	r.Get("/app/search", handleSearchPage)
	r.Get("/api/search", handleSearchAPI)

	// Attachment routes
	r.Post("/api/action/attachment.upload", handleAction)
	r.Post("/api/action/attachment.delete", handleAction)
	r.Get("/files/{attachmentID}", handleAttachmentDownload)

	// Provider routes (WU-302)
	r.Get("/admin/providers", handleProviders)
	r.Post("/api/providers/create", handleProviderCreateAction)
	r.Post("/api/providers/delete", handleProviderDeleteAction)
	r.Post("/api/providers/allocate", handleProviderAllocateAction)

	// Agent routes (WU-303)
	r.Get("/app/org/{orgID}/agents", handleOrgAgents)
	r.Post("/api/agents/create", handleAgentCreateAction)
	r.Post("/api/agents/delete", handleAgentDeleteAction)

	// Skill routes (WU-304)
	r.Get("/app/org/{orgID}/skills", handleOrgSkills)
	r.Post("/api/skills/create", handleSkillCreateAction)
	r.Post("/api/skills/update", handleSkillUpdateAction)
	r.Post("/api/skills/delete", handleSkillDeleteAction)
}
