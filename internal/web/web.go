package web

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/storage"
	"github.com/thomasteoh/boardchestrator/internal/web/views"
)

// disp is the action dispatcher, set by SetDispatcher at startup.
var disp actionDispatcher

type actionDispatcher interface {
	Dispatch(ctx context.Context, actor action.Actor, name string, input json.RawMessage, opts action.Opts) (any, error)
}

func SetDispatcher(d actionDispatcher) { disp = d }

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
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	actor := action.Actor{Type: action.ActorUser, ID: "placeholder", IP: r.RemoteAddr}
	result, err := disp.Dispatch(r.Context(), actor, name, input, action.Opts{})
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

// handleTaskDetail renders the full task detail page.
func handleTaskDetail(w http.ResponseWriter, r *http.Request) {
	s := shellData(r, "Task Detail", "/tasks")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Stub: return empty detail until the DB-backed handler is wired.
	if err := views.TaskDetailPage(s, views.TaskDetail{}, nil, nil).Render(r.Context(), w); err != nil {
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
	if err := views.ColumnSettingsPage(s, projectID, nil).Render(r.Context(), w); err != nil {
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
	// Task detail routes
	r.Get("/app/org/{orgID}/project/{projectID}/task/{taskID}", handleTaskDetail)
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
	// Sprint routes
	r.Get("/app/org/{orgID}/project/{projectID}/sprints", handleSprintList)
	r.Post("/api/action/sprint.create", handleAction)
	r.Post("/api/action/sprint.update", handleAction)
	r.Post("/api/action/sprint.close", handleAction)
	r.Post("/api/action/sprint.add_task", handleAction)
	r.Post("/api/action/sprint.remove_task", handleAction)

	// Attachment routes
	r.Post("/api/action/attachment.upload", handleAction)
	r.Post("/api/action/attachment.delete", handleAction)
	r.Get("/files/{attachmentID}", handleAttachmentDownload)
}
