package web

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/search"
)

// WU-402 Resource routes + OpenAPI: resource-style GET aliases under
// /api/v1 with cursor pagination + ETag/If-Match on task update, plus a
// generated OpenAPI 3.1 document served at /api/v1/openapi.json and an
// embedded docs viewer page at /app/docs.

// cursorFor builds a base64 opaque cursor from a page offset (WU-402).
func cursorFor(offset int) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(offset)))
}

// nextCursor decodes an opaque cursor into a page offset (0 = start).
func nextCursor(c string) int {
	if c == "" {
		return 0
	}
	b, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(string(b))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// etagFor builds a strong ETag from an id + updated_at (task mutation guard).
func etagFor(id, updatedAt string) string {
	h := sha256.Sum256([]byte(id + ":" + updatedAt))
	return `"` + hex.EncodeToString(h[:]) + `"`
}

// requireAPIKey extracts the bearer API-key actor id or writes a 401 problem.
func requireAPIKey(w http.ResponseWriter, r *http.Request) (string, bool) {
	actor, ok := auth.APIKeyActorFrom(r.Context())
	if !ok {
		writeProblem(w, http.StatusUnauthorized, "unauthorized", "Bearer API key required", "")
		return "", false
	}
	return actor.ID, true
}

// orgExists verifies the org id resolves before a resource read (WU-402).
func orgExists(db *sql.DB, orgID string) bool {
	q := sqlc.New(db)
	if _, err := q.FindOrgByID(context.Background(), orgID); err != nil {
		return false
	}
	return true
}

// handleResourceProjects lists projects in an org with cursor pagination.
func handleResourceProjects(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireAPIKey(w, r); !ok {
		return
	}
	orgID := chi.URLParam(r, "orgID")
	if !orgExists(disp.DB(), orgID) {
		writeProblem(w, http.StatusNotFound, "not_found", "Org not found", orgID)
		return
	}
	q := sqlc.New(disp.DB())
	projects, err := q.ListProjectsByOrg(context.Background(), orgID)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "internal", "List projects", err.Error())
		return
	}
	// Cursor pagination over a stable name-ordered slice using an offset.
	offset := nextCursor(r.URL.Query().Get("cursor"))
	limit := pageLimit(r)
	items := make([]map[string]any, 0, limit)
	next := ""
	idx := 0
	for _, p := range projects {
		if idx < offset {
			idx++
			continue
		}
		if len(items) >= limit {
			break
		}
		items = append(items, map[string]any{
			"id": p.ID, "org_id": p.OrgID, "team_id": p.TeamID, "name": p.Name,
			"key": p.Key, "visibility": p.Visibility, "archived": p.Archived,
			"created_at": p.CreatedAt,
		})
		idx++
	}
	if len(items) >= limit && idx < len(projects) {
		next = cursorFor(idx)
	}
	writeResourceList(w, items, next)
}

// handleResourceTaskByKey resolves a task by the `KEY-n` alias
// (project key + number) and returns its detail (WU-402 AC).
func handleResourceTaskByKey(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireAPIKey(w, r); !ok {
		return
	}
	orgID := chi.URLParam(r, "orgID")
	projectKey := chi.URLParam(r, "projectKey")
	alias := chi.URLParam(r, "taskKey") // e.g. "3" from P1-3
	if !orgExists(disp.DB(), orgID) {
		writeProblem(w, http.StatusNotFound, "not_found", "Org not found", orgID)
		return
	}
	q := sqlc.New(disp.DB())
	proj, err := q.FindProjectByKey(context.Background(), sqlc.FindProjectByKeyParams{OrgID: orgID, Key: projectKey})
	if err != nil {
		writeProblem(w, http.StatusNotFound, "not_found", "Project not found", projectKey)
		return
	}
	num, err := strconv.Atoi(alias)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_input", "Bad task alias", alias)
		return
	}
	task, err := q.FindTaskByKey(context.Background(), sqlc.FindTaskByKeyParams{ProjectID: proj.ID, Key: projectKey, KeyNum: int64(num)})
	if err != nil {
		writeProblem(w, http.StatusNotFound, "not_found", "Task not found", alias)
		return
	}
	body := taskJSON(taskView{
		ID: task.ID, ProjectID: task.ProjectID, Title: task.Title, Description: task.Description,
		Key: task.Key, KeyNum: task.KeyNum, Points: task.Points, Priority: task.Priority,
		Status: task.Status, DueAt: task.DueAt, SortOrder: task.SortOrder, Archived: task.Archived,
		CreatedAt: task.CreatedAt, UpdatedAt: task.UpdatedAt,
	})
	w.Header().Set("ETag", etagFor(task.ID, task.UpdatedAt))
	writeResource(w, body)
}

// handleResourceComments lists comments on a task.
func handleResourceComments(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireAPIKey(w, r); !ok {
		return
	}
	orgID := chi.URLParam(r, "orgID")
	projectID := chi.URLParam(r, "projectID")
	taskID := chi.URLParam(r, "taskID")
	if !orgExists(disp.DB(), orgID) {
		writeProblem(w, http.StatusNotFound, "not_found", "Org not found", orgID)
		return
	}
	q := sqlc.New(disp.DB())
	comments, err := q.ListCommentsByTask(context.Background(), sqlc.ListCommentsByTaskParams{TaskID: taskID, ProjectID: projectID})
	if err != nil {
		writeProblem(w, http.StatusNotFound, "not_found", "Task not found", taskID)
		return
	}
	items := make([]map[string]any, 0, len(comments))
	for _, c := range comments {
		items = append(items, map[string]any{
			"id": c.ID, "task_id": c.TaskID, "author_id": c.AuthorID,
			"body": c.Body, "created_at": c.CreatedAt, "updated_at": c.UpdatedAt,
		})
	}
	writeResourceList(w, items, "")
}

// handleResourceSprints lists sprints for a project.
func handleResourceSprints(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireAPIKey(w, r); !ok {
		return
	}
	orgID := chi.URLParam(r, "orgID")
	projectID := chi.URLParam(r, "projectID")
	if !orgExists(disp.DB(), orgID) {
		writeProblem(w, http.StatusNotFound, "not_found", "Org not found", orgID)
		return
	}
	q := sqlc.New(disp.DB())
	sprints, err := q.ListSprints(context.Background(), projectID)
	if err != nil {
		writeProblem(w, http.StatusNotFound, "not_found", "Project not found", projectID)
		return
	}
	items := make([]map[string]any, 0, len(sprints))
	for _, s := range sprints {
		items = append(items, map[string]any{
			"id": s.ID, "project_id": s.ProjectID, "name": s.Name,
			"starts_on": s.StartsOn, "ends_on": s.EndsOn, "state": s.State,
			"created_at": s.CreatedAt,
		})
	}
	writeResourceList(w, items, "")
}

// handleResourceLabels lists labels in an org.
func handleResourceLabels(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireAPIKey(w, r); !ok {
		return
	}
	orgID := chi.URLParam(r, "orgID")
	if !orgExists(disp.DB(), orgID) {
		writeProblem(w, http.StatusNotFound, "not_found", "Org not found", orgID)
		return
	}
	q := sqlc.New(disp.DB())
	labels, err := q.ListLabelsByOrg(context.Background(), orgID)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "internal", "List labels", err.Error())
		return
	}
	items := make([]map[string]any, 0, len(labels))
	for _, l := range labels {
		items = append(items, map[string]any{
			"id": l.ID, "org_id": l.OrgID, "name": l.Name, "color": l.Color,
			"description": l.Description, "created_at": l.CreatedAt,
		})
	}
	writeResourceList(w, items, "")
}

// handleResourceSearch runs the search index scoped to the API-key actor.
func handleResourceSearch(w http.ResponseWriter, r *http.Request) {
	actorID, ok := requireAPIKey(w, r)
	if !ok {
		return
	}
	query := r.URL.Query().Get("q")
	if strings.TrimSpace(query) == "" {
		writeProblem(w, http.StatusBadRequest, "invalid_input", "Missing q", "")
		return
	}
	results, err := search.Query(context.Background(), disp.DB(), query, actorID, pageLimit(r))
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "internal", "Search", err.Error())
		return
	}
	writeResource(w, map[string]any{"results": results})
}

// handleResourceTaskUpdate updates a task, honoring ETag/If-Match → 412 on
// stale versions (WU-402 AC).
func handleResourceTaskUpdate(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireAPIKey(w, r); !ok {
		return
	}
	orgID := chi.URLParam(r, "orgID")
	projectID := chi.URLParam(r, "projectID")
	taskID := chi.URLParam(r, "taskID")
	if !orgExists(disp.DB(), orgID) {
		writeProblem(w, http.StatusNotFound, "not_found", "Org not found", orgID)
		return
	}
	q := sqlc.New(disp.DB())
	task, err := q.FindTaskByID(context.Background(), sqlc.FindTaskByIDParams{ID: taskID, ProjectID: projectID})
	if err != nil {
		writeProblem(w, http.StatusNotFound, "not_found", "Task not found", taskID)
		return
	}
	// Conditional update: If-Match must match the current ETag.
	if im := r.Header.Get("If-Match"); im != "" {
		cur := etagFor(task.ID, task.UpdatedAt)
		if im != cur && im != "*" {
			writeProblem(w, http.StatusPreconditionFailed, "conflict", "Stale version", "")
			return
		}
	}
	var in map[string]any
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_input", "Invalid JSON body", err.Error())
		return
	}
	title, _ := in["title"].(string)
	desc, _ := in["description"].(string)
	points := task.Points
	if v, ok := in["points"].(float64); ok {
		points = int64(v)
	}
	status, _ := in["status"].(string)
	if title == "" {
		title = task.Title
	}
	if desc == "" {
		desc = task.Description
	}
	if status == "" {
		status = task.Status
	}
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	updated, err := q.UpdateTask(context.Background(), sqlc.UpdateTaskParams{
		ID: task.ID, ProjectID: projectID,
		Title: title, Description: desc, Points: points, Priority: task.Priority,
		DueAt: task.DueAt, SortOrder: task.SortOrder, Status: status, UpdatedAt: now,
	})
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "internal", "Update task", err.Error())
		return
	}
	writeResource(w, taskJSON(taskView{
		ID: updated.ID, ProjectID: updated.ProjectID, Title: updated.Title, Description: updated.Description,
		Key: updated.Key, KeyNum: 0, Points: updated.Points, Priority: updated.Priority,
		Status: updated.Status, DueAt: updated.DueAt, SortOrder: updated.SortOrder, Archived: 0,
		CreatedAt: updated.CreatedAt, UpdatedAt: updated.UpdatedAt,
	}))
}

// taskView is the JSON shape for a task resource (WU-402).
type taskView struct {
	ID          string
	ProjectID   string
	Title       string
	Description string
	Key         string
	KeyNum      int64
	Points      int64
	Priority    int64
	Status      string
	DueAt       string
	SortOrder   float64
	Archived    int64
	CreatedAt   string
	UpdatedAt   string
}

// taskJSON maps a task view to a JSON object (WU-402 shape).
func taskJSON(t taskView) map[string]any {
	return map[string]any{
		"id": t.ID, "project_id": t.ProjectID, "title": t.Title,
		"description": t.Description, "key": t.Key, "key_num": t.KeyNum,
		"points": t.Points, "priority": t.Priority, "status": t.Status,
		"due_at": t.DueAt, "sort_order": t.SortOrder, "archived": t.Archived,
		"created_at": t.CreatedAt, "updated_at": t.UpdatedAt,
	}
}

// writeResource writes a single JSON resource body.
func writeResource(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// writeResourceList writes a paginated list envelope: {data:[...], next:...}.
func writeResourceList(w http.ResponseWriter, items []map[string]any, next string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"data": items, "next": next})
}

// pageLimit parses ?limit= into a bounded page size (default 50, max 200).
func pageLimit(r *http.Request) int {
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
			limit = n
		}
	}
	return limit
}
