package web

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// seedResourceOrg seeds an org + project with tasks for the resource tests.
func seedResourceOrg(t *testing.T, db *sql.DB) (orgID, projectID string) {
	t.Helper()
	q := sqlc.New(db)
	if _, err := db.Exec(`INSERT INTO orgs (id, name, slug, visibility, context, monthly_cap_usd, cap_alert_pct) VALUES ('resorg', 'Res', 'res', 'private', '', 0, 80)`); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	proj, err := q.CreateProject(context.Background(), sqlc.CreateProjectParams{
		ID: "resproj", OrgID: "resorg", Name: "Res Project",
		Key: "RP", Context: "", Visibility: "private",
	})
	if err != nil {
		t.Fatalf("seed project: %v", err)
	}
	return "resorg", proj.ID
}

func seedTask(t *testing.T, db *sql.DB, projectID, key string, num int64, title string) {
	t.Helper()
	q := sqlc.New(db)
	_, err := q.CreateTask(context.Background(), sqlc.CreateTaskParams{
		ID: key + "-" + fmt.Sprint(num), ProjectID: projectID, Title: title,
		Description: "", Key: key, KeyNum: num, Points: 0, Priority: 0,
		Status: "backlog", DueAt: "", SortOrder: 0,
	})
	if err != nil {
		t.Fatalf("seed task %s: %v", key, err)
	}
}

func v1Get(t *testing.T, router http.Handler, token, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// TestResourcePagination covers WU-402 AC: pagination round-trip. Seed more
// projects than the page limit and walk the cursor until exhausted, asserting
// every project is seen exactly once.
func TestResourcePagination(t *testing.T) {
	resetV1()
	t.Cleanup(resetV1)
	db := dbtest.New(t)
	router, token := newV1Router(t, db)
	_, projID := seedResourceOrg(t, db)
	q := sqlc.New(db)
	// Seed 7 projects under the same org.
	for i := 0; i < 7; i++ {
		if _, err := q.CreateProject(context.Background(), sqlc.CreateProjectParams{
			ID: fmt.Sprintf("rp%d", i), OrgID: "resorg", Name: fmt.Sprintf("P%d", i),
			Key: fmt.Sprintf("K%d", i), Context: "", Visibility: "private",
		}); err != nil {
			t.Fatalf("seed project %d: %v", i, err)
		}
	}
	_ = projID

	seen := map[string]bool{}
	cursor := ""
	page := 0
	for {
		path := "/api/v1/orgs/resorg/projects?limit=3"
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		rec := v1Get(t, router, token, path)
		if rec.Code != http.StatusOK {
			t.Fatalf("page %d: status %d", page, rec.Code)
		}
		var body struct {
			Data []map[string]any `json:"data"`
			Next string           `json:"next"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode page: %v", err)
		}
		for _, p := range body.Data {
			id := p["id"].(string)
			if seen[id] {
				t.Fatalf("duplicate project %s across pages", id)
			}
			seen[id] = true
		}
		page++
		if body.Next == "" {
			break
		}
		cursor = body.Next
		if page > 10 {
			t.Fatalf("cursor did not terminate")
		}
	}
	if len(seen) != 8 { // resproj + 7 seeded
		t.Fatalf("round-trip saw %d projects, want 8", len(seen))
	}
}

// TestResourceTaskETag covers WU-402 AC: stale If-Match → 412; fresh
// If-Match / no If-Match → 200. Also exercises the KEY-n lookup.
func TestResourceTaskETag(t *testing.T) {
	resetV1()
	t.Cleanup(resetV1)
	db := dbtest.New(t)
	router, token := newV1Router(t, db)
	_, projID := seedResourceOrg(t, db)
	seedTask(t, db, projID, "RP", 3, "Third task")

	// GET by KEY-n alias → ETag.
	get := v1Get(t, router, token, "/api/v1/orgs/resorg/projects/RP/tasks/3")
	if get.Code != http.StatusOK {
		t.Fatalf("get by key: status %d", get.Code)
	}
	etag := get.Header().Get("ETag")
	if etag == "" {
		t.Fatalf("missing ETag on task GET")
	}

	put := func(ifMatch, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut,
			"/api/v1/orgs/resorg/projects/"+projID+"/tasks/RP-3", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		if ifMatch != "" {
			req.Header.Set("If-Match", ifMatch)
		}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}

	// Stale If-Match → 412.
	stale := put(`"deadbeef"`, `{"title":"changed"}`)
	if stale.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale If-Match: status %d, want 412", stale.Code)
	}
	var p problem
	if err := json.Unmarshal(stale.Body.Bytes(), &p); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if p.Type != "conflict" {
		t.Fatalf("problem type %q, want conflict", p.Type)
	}

	// Fresh If-Match → 200.
	fresh := put(etag, `{"title":"renamed"}`)
	if fresh.Code != http.StatusOK {
		t.Fatalf("fresh If-Match: status %d, want 200", fresh.Code)
	}
	if !strings.Contains(fresh.Body.String(), `"renamed"`) {
		t.Fatalf("update body missing new title: %s", fresh.Body.String())
	}

	// No If-Match → 200 (unconditional update allowed).
	noMatch := put("", `{"status":"done"}`)
	if noMatch.Code != http.StatusOK {
		t.Fatalf("no If-Match: status %d, want 200", noMatch.Code)
	}
}

// TestOpenAPIValidates covers WU-402 AC: the OpenAPI 3.1 document is served
// and validates against the schema shape (openapi version, info, paths,
// securitySchemes, components).
func TestOpenAPIValidates(t *testing.T) {
	db := dbtest.New(t)
	router, _ := newV1Router(t, db)
	rec := v1Get(t, router, "", "/api/v1/openapi.json")
	if rec.Code != http.StatusOK {
		t.Fatalf("openapi: status %d, want 200", rec.Code)
	}
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode openapi: %v", err)
	}
	if doc["openapi"] != "3.1.0" {
		t.Fatalf("openapi version %v, want 3.1.0", doc["openapi"])
	}
	info, ok := doc["info"].(map[string]any)
	if !ok || info["title"] == "" || info["version"] == "" {
		t.Fatalf("info missing title/version: %v", doc["info"])
	}
	paths, ok := doc["paths"].(map[string]any)
	if !ok || len(paths) == 0 {
		t.Fatalf("paths empty")
	}
	if _, ok := paths["/actions/{name}"]; !ok {
		t.Fatalf("missing /actions/{name} path")
	}
	comps, ok := doc["components"].(map[string]any)
	if !ok {
		t.Fatalf("missing components")
	}
	ss, ok := comps["securitySchemes"].(map[string]any)
	if !ok || ss["BearerAuth"] == nil {
		t.Fatalf("missing BearerAuth security scheme")
	}
	schemas, ok := comps["schemas"].(map[string]any)
	if !ok || schemas["Problem"] == nil {
		t.Fatalf("missing Problem schema")
	}
}

// TestDocsPageRenders covers WU-402 AC (extended): the in-app help area
// renders the overview with the guide sidebar and the API reference link.
func TestDocsPageRenders(t *testing.T) {
	db := dbtest.New(t)
	router, _ := newV1Router(t, db)
	rec := v1Get(t, router, "", "/app/docs")
	if rec.Code != http.StatusOK {
		t.Fatalf("docs page: status %d, want 200", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Fatalf("docs content-type %q, want text/html", ct)
	}
	if !strings.Contains(rec.Body.String(), "Boardchestrator help") {
		t.Fatalf("docs page missing help overview")
	}
	if !strings.Contains(rec.Body.String(), "Getting started") {
		t.Fatalf("docs page missing guide nav")
	}
	if !strings.Contains(rec.Body.String(), "/api/v1/openapi.json") {
		t.Fatalf("docs page missing API reference link")
	}
}

// TestDocsGuideRenders checks each embedded guide renders as an app page.
func TestDocsGuideRenders(t *testing.T) {
	db := dbtest.New(t)
	router, _ := newV1Router(t, db)
	for _, slug := range docsSlugs() {
		if slug == "index" {
			continue
		}
		rec := v1Get(t, router, "", "/app/docs/"+slug)
		if rec.Code != http.StatusOK {
			t.Fatalf("docs/%s: status %d, want 200", slug, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "Help") {
			t.Fatalf("docs/%s: missing app shell title", slug)
		}
	}
}
