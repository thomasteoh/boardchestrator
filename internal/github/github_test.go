package github

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

var ctx = context.Background()

// seed creates an org, project, task (ABC-1), and project_github config row.
func seed(t *testing.T, db *sql.DB, secret string) (orgID, projID, taskID, repo string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO orgs (id, name, slug, context, visibility) VALUES ('org1','Acme','acme','','private')`); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO projects (id, org_id, name, key, context, visibility) VALUES ('proj1','org1','Core','ABC','','private')`); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO tasks (id, project_id, title, key, key_num, status, sort_order) VALUES ('task1','proj1','Do thing','ABC',1,'backlog',0)`); err != nil {
		t.Fatalf("seed task: %v", err)
	}
	repo = "acme/core"
	q := sqlc.New(db)
	_, err := q.UpsertProjectGithub(ctx, sqlc.UpsertProjectGithubParams{
		ID: "pg1", ProjectID: "proj1", Repo: repo,
		Transitions: `{"opened":"todo","merged":"done"}`, WebhookSecret: secret, Enabled: 1,
	})
	if err != nil {
		t.Fatalf("seed project_github: %v", err)
	}
	return "org1", "proj1", "task1", repo
}

// sign returns the X-Hub-Signature-256 header value for body.
func sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// deliver sends a signed webhook body and returns the recorder.
func deliver(t *testing.T, db *sql.DB, disp *action.Dispatcher, event, secret string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/hooks/github", strings.NewReader(string(body)))
	req.Header.Set("X-GitHub-Event", event)
	req.Header.Set("X-Hub-Signature-256", sign(secret, body))
	rr := httptest.NewRecorder()
	New(db, disp).Handle(rr, req)
	return rr
}

// TestSignatureReject verifies bad secret / missing signature / unknown repo
// are rejected, and a correct secret succeeds.
func TestSignatureReject(t *testing.T) {
	db := dbtest.New(t)
	disp := action.New(db)
	_, _, _, repo := seed(t, db, "correct-horse")

	body := []byte(`{"repository":{"full_name":"` + repo + `"},"ref":"refs/heads/feature/ABC-1"}`)

	// Wrong secret → 401.
	if rr := deliver(t, db, disp, "push", "wrong-secret", body); rr.Code != http.StatusUnauthorized {
		t.Fatalf("wrong secret: got %d, want 401", rr.Code)
	}
	// No signature → 401.
	req := httptest.NewRequest(http.MethodPost, "/hooks/github", strings.NewReader(string(body)))
	req.Header.Set("X-GitHub-Event", "push")
	rr := httptest.NewRecorder()
	New(db, disp).Handle(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("no signature: got %d, want 401", rr.Code)
	}
	// Unknown repo → 404.
	unknown := []byte(`{"repository":{"full_name":"nope/x"}}`)
	if rr := deliver(t, db, disp, "push", "correct-horse", unknown); rr.Code != http.StatusNotFound {
		t.Fatalf("unknown repo: got %d, want 404", rr.Code)
	}
	// Correct secret → 200.
	if rr := deliver(t, db, disp, "push", "correct-horse", body); rr.Code != http.StatusOK {
		t.Fatalf("valid: got %d, want 200: %s", rr.Code, rr.Body.String())
	}
}

// TestExtractionTable drives KEY-n extraction across branch/commit bodies and
// verifies github_links rows + task resolution.
func TestExtractionTable(t *testing.T) {
	db := dbtest.New(t)
	disp := action.New(db)
	_, _, _, repo := seed(t, db, "s3cret")

	body := []byte(`{
		"repository":{"full_name":"` + repo + `"},
		"ref":"refs/heads/feature/ABC-1",
		"commits":[
			{"id":"c1","message":"fixes ABC-1: bug","url":"https://github.com/acme/core/commit/c1"},
			{"id":"c2","message":"adds ABC-2: feature","url":"https://github.com/acme/core/commit/c2"}
		]
	}`)
	if rr := deliver(t, db, disp, "push", "s3cret", body); rr.Code != http.StatusOK {
		t.Fatalf("push: got %d: %s", rr.Code, rr.Body.String())
	}

	q := sqlc.New(db)
	links, err := q.ListGithubLinksByProject(ctx, "proj1")
	if err != nil {
		t.Fatalf("list links: %v", err)
	}
	got := map[string]string{}
	for _, ln := range links {
		got[ln.Kind+":"+ln.Ref] = ln.State
	}
	if _, ok := got["branch:feature/ABC-1"]; !ok {
		t.Fatalf("missing branch link: %v", got)
	}
	if got["commit:c1"] != "commit.pushed" {
		t.Fatalf("commit c1 state: %q", got["commit:c1"])
	}
	// ABC-1 commit resolves to task1.
	var taskID string
	for _, ln := range links {
		if ln.Kind == "commit" && ln.Ref == "c1" && ln.TaskID.Valid && ln.TaskID.String == "task1" {
			taskID = ln.TaskID.String
		}
	}
	if taskID != "task1" {
		t.Fatalf("ABC-1 not resolved to task1: %+v", links)
	}
}

// TestMergeTransition verifies a merged PR dispatches task.move to the
// configured "merged"→status transition via the github service actor.
func TestMergeTransition(t *testing.T) {
	db := dbtest.New(t)
	disp := action.New(db)
	_, _, _, repo := seed(t, db, "s3cret")

	// Opened PR referencing ABC-1.
	openBody := []byte(`{
		"repository":{"full_name":"` + repo + `"},
		"action":"opened","number":42,
		"ref":"refs/heads/feature/ABC-1",
		"pull_request":{"title":"ABC-1: thing","body":"closes ABC-1","html_url":"https://github.com/acme/core/pull/42","merged":false,"state":"open"}
	}`)
	if rr := deliver(t, db, disp, "pull_request", "s3cret", openBody); rr.Code != http.StatusOK {
		t.Fatalf("opened: got %d", rr.Code)
	}

	// Merged (closed + merged).
	mergedBody := []byte(`{
		"repository":{"full_name":"` + repo + `"},
		"action":"closed","number":42,
		"ref":"refs/heads/feature/ABC-1",
		"pull_request":{"title":"ABC-1: thing","body":"closes ABC-1","html_url":"https://github.com/acme/core/pull/42","merged":true,"state":"closed"}
	}`)
	if rr := deliver(t, db, disp, "pull_request", "s3cret", mergedBody); rr.Code != http.StatusOK {
		t.Fatalf("merged: got %d", rr.Code)
	}

	q := sqlc.New(db)
	task, err := q.FindTaskByID(ctx, sqlc.FindTaskByIDParams{ID: "task1", ProjectID: "proj1"})
	if err != nil {
		t.Fatalf("find task: %v", err)
	}
	if task.Status != "done" {
		t.Fatalf("merged transition not applied: status=%q want done", task.Status)
	}
}

// TestLinkList verifies the link data surfaced for the task page (link render
// data): ListGithubLinksByTask returns the PR link for a task.
func TestLinkList(t *testing.T) {
	db := dbtest.New(t)
	disp := action.New(db)
	_, _, _, repo := seed(t, db, "s3cret")

	body := []byte(`{
		"repository":{"full_name":"` + repo + `"},
		"action":"opened","number":7,
		"ref":"refs/heads/feature/ABC-1",
		"pull_request":{"title":"ABC-1: thing","body":"fixes ABC-1","html_url":"https://github.com/acme/core/pull/7","merged":false,"state":"open"}
	}`)
	if rr := deliver(t, db, disp, "pull_request", "s3cret", body); rr.Code != http.StatusOK {
		t.Fatalf("pr: got %d", rr.Code)
	}

	q := sqlc.New(db)
	links, err := q.ListGithubLinksByTask(ctx, sql.NullString{String: "task1", Valid: true})
	if err != nil {
		t.Fatalf("list by task: %v", err)
	}
	found := false
	for _, ln := range links {
		if ln.Kind == "pr" && ln.Ref == "7" && ln.TaskID.Valid && ln.TaskID.String == "task1" {
			found = true
			if !strings.HasPrefix(ln.Url, "https://github.com/acme/core/pull/7") {
				t.Fatalf("pr url: %q", ln.Url)
			}
		}
	}
	if !found {
		t.Fatalf("no pr link for task1: %+v", links)
	}
}
