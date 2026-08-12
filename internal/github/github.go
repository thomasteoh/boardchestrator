// Package github implements inbound GitHub webhooks (WU-405): signature
// verification, KEY-n extraction from branch/commit/PR bodies into github_links,
// and PR opened/merged → configured task transitions via the action dispatcher
// (actor: github integration service actor).
package github

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// keyRe matches a project key + numeric suffix: KEY-n (e.g. ABC-123).
var keyRe = regexp.MustCompile(`([A-Z][A-Z0-9_]*)-([0-9]+)`)

// Dispatcher is the subset of the action dispatcher the receiver needs.
type Dispatcher interface {
	Dispatch(ctx context.Context, actor action.Actor, name string, input json.RawMessage, opts action.Opts) (any, error)
	DB() *sql.DB
}

// Receiver handles inbound GitHub webhook deliveries.
type Receiver struct {
	db   *sql.DB
	disp Dispatcher
}

// New builds a receiver over the dispatcher.
func New(db *sql.DB, disp Dispatcher) *Receiver {
	return &Receiver{db: db, disp: disp}
}

// webhookPayload is the subset of a GitHub webhook body the receiver reads.
type webhookPayload struct {
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
	Ref    string `json:"ref"`
	Number int    `json:"number"`
	Action string `json:"action"`
	Title  string `json:"title"`
	Body   string `json:"body"`
	Head   struct {
		Sha string `json:"sha"`
	} `json:"head"`
	PullRequest struct {
		Title     string `json:"title"`
		Body      string `json:"body"`
		URL       string `json:"html_url"`
		Merged    bool   `json:"merged"`
		State     string `json:"state"`
		HeadLabel string `json:"head_label"`
	} `json:"pull_request"`
	Commits []struct {
		ID      string `json:"id"`
		Message string `json:"message"`
		URL     string `json:"url"`
	} `json:"commits"`
}

// Handle processes one GitHub webhook POST.
func (r *Receiver) Handle(w http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(io.LimitReader(req.Body, 1<<20))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	sigHeader := req.Header.Get("X-Hub-Signature-256")
	if sigHeader == "" {
		http.Error(w, "missing signature", http.StatusUnauthorized)
		return
	}
	event := req.Header.Get("X-GitHub-Event")

	var payload webhookPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "bad payload", http.StatusBadRequest)
		return
	}

	q := sqlc.New(r.db)
	cfg, err := q.FindProjectGithubByRepo(req.Context(), payload.Repository.FullName)
	if err != nil {
		http.Error(w, "unknown repo", http.StatusNotFound)
		return
	}
	if !verifySignature(cfg.WebhookSecret, sigHeader, body) {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	r.process(req.Context(), q, cfg, event, payload)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"ok":true}`))
}

// verifySignature compares X-Hub-Signature-256 to an HMAC-SHA256 of the body.
func verifySignature(secret, sigHeader string, body []byte) bool {
	const prefix = "sha256="
	if !strings.HasPrefix(sigHeader, prefix) {
		return false
	}
	got := strings.TrimPrefix(sigHeader, prefix)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	want := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(got), []byte(want))
}

// process extracts KEY-n refs, upserts github_links, and applies transitions.
func (r *Receiver) process(ctx context.Context, q *sqlc.Queries, cfg sqlc.ProjectGithub, event string, p webhookPayload) {
	switch event {
	case "push":
		if branch := branchFromRef(p.Ref); branch != "" {
			r.upsertFromText(ctx, q, cfg, "branch", branch, branch, "", "")
		}
		for _, c := range p.Commits {
			r.upsertFromText(ctx, q, cfg, "commit", c.ID, c.Message, c.URL, "commit.pushed")
		}
	case "pull_request":
		prNum := strconv.Itoa(p.Number)
		state := "pr." + p.Action
		r.upsertFromText(ctx, q, cfg, "pr", prNum, p.PullRequest.Title+"\n"+p.PullRequest.Body, p.PullRequest.URL, state)
		if hb := branchFromRef(p.Ref); hb != "" {
			r.upsertFromText(ctx, q, cfg, "branch", hb, hb, "", "")
		}
		// Merge → configured transition.
		if p.Action == "closed" && p.PullRequest.Merged {
			r.applyTransition(ctx, q, cfg, "merged")
		} else if p.Action == "opened" {
			r.applyTransition(ctx, q, cfg, "opened")
		}
	}
}

// branchFromRef extracts the branch name from a git ref ("refs/heads/main"
// → "main", "refs/heads/feature/x" → "feature/x").
func branchFromRef(ref string) string {
	const prefix = "refs/heads/"
	if strings.HasPrefix(ref, prefix) {
		return strings.TrimPrefix(ref, prefix)
	}
	if strings.HasPrefix(ref, "refs/tags/") {
		return strings.TrimPrefix(ref, "refs/tags/")
	}
	return ref
}

// upsertFromText extracts KEY-n refs from text and upserts a github_link row
// per match, resolving each to a task by (project_id, key, key_num).
func (r *Receiver) upsertFromText(ctx context.Context, q *sqlc.Queries, cfg sqlc.ProjectGithub, kind, ref, text, url, state string) {
	matches := keyRe.FindAllStringSubmatch(text, -1)
	for _, m := range matches {
		key := m[1]
		num, err := strconv.Atoi(m[2])
		if err != nil {
			continue
		}
		var taskID sql.NullString
		task, terr := q.FindTaskByKey(ctx, sqlc.FindTaskByKeyParams{
			ProjectID: cfg.ProjectID, Key: key, KeyNum: int64(num),
		})
		if terr == nil {
			taskID = sql.NullString{String: task.ID, Valid: true}
		}
		if _, uerr := q.UpsertGithubLink(ctx, sqlc.UpsertGithubLinkParams{
			ID: newID(), ProjectID: cfg.ProjectID, Kind: kind, Key: key, KeyNum: int64(num),
			Ref: ref, State: state, TaskID: taskID, Url: url,
		}); uerr != nil {
			// A failed link write is non-fatal; keep delivering other links.
			continue
		}
	}
}

// applyTransition dispatches task.move to the transition's target status for
// every task linked by PRs in this webhook, using the github service actor.
func (r *Receiver) applyTransition(ctx context.Context, q *sqlc.Queries, cfg sqlc.ProjectGithub, prState string) {
	var transitions map[string]string
	if err := json.Unmarshal([]byte(cfg.Transitions), &transitions); err != nil {
		return
	}
	target, ok := transitions[prState]
	if !ok || target == "" {
		return
	}
	orgID, err := q.GetProjectOrg(ctx, cfg.ProjectID)
	if err != nil {
		return
	}
	links, err := q.ListGithubLinksByProject(ctx, cfg.ProjectID)
	if err != nil {
		return
	}
	seen := map[string]bool{}
	for _, ln := range links {
		if ln.Kind != "pr" || !ln.TaskID.Valid {
			continue
		}
		if seen[ln.TaskID.String] {
			continue
		}
		seen[ln.TaskID.String] = true
		task, terr := q.FindTaskByID(ctx, sqlc.FindTaskByIDParams{ID: ln.TaskID.String, ProjectID: cfg.ProjectID})
		if terr != nil {
			continue
		}
		in := map[string]any{
			"id": task.ID, "project_id": cfg.ProjectID,
			"to_status": target, "sort_order": task.SortOrder,
		}
		raw, _ := json.Marshal(in)
		_, _ = r.disp.Dispatch(ctx, action.Actor{Type: action.ActorService, ID: "github"}, "task.move", raw,
			action.Opts{Org: orgID, Proj: cfg.ProjectID})
	}
}

// newID returns a unique id for a github_links row.
func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("gh-%d", time.Now().UnixNano())
	}
	return "gh-" + hex.EncodeToString(b)
}
