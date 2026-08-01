// Package notify subscribes to action events and creates notification rows
// for the right users. Grouping coalesces multiple events on the same subject
// into a single notification row.
package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// GroupWindow is how long we coalesce notifications with the same grouping_key.
const GroupWindow = 5 * time.Minute

// Engine subscribes to action events and creates notification rows.
type Engine struct {
	q   *sqlc.Queries
	now func() time.Time
}

// New creates a notification engine.
func New(q *sqlc.Queries) *Engine {
	return &Engine{q: q, now: time.Now}
}

// HandleEvent processes one action event and creates notification rows.
func (e *Engine) HandleEvent(ctx context.Context, ev action.Event) (int, error) {
	switch ev.Name {
	case "task.create", "task.update", "task.assign":
		return e.handleTaskEvent(ctx, ev)
	default:
		return 0, nil
	}
}

func (e *Engine) handleTaskEvent(ctx context.Context, ev action.Event) (int, error) {
	var payload struct {
		ID        string   `json:"ID"`
		Title     string   `json:"Title"`
		Status    string   `json:"Status"`
		Assignee  string   `json:"Assignee"`
		ProjectID string   `json:"ProjectID"`
		MemberIDs []string `json:"MemberIDs"`
	}
	if err := json.Unmarshal(ev.Payload, &payload); err != nil {
		return 0, fmt.Errorf("notify: unmarshal: %w", err)
	}

	var userIDs []string
	switch ev.Name {
	case "task.assign":
		if payload.Assignee != "" {
			userIDs = []string{payload.Assignee}
		}
	case "task.create":
		userIDs = payload.MemberIDs
	case "task.update":
		if payload.Assignee != "" {
			userIDs = []string{payload.Assignee}
		}
	}

	title := eventTitle(ev.Name, payload.Title)
	body := eventBody(ev.Name, payload.Title, payload.Status)
	groupingKey := ev.Name + ":" + payload.ID

	created := 0
	for _, uid := range userIDs {
		if uid == ev.Actor.ID && ev.Name != "task.assign" {
			continue // self-action excluded
		}
		n, err := e.insertOrGroup(ctx, uid, ev, payload.ProjectID, title, body, groupingKey)
		if err != nil {
			return created, err
		}
		created += n
	}
	return created, nil
}

func (e *Engine) insertOrGroup(ctx context.Context, userID string, ev action.Event, projectID, title, body, groupingKey string) (int, error) {
	existing, err := e.q.FindGroupedNotification(ctx, groupingKey)
	if err == nil && existing.ReadAt == "" {
		// Group: mark old read, insert fresh.
		if err := e.q.MarkNotificationRead(ctx, sqlc.MarkNotificationReadParams{
			ReadAt: e.now().UTC().Format(time.RFC3339),
			ID:     existing.ID,
			UserID: userID,
		}); err != nil {
			return 0, fmt.Errorf("notify: mark old: %w", err)
		}
	}

	id := newID()
	if _, err := e.q.CreateNotification(ctx, sqlc.CreateNotificationParams{
		ID:          id,
		OrgID:       ev.Org,
		UserID:      userID,
		EventName:   ev.Name,
		SubjectID:   ev.Subject,
		Title:       title,
		Body:        body,
		GroupingKey: groupingKey,
	}); err != nil {
		return 0, fmt.Errorf("notify: create: %w", err)
	}
	return 1, nil
}

func eventTitle(name, taskTitle string) string {
	switch name {
	case "task.create":
		return "New task: " + taskTitle
	case "task.update":
		return "Task updated: " + taskTitle
	case "task.assign":
		return "You were assigned: " + taskTitle
	default:
		return taskTitle
	}
}

func eventBody(name, taskTitle, status string) string {
	switch name {
	case "task.create":
		return taskTitle + " was created"
	case "task.update":
		return taskTitle + " is now " + status
	case "task.assign":
		return taskTitle + " was assigned to you"
	default:
		return ""
	}
}

func newID() string {
	return fmt.Sprintf("%x", time.Now().UnixNano())
}
