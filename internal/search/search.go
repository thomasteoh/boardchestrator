// Package search provides FTS5 search indexing and querying.
package search

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Indexer handles FTS5 index updates. Create with NewIndexer, then call
// HandleEvent for each event the subscriber receives.
type Indexer struct {
	db *sql.DB
}

// NewIndexer creates an Indexer over db.
func NewIndexer(d *sql.DB) *Indexer {
	return &Indexer{db: d}
}

// IndexEvent processes a search-relevant event (task.create, comment.delete, etc.)
// evName and evPayload are the event name and raw JSON payload.
func (ix *Indexer) IndexEvent(ctx context.Context, evName string, evPayload json.RawMessage) error {
	switch evName {
	case "task.create", "task.update":
		var payload struct {
			ID          string `json:"id"`
			Title       string `json:"title"`
			Description string `json:"description"`
			Key         string `json:"key"`
			ProjectID   string `json:"project_id"`
		}
		if err := json.Unmarshal(evPayload, &payload); err != nil {
			return fmt.Errorf("index task: %w", err)
		}
		var rowid int64
		err := ix.db.QueryRowContext(ctx,
			"SELECT rowid FROM tasks WHERE id = ?", payload.ID,
		).Scan(&rowid)
		if err != nil {
			return nil // task may not exist yet
		}
		_, err = ix.db.ExecContext(ctx,
			`INSERT INTO tasks_fts (rowid, id, title, description, key, project_id)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			rowid, payload.ID, payload.Title, payload.Description, payload.Key, payload.ProjectID,
		)
		return err

	case "task.archive":
		var payload struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(evPayload, &payload); err != nil {
			return fmt.Errorf("index archive: %w", err)
		}
		_, err := ix.db.ExecContext(ctx,
			`DELETE FROM tasks_fts WHERE rowid IN (SELECT rowid FROM tasks WHERE id = ?)`,
			payload.ID,
		)
		return err

	case "comment.create", "comment.update":
		var payload struct {
			ID        string `json:"id"`
			Body      string `json:"body"`
			TaskID    string `json:"task_id"`
			ProjectID string `json:"project_id"`
		}
		if err := json.Unmarshal(evPayload, &payload); err != nil {
			return fmt.Errorf("index comment: %w", err)
		}
		var rowid int64
		err := ix.db.QueryRowContext(ctx,
			"SELECT rowid FROM comments WHERE id = ?", payload.ID,
		).Scan(&rowid)
		if err != nil {
			return nil
		}
		_, err = ix.db.ExecContext(ctx,
			`INSERT INTO comments_fts (rowid, id, body, task_id, project_id)
			 VALUES (?, ?, ?, ?, ?)`,
			rowid, payload.ID, payload.Body, payload.TaskID, payload.ProjectID,
		)
		return err

	case "comment.delete":
		var payload struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(evPayload, &payload); err != nil {
			return fmt.Errorf("index comment delete: %w", err)
		}
		_, err := ix.db.ExecContext(ctx,
			`DELETE FROM comments_fts WHERE rowid IN (SELECT rowid FROM comments WHERE id = ?)`,
			payload.ID,
		)
		return err
	}
	return nil
}

// QueryResult is a single search hit.
type QueryResult struct {
	Type      string `json:"type"` // "task" or "comment"
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`
	Title     string `json:"title,omitempty"`
	Key       string `json:"key,omitempty"`
	Body      string `json:"body,omitempty"`
	Status    string `json:"status,omitempty"`
}

// Query runs an FTS5 search across tasks and comments.
func Query(ctx context.Context, db *sql.DB, query string, userID string, limit int) ([]QueryResult, error) {
	if strings.TrimSpace(query) == "" {
		return nil, nil
	}
	if limit <= 0 {
		limit = 50
	}

	ftsQuery := buildFTSQuery(query)

	var results []QueryResult

	// Search tasks
	rows, err := db.QueryContext(ctx, `
		SELECT t.id, t.project_id, t.title, t.key, t.status
		FROM tasks t
		INNER JOIN tasks_fts ON tasks_fts.rowid = t.rowid
		WHERE tasks_fts MATCH ?
		ORDER BY rank
		LIMIT ?`, ftsQuery, limit)
	if err != nil {
		return nil, fmt.Errorf("search tasks: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var r QueryResult
		r.Type = "task"
		if err := rows.Scan(&r.ID, &r.ProjectID, &r.Title, &r.Key, &r.Status); err != nil {
			return nil, fmt.Errorf("scan task: %w", err)
		}
		results = append(results, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Search comments
	rows2, err := db.QueryContext(ctx, `
		SELECT c.id, c.task_id, c.project_id, c.body
		FROM comments c
		INNER JOIN comments_fts ON comments_fts.rowid = c.rowid
		WHERE comments_fts MATCH ?
		ORDER BY rank
		LIMIT ?`, ftsQuery, limit)
	if err != nil {
		return nil, fmt.Errorf("search comments: %w", err)
	}
	defer rows2.Close()
	for rows2.Next() {
		var r QueryResult
		r.Type = "comment"
		var taskID string
		if err := rows2.Scan(&r.ID, &taskID, &r.ProjectID, &r.Body); err != nil {
			return nil, fmt.Errorf("scan comment: %w", err)
		}
		r.Key = taskID // reuse Key field for task_id reference
		results = append(results, r)
	}
	if err := rows2.Err(); err != nil {
		return nil, err
	}

	return results, nil
}

// buildFTSQuery sanitises user input into a valid FTS5 query string with prefix matching.
func buildFTSQuery(raw string) string {
	parts := strings.Fields(raw)
	if len(parts) == 0 {
		return ""
	}
	var b strings.Builder
	for i, p := range parts {
		if i > 0 {
			b.WriteByte(' ')
		}
		p = strings.ReplaceAll(p, `"`, "")
		p = strings.ReplaceAll(p, "(", "")
		p = strings.ReplaceAll(p, ")", "")
		if p == "" {
			continue
		}
		b.WriteString(p)
		b.WriteByte('*')
	}
	return b.String()
}

// ErrProjectNotVisible is returned when the user has no access to a project.
var ErrProjectNotVisible = errors.New("project not visible")

// FilterByVisibility filters results to projects the user can see.
func FilterByVisibility(ctx context.Context, db *sql.DB, results []QueryResult, userID string) ([]QueryResult, error) {
	if userID == "" {
		return nil, nil
	}

	filtered := make([]QueryResult, 0, len(results))
	for _, r := range results {
		var count int
		err := db.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM memberships m
			JOIN projects p ON p.id = ? AND p.org_id = m.org_id
			WHERE m.actor_id = ? AND m.actor_type = 'user'`, r.ProjectID, userID,
		).Scan(&count)
		if err != nil {
			continue
		}
		if count > 0 {
			filtered = append(filtered, r)
		}
	}
	return filtered, nil
}
