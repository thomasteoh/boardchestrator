package wiki

import (
	"context"
	"fmt"
	"strings"
)

// TaskLink is one task referencing a wiki page (via [[page]] syntax in its
// description or a comment). Used for the wiki backlink list (WU-503).
type TaskLink struct {
	TaskID    string `json:"task_id"`
	ProjectID string `json:"project_id"`
	Key       string `json:"key"`
	Title     string `json:"title"`
	Status    string `json:"status"`
}

// Backlinks lists tasks in an org that reference this wiki page. A task
// references a page when its description or one of its comments contains
// [[name]] where name is the page's display name (e.g. [[onboarding]] matches
// docs/onboarding.md) or the page's full path. Returns nil for no references.
func (s *Store) Backlinks(ctx context.Context, orgID, pagePath string) ([]TaskLink, error) {
	name := backlinkName(pagePath)
	// Match both the display name and the full repo path in the [[...]] token.
	like := "%[[" + name + "]]%"
	pathLike := "%[[" + pagePath + "]]%"

	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT t.id, t.project_id, t.key, t.title, t.status
		FROM tasks t
		JOIN projects p ON p.id = t.project_id
		WHERE p.org_id = ?
		  AND (
		    t.description LIKE ? OR t.description LIKE ?
		    OR EXISTS (
		      SELECT 1 FROM comments c
		      WHERE c.task_id = t.id
		        AND (c.body LIKE ? OR c.body LIKE ?)
		    )
		  )
		ORDER BY t.key`, orgID, like, pathLike, like, pathLike)
	if err != nil {
		return nil, fmt.Errorf("wiki: backlinks: %w", err)
	}
	defer rows.Close()

	var links []TaskLink
	for rows.Next() {
		var l TaskLink
		if err := rows.Scan(&l.TaskID, &l.ProjectID, &l.Key, &l.Title, &l.Status); err != nil {
			return nil, fmt.Errorf("wiki: backlinks scan: %w", err)
		}
		links = append(links, l)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return links, nil
}

// ResolvePage maps a [[name]] reference to the repo path of a wiki page in
// the org, or "" if no page matches. It matches by display name (case- and
// space-insensitive) then by full path. This backs [[wiki page]] autolinking
// in task descriptions/comments (WU-503).
func (s *Store) ResolvePage(ctx context.Context, orgID, name string) (string, error) {
	pages, err := s.PageTree(ctx, orgID)
	if err != nil {
		return "", err
	}
	want := strings.ToLower(strings.TrimSuffix(name, ".md"))
	for _, p := range pages {
		if strings.ToLower(backlinkName(p.Path)) == want || strings.ToLower(p.Path) == want {
			return p.Path, nil
		}
	}
	return "", nil
}

// backlinkName derives the [[...]] display name for a page path
// (docs/onboarding.md → onboarding).
func backlinkName(path string) string {
	base := path
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	return strings.TrimSuffix(base, ".md")
}
