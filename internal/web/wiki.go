package web

import (
	"context"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/web/views"
)

// handleWikiPage renders the wiki read view for the current page (or the tree
// root if no path is given). It falls back to a "no wiki configured" or
// "connect GitHub" prompt as appropriate.
func handleWikiPage(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	path := chi.URLParam(r, "path")
	if path == "" {
		path = "index.md"
	} else if !strings.HasSuffix(path, ".md") {
		path = strings.TrimSuffix(path, "/") + ".md"
	}
	title := "Wiki"
	s := shellData(r, title, "/wiki")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	page, err := wikiStore.ReadPage(r.Context(), orgID, path)
	if err != nil {
		renderWikiError(w, r, s, orgID, err)
		return
	}
	// Tree for nav.
	tree, err := wikiStore.PageTree(r.Context(), orgID)
	if err != nil {
		tree = nil
	}
	// Whether the actor can edit (has a linked GitHub token + edit permission).
	canEdit := actorCanEditWiki(r.Context(), orgID)
	if err := views.WikiPage(s, orgID, path, page, tree, canEdit).Render(r.Context(), w); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// handleWikiEditPage renders the markdown editor with live preview.
func handleWikiEditPage(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	path := chi.URLParam(r, "path")
	if !strings.HasSuffix(path, ".md") {
		path = strings.TrimSuffix(path, "/") + ".md"
	}
	s := shellData(r, "Edit Wiki", "/wiki")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	page, err := wikiStore.ReadPage(r.Context(), orgID, path)
	if err != nil {
		renderWikiError(w, r, s, orgID, err)
		return
	}
	if err := views.WikiEditPage(s, orgID, path, page.Markdown).Render(r.Context(), w); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// handleWikiHistoryPage renders the commit history for a page.
func handleWikiHistoryPage(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	path := chi.URLParam(r, "path")
	if !strings.HasSuffix(path, ".md") {
		path = strings.TrimSuffix(path, "/") + ".md"
	}
	s := shellData(r, "Wiki History", "/wiki")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	commits, err := wikiStore.History(r.Context(), orgID, path)
	if err != nil {
		renderWikiError(w, r, s, orgID, err)
		return
	}
	if err := views.WikiHistoryPage(s, orgID, path, commits).Render(r.Context(), w); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// renderWikiError renders the read page with the error surfaced — including
// the "connect GitHub" / "no wiki configured" prompts.
func renderWikiError(w http.ResponseWriter, r *http.Request, s views.Shell, orgID string, err error) {
	tree, terr := wikiStore.PageTree(r.Context(), orgID)
	if terr != nil {
		tree = nil
	}
	canEdit := actorCanEditWiki(r.Context(), orgID)
	msg := err.Error()
	if err := views.WikiError(s, orgID, msg, tree, canEdit).Render(r.Context(), w); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// actorCanEditWiki reports whether the session's actor can edit: they must
// have a linked GitHub token (commit-as-user) and hold the wiki.edit
// permission in this org. The action layer enforces the permission on submit;
// this gate only hides the editor for unlinked users (read-only wiki).
func actorCanEditWiki(ctx context.Context, orgID string) bool {
	sess, ok := auth.SessionFrom(ctx)
	if !ok || sess.UserID == "" || disp == nil || disp.DB() == nil {
		return false
	}
	conn, err := sqlc.New(disp.DB()).FindGithubConnection(ctx, sess.UserID)
	if err != nil {
		return false // not connected → read-only
	}
	return conn.TokenEnc != ""
}
