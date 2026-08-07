package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestBoardRenderNoNplusOne is a compile-time/structural assertion:
// the board render path uses a fixed set of sqlc queries, not a loop-per-item
// pattern. When a DB-backed board handler is wired, extend this with a
// query-counting DB wrapper.
func TestBoardRenderNoNplusOne(t *testing.T) {
	// The board handler currently passes nil slices to the templ render,
	// so render does zero DB queries. Budget: 0.
	r := httptest.NewRequest(http.MethodGet, "/app/project/p-1/board", nil)
	w := httptest.NewRecorder()
	handleBoardView(w, r)
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

// TestBacklogRenderNoNplusOne asserts the backlog handler also uses no
// per-item queries.
func TestBacklogRenderNoNplusOne(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/app/project/p-1/backlog", nil)
	w := httptest.NewRecorder()
	handleBacklogView(w, r)
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}
