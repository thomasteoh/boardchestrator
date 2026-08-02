package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestNotifUnreadCountReturnsJSON asserts the unread count endpoint returns
// valid JSON even when unauthenticated.
func TestNotifUnreadCountReturnsJSON(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/notif/unread-count", nil)
	w := httptest.NewRecorder()
	handleNotifUnreadCount(w, r)
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	var data map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		t.Fatalf("response body not valid JSON: %v", err)
	}
	count, ok := data["count"].(float64)
	if !ok {
		t.Error("count field not a number")
	}
	if count != 0 {
		t.Errorf("expected count=0, got %.0f", count)
	}
}

// TestBoardPartialHandler asserts the handler responds without panic.
func TestBoardPartialHandler(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/app/project/proj-1/board/partial", nil)
	w := httptest.NewRecorder()
	handleBoardPartial(w, r)
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

// TestCommentsPartialHandler asserts the handler responds without panic.
func TestCommentsPartialHandler(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/project/proj-1/task/task-1/comments-partial", nil)
	w := httptest.NewRecorder()
	handleCommentsPartial(w, r)
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}
