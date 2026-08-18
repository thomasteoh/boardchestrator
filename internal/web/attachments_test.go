package web

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/storage"
)

// seedAttachmentFixture creates a user, org, project, task, and an attachment
// row backed by a real local file, and returns the attachment id and storage
// key. It uploads through the given store so the file is readable by the
// download handler when fileStore is set to the same store.
func seedAttachmentFixture(t *testing.T, db *sql.DB, orgID, userID string, store storage.Store) (attID, storageKey string) {
	t.Helper()
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `INSERT INTO users (id, email, name) VALUES (?, ?, 'U')`, userID, userID+"@acme.test"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	org, err := sqlc.New(db).CreateOrg(ctx, sqlc.CreateOrgParams{ID: orgID, Name: "Acme", Slug: orgID, Context: "", Visibility: "private"})
	if err != nil {
		t.Fatalf("seed org: %v", err)
	}
	proj, err := sqlc.New(db).CreateProject(ctx, sqlc.CreateProjectParams{ID: "proj" + orgID, OrgID: org.ID, Name: "P", Key: "P1", Visibility: "private"})
	if err != nil {
		t.Fatalf("seed project: %v", err)
	}
	if _, err := sqlc.New(db).CreateTask(ctx, sqlc.CreateTaskParams{
		ID: "task" + orgID, ProjectID: proj.ID, Title: "T", Key: "P1-1", KeyNum: 1,
		Points: 0, Priority: 0, Status: "todo", DueAt: "", SortOrder: 0,
	}); err != nil {
		t.Fatalf("seed task: %v", err)
	}
	// Upload through the store so the file actually exists for Open().
	attID, storageKey, _, err = store.Upload(ctx, "notes.txt", []byte("hello"), orgID, "task"+orgID)
	if err != nil {
		t.Fatalf("store upload: %v", err)
	}
	if _, err := sqlc.New(db).CreateAttachment(ctx, sqlc.CreateAttachmentParams{
		ID: attID, OrgID: org.ID, TaskID: "task" + orgID, UploaderID: userID,
		Filename: "notes.txt", Mime: "text/plain", Size: 5, StorageKey: storageKey,
	}); err != nil {
		t.Fatalf("create attachment: %v", err)
	}
	return attID, storageKey
}

// newAttachmentRouter mounts the web routes behind CSP + session middleware
// (mirroring production server.setupMiddleware), wires a real dispatcher and a
// local file store shared with the fixture, and returns the router plus the
// session store.
func newAttachmentRouter(t *testing.T, db *sql.DB) (http.Handler, *auth.SessionStore, storage.Store) {
	t.Helper()
	SetDispatcher(action.New(db))
	store := storage.NewLocalStore(storage.Config{DataDir: t.TempDir(), MaxSize: 1 << 20})
	SetFileStore(store)
	t.Cleanup(func() { disp = nil; fileStore = nil })

	sessions := auth.NewSessionStore(db)
	sc := auth.SessionConfig{Store: sessions, Secret: "01234567890123456789012345678901", Insecure: true}
	r := chi.NewRouter()
	r.Use(auth.CSP())
	r.Use(sc.Session())
	Routes(r)
	return r, sessions, store
}

// TestAttachmentDownloadRequiresMembership covers WU-519 AC: anonymous → 401,
// cross-org member → 404 (never confirm existence), same-org member → 200.
func TestAttachmentDownloadRequiresMembership(t *testing.T) {
	db := dbtest.New(t)
	router, sessions, store := newAttachmentRouter(t, db)

	// Seed org A with user uA (member) and an attachment. User uB is a member
	// of org B only — no membership in org A.
	attID, _ := seedAttachmentFixture(t, db, "orgA", "uA", store)
	seedAttachmentFixture(t, db, "orgB", "uB", store)
	if _, err := db.Exec(`INSERT INTO memberships (id, org_id, actor_id, actor_type, resource_type, resource_id) VALUES ('mA','orgA','uA','user','org',''), ('mB','orgB','uB','user','org','')`); err != nil {
		t.Fatalf("seed memberships: %v", err)
	}

	do := func(cookie string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/files/"+attID, nil)
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: cookie})
		}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}

	// Anonymous → 401.
	if rec := do(""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous: status %d, want 401", rec.Code)
	}

	// uB (member of org B only) → 404 (cross-tenant must not confirm existence).
	rawB, _, err := sessions.Create(context.Background(), "uB", "", "")
	if err != nil {
		t.Fatalf("session uB: %v", err)
	}
	if rec := do(rawB); rec.Code != http.StatusNotFound {
		t.Fatalf("cross-org member: status %d, want 404", rec.Code)
	}

	// uA (member of org A) → 200 and streams the bytes.
	rawA, _, err := sessions.Create(context.Background(), "uA", "", "")
	if err != nil {
		t.Fatalf("session uA: %v", err)
	}
	rec := do(rawA)
	if rec.Code != http.StatusOK {
		t.Fatalf("same-org member: status %d, want 200", rec.Code)
	}
	if body := rec.Body.String(); body != "hello" {
		t.Fatalf("body = %q, want hello", body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain" {
		t.Fatalf("Content-Type = %q, want text/plain", ct)
	}
}

// TestAttachmentDownloadAPIKeyOrgBinding covers the API-key principal branch of
// WU-519: a key owned by org B cannot download org A's attachment (404), and
// the same attachment is reachable by a key owned by org A (200).
func TestAttachmentDownloadAPIKeyOrgBinding(t *testing.T) {
	db := dbtest.New(t)
	// API-key middleware resolves the key; the handler then checks key.OrgID
	// against att.OrgID. Both keys use real 32-byte secrets so the middleware
	// verifies the hash; prefixes must differ (lookup is by prefix).
	secretA := [32]byte{1, 1, 1, 1}
	secretB := [32]byte{2, 2, 2, 2}
	prefixA := "aaaaaaa1"
	prefixB := "bbbbbbb1"
	SetDispatcher(action.New(db))
	store := storage.NewLocalStore(storage.Config{DataDir: t.TempDir(), MaxSize: 1 << 20})
	SetFileStore(store)
	t.Cleanup(func() { disp = nil; fileStore = nil })

	attID, _ := seedAttachmentFixture(t, db, "orgA", "uA", store)
	seedAttachmentFixture(t, db, "orgB", "uB", store)
	q := sqlc.New(db)
	hashA := sha256.Sum256(secretA[:])
	hashB := sha256.Sum256(secretB[:])
	if _, err := q.CreateAPIKey(context.Background(), sqlc.CreateAPIKeyParams{
		ID: "keyA", UserID: "uA", OrgID: "orgA", Name: "a", Prefix: prefixA,
		Hash: hex.EncodeToString(hashA[:]), ScopeJson: `{}`,
	}); err != nil {
		t.Fatalf("seed keyA: %v", err)
	}
	if _, err := q.CreateAPIKey(context.Background(), sqlc.CreateAPIKeyParams{
		ID: "keyB", UserID: "uB", OrgID: "orgB", Name: "b", Prefix: prefixB,
		Hash: hex.EncodeToString(hashB[:]), ScopeJson: `{}`,
	}); err != nil {
		t.Fatalf("seed keyB: %v", err)
	}

	r := chi.NewRouter()
	r.Use(auth.CSP())
	r.Use(auth.APIKeyAuthMiddleware(db))
	Routes(r)

	req := func(token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/files/"+attID, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}

	// Key owned by org B → 404.
	if rec := req(prefixB + hex.EncodeToString(secretB[:])); rec.Code != http.StatusNotFound {
		t.Fatalf("key from org B: status %d, want 404", rec.Code)
	}

	// Key owned by org A → 200 and streams the bytes.
	rec := req(prefixA + hex.EncodeToString(secretA[:]))
	if rec.Code != http.StatusOK {
		t.Fatalf("key from org A: status %d, want 200", rec.Code)
	}
	if body := rec.Body.String(); body != "hello" {
		t.Fatalf("body = %q, want hello", body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain" {
		t.Fatalf("Content-Type = %q, want text/plain", ct)
	}
}
