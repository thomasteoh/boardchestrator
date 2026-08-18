package action

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/storage"
)

// registerAttachmentFixtures re-registers the attachment actions (the registry
// is wiped by reset() at the start of each test). The real handleAttachmentUpload
// is wired so the test exercises the production MIME derivation.
func registerAttachmentFixtures() {
	Register(Definition{
		Name: "attachment.upload", Impact: ImpactLow, Permission: "task.update", Scope: ScopeProject,
		Input: FuncSchema(func(raw json.RawMessage) error { return nil }), Handle: handleAttachmentUpload,
	})
}

// seedAttachmentTask creates the user/org/project/task rows the attachments
// table foreign-keys to, and returns the task id.
func seedAttachmentTask(t *testing.T, db *sql.DB) string {
	t.Helper()
	ctx := context.Background()
	q := sqlc.New(db)
	if _, err := db.ExecContext(ctx, `INSERT INTO users (id, email, name) VALUES ('u1', 'u1@acme.test', 'U1')`); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	org, err := q.CreateOrg(ctx, sqlc.CreateOrgParams{ID: "org1", Name: "Acme", Slug: "acme", Context: "", Visibility: "private"})
	if err != nil {
		t.Fatalf("seed org: %v", err)
	}
	proj, err := q.CreateProject(ctx, sqlc.CreateProjectParams{ID: "proj1", OrgID: org.ID, Name: "P", Key: "P1", Visibility: "private"})
	if err != nil {
		t.Fatalf("seed project: %v", err)
	}
	task, err := q.CreateTask(ctx, sqlc.CreateTaskParams{
		ID: "task1", ProjectID: proj.ID, Title: "T", Key: "P1-1", KeyNum: 1,
		Points: 0, Priority: 0, Status: "todo", DueAt: "", SortOrder: 0,
	})
	if err != nil {
		t.Fatalf("seed task: %v", err)
	}
	return task.ID
}

// TestAttachmentUploadDerivesMIME covers WU-519 AC: a client-supplied MimeType
// that disagrees with the extension-derived type is dropped — a .txt upload
// claiming text/javascript is stored and served as text/plain.
func TestAttachmentUploadDerivesMIME(t *testing.T) {
	reset()
	t.Cleanup(reset)
	registerAttachmentFixtures()

	db := dbtest.New(t)
	taskID := seedAttachmentTask(t, db)

	store := storage.NewLocalStore(storage.Config{DataDir: t.TempDir(), MaxSize: 1 << 20})
	SetStorageStore(store)
	t.Cleanup(func() { attachmentStore = nil })

	d := New(db)
	ctx := context.Background()

	// Upload notes.txt claiming text/javascript. The handler must ignore the
	// claim and store the extension-derived text/plain. Data is []byte, so the
	// JSON carries base64.
	out, err := d.Dispatch(ctx, userActor(), "attachment.upload",
		json.RawMessage(`{"task_id":"`+taskID+`","project_id":"proj1","filename":"notes.txt","data":"`+base64.StdEncoding.EncodeToString([]byte("alert(1)"))+`","mime_type":"text/javascript"}`),
		Opts{Org: "org1", Proj: "proj1"})
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	raw := mustJSON(t, out)
	if !strings.Contains(raw, `"mime":"text/plain"`) {
		t.Fatalf("stored mime not extension-derived text/plain: %s", raw)
	}

	// The attachment row in the DB must carry text/plain, never text/javascript.
	att, err := sqlc.New(db).GetAttachment(ctx, extractID(t, raw))
	if err != nil {
		t.Fatalf("GetAttachment: %v", err)
	}
	if att.Mime != "text/plain" {
		t.Fatalf("DB mime = %q, want text/plain (client claim dropped)", att.Mime)
	}
}
