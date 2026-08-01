package action

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
)

func TestNotifMarkRead(t *testing.T) {
	reset()
	t.Cleanup(reset)
	Register(Definition{
		Name:   "org.create",
		Impact: ImpactHigh,
		Scope:  ScopePlatform,
		Handle: handleOrgCreate,
	})
	Register(Definition{
		Name:   "notif.mark_read",
		Impact: ImpactLow,
		Scope:  ScopePlatform,
		Handle: handleMarkRead,
	})

	db := dbtest.New(t)
	d := New(db)
	ctx := context.Background()

	// Seed a user and notification row directly.
	_, err := db.ExecContext(ctx, `INSERT INTO users (id, email, name) VALUES ('u1', 'u@x', 'U1')`)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	_, err = db.ExecContext(ctx, `INSERT INTO orgs (id, name, slug) VALUES ('o1', 'O', 'o')`)
	if err != nil {
		t.Fatalf("seed org: %v", err)
	}
	_, err = db.ExecContext(ctx, `INSERT INTO notifications (id, org_id, user_id, event_name, title, body, grouping_key) VALUES ('n1', 'o1', 'u1', 'task.create', 'Test', 'Body', 'g1')`)
	if err != nil {
		t.Fatalf("seed notification: %v", err)
	}

	in := map[string]any{"id": "n1", "user_id": "u1"}
	raw, _ := json.Marshal(in)
	_, err = d.Dispatch(ctx, userActor(), "notif.mark_read", raw, Opts{Org: "o1"})
	if err != nil {
		t.Fatalf("notif.mark_read: %v", err)
	}
}

func TestNotifMarkAllRead(t *testing.T) {
	reset()
	t.Cleanup(reset)
	Register(Definition{
		Name:   "notif.mark_all_read",
		Impact: ImpactLow,
		Scope:  ScopePlatform,
		Handle: handleMarkAllRead,
	})

	db := dbtest.New(t)
	d := New(db)
	ctx := context.Background()

	// Seed user + org + notifications.
	_, err := db.ExecContext(ctx, `INSERT INTO users (id, email, name) VALUES ('u1', 'u@x', 'U1')`)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	_, err = db.ExecContext(ctx, `INSERT INTO orgs (id, name, slug) VALUES ('o1', 'O', 'o')`)
	if err != nil {
		t.Fatalf("seed org: %v", err)
	}
	for _, id := range []string{"n1", "n2"} {
		_, err := db.ExecContext(ctx, `INSERT INTO notifications (id, org_id, user_id, event_name, title, body, grouping_key) VALUES (?, 'o1', 'u1', 'task.update', 'T', 'B', 'g')`, id)
		if err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}

	in := map[string]any{"user_id": "u1"}
	raw, _ := json.Marshal(in)
	_, err = d.Dispatch(ctx, userActor(), "notif.mark_all_read", raw, Opts{Org: "o1"})
	if err != nil {
		t.Fatalf("notif.mark_all_read: %v", err)
	}
}

func TestNotifUnreadCount(t *testing.T) {
	reset()
	t.Cleanup(reset)
	Register(Definition{
		Name:   "notif.unread_count",
		Impact: ImpactRead,
		Scope:  ScopePlatform,
		Handle: handleNotifUnreadCount,
	})

	db := dbtest.New(t)
	d := New(db)
	ctx := context.Background()

	// Seed user + org + notification.
	_, err := db.ExecContext(ctx, `INSERT INTO users (id, email, name) VALUES ('u1', 'u@x', 'U1')`)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	_, err = db.ExecContext(ctx, `INSERT INTO orgs (id, name, slug) VALUES ('o1', 'O', 'o')`)
	if err != nil {
		t.Fatalf("seed org: %v", err)
	}
	_, err = db.ExecContext(ctx, `INSERT INTO notifications (id, org_id, user_id, event_name, title, body, grouping_key) VALUES ('n1', 'o1', 'u1', 'task.create', 'T', 'B', 'g')`)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	in := map[string]any{"user_id": "u1"}
	raw, _ := json.Marshal(in)
	out, err := d.Dispatch(ctx, userActor(), "notif.unread_count", raw, Opts{Org: "o1"})
	if err != nil {
		t.Fatalf("notif.unread_count: %v", err)
	}
	got := mustJSON(t, out)
	if !contains(got, `"count":1`) {
		t.Errorf("expected count 1: %s", got)
	}
}
