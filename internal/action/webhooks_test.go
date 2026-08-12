package action

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
)

// TestWebhookManagementCRUD covers WU-404 AC: webhook.create/update/delete/list
// round-trip through the dispatcher against a real DB.
func TestWebhookManagementCRUD(t *testing.T) {
	d := New(dbtest.New(t))
	ctx := context.Background()

	orgOut, err := d.Dispatch(ctx, userActor(), "org.create",
		json.RawMessage(`{"name":"Acme","slug":"acme","visibility":"private"}`),
		Opts{Org: ""})
	if err != nil {
		t.Fatalf("org.create: %v", err)
	}
	orgID := extractID(t, mustJSON(t, orgOut))

	// Create a webhook.
	createOut, err := d.Dispatch(ctx, userActor(), "webhook.create",
		json.RawMessage(`{"org_id":"`+orgID+`","name":"ci","url":"https://hooks.example/ci","secret":"s3cret","event_filter":["task.create"]}`),
		Opts{Org: orgID})
	if err != nil {
		t.Fatalf("webhook.create: %v", err)
	}
	createJSON := mustJSON(t, createOut)
	if !strings.Contains(createJSON, `"url":"https://hooks.example/ci"`) {
		t.Fatalf("create missing url: %s", createJSON)
	}
	whID := extractID(t, createJSON)

	// List.
	listOut, err := d.Dispatch(ctx, userActor(), "webhook.list",
		json.RawMessage(`{"org_id":"`+orgID+`"}`),
		Opts{Org: orgID})
	if err != nil {
		t.Fatalf("webhook.list: %v", err)
	}
	if !strings.Contains(mustJSON(t, listOut), `"id":"`+whID+`"`) {
		t.Fatalf("list missing webhook: %s", mustJSON(t, listOut))
	}

	// Update (rename + disable).
	updOut, err := d.Dispatch(ctx, userActor(), "webhook.update",
		json.RawMessage(`{"id":"`+whID+`","org_id":"`+orgID+`","name":"ci2","enabled":false}`),
		Opts{Org: orgID})
	if err != nil {
		t.Fatalf("webhook.update: %v", err)
	}
	updJSON := mustJSON(t, updOut)
	if !strings.Contains(updJSON, `"ci2"`) || !strings.Contains(updJSON, `"enabled":false`) {
		t.Fatalf("update not reflected: %s", updJSON)
	}

	// Delete.
	delOut, err := d.Dispatch(ctx, userActor(), "webhook.delete",
		json.RawMessage(`{"id":"`+whID+`","org_id":"`+orgID+`"}`),
		Opts{Org: orgID})
	if err != nil {
		t.Fatalf("webhook.delete: %v", err)
	}
	if !strings.Contains(mustJSON(t, delOut), `"deleted":true`) {
		t.Fatalf("delete result: %s", mustJSON(t, delOut))
	}

	// List is now empty.
	listOut2, err := d.Dispatch(ctx, userActor(), "webhook.list",
		json.RawMessage(`{"org_id":"`+orgID+`"}`),
		Opts{Org: orgID})
	if err != nil {
		t.Fatalf("webhook.list: %v", err)
	}
	if strings.Contains(mustJSON(t, listOut2), `"id":"`+whID+`"`) {
		t.Fatalf("deleted webhook still listed")
	}
}
