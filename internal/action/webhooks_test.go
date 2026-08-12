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
	// Other tests call reset(), wiping the init-registered registry. Re-register
	// the webhook actions here (guards against the unknown-action failure).
	reset()
	t.Cleanup(reset)
	Register(Definition{Name: "webhook.create", Impact: ImpactHigh, Permission: "webhook.create", Scope: ScopeOrg, Input: FuncSchema(func(raw json.RawMessage) error { return nil }), Handle: handleWebhookCreate})
	Register(Definition{Name: "webhook.update", Impact: ImpactLow, Permission: "webhook.update", Scope: ScopeOrg, Input: FuncSchema(func(raw json.RawMessage) error { return nil }), Handle: handleWebhookUpdate})
	Register(Definition{Name: "webhook.delete", Impact: ImpactHigh, Permission: "webhook.delete", Scope: ScopeOrg, Input: FuncSchema(func(raw json.RawMessage) error { return nil }), Handle: handleWebhookDelete})
	Register(Definition{Name: "webhook.list", Impact: ImpactRead, Permission: "webhook.list", Scope: ScopeOrg, Input: FuncSchema(func(raw json.RawMessage) error { return nil }), Handle: handleWebhookList})

	db := dbtest.New(t)
	d := New(db)
	ctx := context.Background()

	// Seed an org directly (org.create is only test-registered).
	if _, err := db.Exec(`INSERT INTO orgs (id, name, slug, visibility, context, monthly_cap_usd, cap_alert_pct) VALUES ('org1', 'Acme', 'acme', 'private', '', 0, 80)`); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	orgID := "org1"

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
