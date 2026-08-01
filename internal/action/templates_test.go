package action

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
	"github.com/thomasteoh/boardchestrator/internal/schedule"
)

func TestTemplateCreateRoundTrip(t *testing.T) {
	reset()
	t.Cleanup(reset)
	Register(Definition{
		Name:   "org.create",
		Impact: ImpactHigh,
		Scope:  ScopePlatform,
		Handle: handleOrgCreate,
	})
	Register(Definition{
		Name:   "project.create",
		Impact: ImpactHigh,
		Scope:  ScopeOrg,
		Handle: handleProjectCreate,
	})
	Register(Definition{
		Name:   "template.create",
		Impact: ImpactLow,
		Scope:  ScopeProject,
		Handle: handleTemplateCreate,
	})

	db := dbtest.New(t)
	d := New(db, WithScopeResolver(NewDBScopeResolver(db)))
	ctx := context.Background()

	orgOut, err := d.Dispatch(ctx, userActor(), "org.create",
		json.RawMessage(`{"name":"O","slug":"o","visibility":"private"}`),
		Opts{Org: ""})
	if err != nil {
		t.Fatalf("org.create: %v", err)
	}
	orgID := mustParseID(t, orgOut)

	projOut, err := d.Dispatch(ctx, userActor(), "project.create",
		json.RawMessage(`{"org_id":"`+orgID+`","name":"P","key":"PROJ","visibility":"private"}`),
		Opts{Org: orgID})
	if err != nil {
		t.Fatalf("project.create: %v", err)
	}
	projID := mustParseID(t, projOut)

	in := map[string]any{
		"org_id":               orgID,
		"project_id":           projID,
		"name":                 "Bug fix",
		"title_template":       "[BUG] {{title}}",
		"description_template": "Fix this bug",
		"points":               3,
		"priority":             2,
		"status":               "in_progress",
		"labels_json":          `["bug","urgent"]`,
	}

	raw, _ := json.Marshal(in)
	out, err := d.Dispatch(ctx, userActor(), "template.create", raw, Opts{Org: orgID, Proj: projID})
	if err != nil {
		t.Fatalf("template.create: %v", err)
	}

	got := mustJSON(t, out)
	if !strings.Contains(got, `"Name":"Bug fix"`) {
		t.Errorf("result missing expected name: %s", got)
	}
}

func TestTemplateCreateFrom(t *testing.T) {
	reset()
	t.Cleanup(reset)
	Register(Definition{
		Name:   "org.create",
		Impact: ImpactHigh,
		Scope:  ScopePlatform,
		Handle: handleOrgCreate,
	})
	Register(Definition{
		Name:   "project.create",
		Impact: ImpactHigh,
		Scope:  ScopeOrg,
		Handle: handleProjectCreate,
	})
	Register(Definition{
		Name:   "template.create",
		Impact: ImpactLow,
		Scope:  ScopeProject,
		Handle: handleTemplateCreate,
	})
	Register(Definition{
		Name:   "template.create_from",
		Impact: ImpactLow,
		Scope:  ScopeProject,
		Handle: handleTemplateCreateFrom,
	})

	db := dbtest.New(t)
	d := New(db, WithScopeResolver(NewDBScopeResolver(db)))
	ctx := context.Background()

	orgOut, err := d.Dispatch(ctx, userActor(), "org.create",
		json.RawMessage(`{"name":"O","slug":"o","visibility":"private"}`),
		Opts{Org: ""})
	if err != nil {
		t.Fatalf("org.create: %v", err)
	}
	orgID := mustParseID(t, orgOut)

	projOut, err := d.Dispatch(ctx, userActor(), "project.create",
		json.RawMessage(`{"org_id":"`+orgID+`","name":"P","key":"PROJ","visibility":"private"}`),
		Opts{Org: orgID})
	if err != nil {
		t.Fatalf("project.create: %v", err)
	}
	projID := mustParseID(t, projOut)

	// Create a template.
	in := map[string]any{
		"org_id":               orgID,
		"project_id":           projID,
		"name":                 "Bug fix",
		"title_template":       "[BUG] {{title}}",
		"description_template": "Fix this bug",
		"points":               3,
		"priority":             2,
		"status":               "in_progress",
	}
	raw, _ := json.Marshal(in)
	out, err := d.Dispatch(ctx, userActor(), "template.create", raw, Opts{Org: orgID, Proj: projID})
	if err != nil {
		t.Fatalf("template.create: %v", err)
	}
	tmplID := mustParseID(t, out)

	// Create task from template.
	fromIn := map[string]any{
		"org_id":      orgID,
		"project_id":  projID,
		"template_id": tmplID,
		"title":       "My bug",
	}
	raw2, _ := json.Marshal(fromIn)
	out2, err := d.Dispatch(ctx, userActor(), "template.create_from", raw2, Opts{Org: orgID, Proj: projID})
	if err != nil {
		t.Fatalf("template.create_from: %v", err)
	}
	got := mustJSON(t, out2)
	if !strings.Contains(got, `"Title":"[BUG] {{title}}"`) {
		t.Errorf("task title should come from template: %s", got)
	}
}

func TestTemplateUpdate(t *testing.T) {
	reset()
	t.Cleanup(reset)
	Register(Definition{
		Name:   "org.create",
		Impact: ImpactHigh,
		Scope:  ScopePlatform,
		Handle: handleOrgCreate,
	})
	Register(Definition{
		Name:   "project.create",
		Impact: ImpactHigh,
		Scope:  ScopeOrg,
		Handle: handleProjectCreate,
	})
	Register(Definition{
		Name:   "template.create",
		Impact: ImpactLow,
		Scope:  ScopeProject,
		Handle: handleTemplateCreate,
	})
	Register(Definition{
		Name:   "template.update",
		Impact: ImpactLow,
		Scope:  ScopeProject,
		Handle: handleTemplateUpdate,
	})

	db := dbtest.New(t)
	d := New(db, WithScopeResolver(NewDBScopeResolver(db)))
	ctx := context.Background()

	orgOut, err := d.Dispatch(ctx, userActor(), "org.create",
		json.RawMessage(`{"name":"O","slug":"o","visibility":"private"}`),
		Opts{Org: ""})
	if err != nil {
		t.Fatalf("org.create: %v", err)
	}
	orgID := mustParseID(t, orgOut)

	projOut, err := d.Dispatch(ctx, userActor(), "project.create",
		json.RawMessage(`{"org_id":"`+orgID+`","name":"P","key":"PROJ","visibility":"private"}`),
		Opts{Org: orgID})
	if err != nil {
		t.Fatalf("project.create: %v", err)
	}
	projID := mustParseID(t, projOut)

	// Create.
	in := map[string]any{
		"org_id":               orgID,
		"project_id":           projID,
		"name":                 "Bug fix",
		"title_template":       "[BUG]",
		"description_template": "Fix this bug",
	}
	raw, _ := json.Marshal(in)
	out, err := d.Dispatch(ctx, userActor(), "template.create", raw, Opts{Org: orgID, Proj: projID})
	if err != nil {
		t.Fatalf("template.create: %v", err)
	}
	tmplID := mustParseID(t, out)

	// Update.
	upd := map[string]any{
		"id":                   tmplID,
		"org_id":               orgID,
		"name":                 "Bug fix v2",
		"title_template":       "[BUG-V2]",
		"description_template": "Updated desc",
		"points":               5,
		"priority":             1,
		"status":               "backlog",
		"labels_json":          "[]",
	}
	raw2, _ := json.Marshal(upd)
	out2, err := d.Dispatch(ctx, userActor(), "template.update", raw2, Opts{Org: orgID, Proj: projID})
	if err != nil {
		t.Fatalf("template.update: %v", err)
	}
	got := mustJSON(t, out2)
	if !strings.Contains(got, `"Name":"Bug fix v2"`) {
		t.Errorf("updated template name not reflected: %s", got)
	}
}

// --- Recurring rule tests ---

func TestRecurringCreateAndNextAt(t *testing.T) {
	reset()
	t.Cleanup(reset)
	Register(Definition{
		Name:   "org.create",
		Impact: ImpactHigh,
		Scope:  ScopePlatform,
		Handle: handleOrgCreate,
	})
	Register(Definition{
		Name:   "project.create",
		Impact: ImpactHigh,
		Scope:  ScopeOrg,
		Handle: handleProjectCreate,
	})
	Register(Definition{
		Name:   "template.create",
		Impact: ImpactLow,
		Scope:  ScopeProject,
		Handle: handleTemplateCreate,
	})
	Register(Definition{
		Name:   "recurring.create",
		Impact: ImpactLow,
		Scope:  ScopeProject,
		Handle: handleRecurringCreate,
	})

	db := dbtest.New(t)
	d := New(db, WithScopeResolver(NewDBScopeResolver(db)))
	ctx := context.Background()

	orgOut, err := d.Dispatch(ctx, userActor(), "org.create",
		json.RawMessage(`{"name":"O","slug":"o","visibility":"private"}`),
		Opts{Org: ""})
	if err != nil {
		t.Fatalf("org.create: %v", err)
	}
	orgID := mustParseID(t, orgOut)

	projOut, err := d.Dispatch(ctx, userActor(), "project.create",
		json.RawMessage(`{"org_id":"`+orgID+`","name":"P","key":"PROJ","visibility":"private"}`),
		Opts{Org: orgID})
	if err != nil {
		t.Fatalf("project.create: %v", err)
	}
	projID := mustParseID(t, projOut)

	// Template.
	in := map[string]any{
		"org_id":         orgID,
		"project_id":     projID,
		"name":           "Daily standup",
		"title_template": "Standup",
	}
	raw, _ := json.Marshal(in)
	tmplOut, err := d.Dispatch(ctx, userActor(), "template.create", raw, Opts{Org: orgID, Proj: projID})
	if err != nil {
		t.Fatalf("template.create: %v", err)
	}
	tmplID := mustParseID(t, tmplOut)

	// Recurring rule.
	recIn := map[string]any{
		"org_id":      orgID,
		"project_id":  projID,
		"template_id": tmplID,
		"cron_expr":   "0 9 * * *",
	}
	raw2, _ := json.Marshal(recIn)
	recOut, err := d.Dispatch(ctx, userActor(), "recurring.create", raw2, Opts{Org: orgID, Proj: projID})
	if err != nil {
		t.Fatalf("recurring.create: %v", err)
	}
	got := mustJSON(t, recOut)
	if !strings.Contains(got, `"NextAt"`) {
		t.Errorf("result missing next_at: %s", got)
	}
	if !strings.Contains(got, `"Enabled":1`) {
		t.Errorf("result not enabled by default: %s", got)
	}
}

func TestCronNextAt(t *testing.T) {
	now := time.Date(2026, 8, 1, 8, 0, 0, 0, time.UTC)
	next, err := schedule.NextAt("0 9 * * *", now)
	if err != nil {
		t.Fatalf("NextAt: %v", err)
	}
	if next != "2026-08-01T09:00:00Z" {
		t.Errorf("next_at = %q, want 2026-08-01T09:00:00Z", next)
	}

	// Invalid cron.
	_, err = schedule.NextAt("bad cron", now)
	if err == nil {
		t.Error("bad cron should error")
	}

	// Every weekday at 10. Aug 1 2026 = Saturday, next weekday is Monday Aug 3.
	next2, err := schedule.NextAt("0 10 * * 1-5", now)
	if err != nil {
		t.Fatalf("NextAt weekday: %v", err)
	}
	if next2 != "2026-08-03T10:00:00Z" {
		t.Errorf("weekday next_at = %q, want 2026-08-03", next2)
	}
}

func TestRecurringUpdateAndDelete(t *testing.T) {
	reset()
	t.Cleanup(reset)
	Register(Definition{
		Name:   "org.create",
		Impact: ImpactHigh,
		Scope:  ScopePlatform,
		Handle: handleOrgCreate,
	})
	Register(Definition{
		Name:   "project.create",
		Impact: ImpactHigh,
		Scope:  ScopeOrg,
		Handle: handleProjectCreate,
	})
	Register(Definition{
		Name:   "template.create",
		Impact: ImpactLow,
		Scope:  ScopeProject,
		Handle: handleTemplateCreate,
	})
	Register(Definition{
		Name:   "recurring.create",
		Impact: ImpactLow,
		Scope:  ScopeProject,
		Handle: handleRecurringCreate,
	})
	Register(Definition{
		Name:   "recurring.update",
		Impact: ImpactLow,
		Scope:  ScopeProject,
		Handle: handleRecurringUpdate,
	})
	Register(Definition{
		Name:   "recurring.delete",
		Impact: ImpactLow,
		Scope:  ScopeProject,
		Handle: handleRecurringDelete,
	})

	db := dbtest.New(t)
	d := New(db, WithScopeResolver(NewDBScopeResolver(db)))
	ctx := context.Background()

	orgOut, err := d.Dispatch(ctx, userActor(), "org.create",
		json.RawMessage(`{"name":"O","slug":"o","visibility":"private"}`),
		Opts{Org: ""})
	if err != nil {
		t.Fatalf("org.create: %v", err)
	}
	orgID := mustParseID(t, orgOut)

	projOut, err := d.Dispatch(ctx, userActor(), "project.create",
		json.RawMessage(`{"org_id":"`+orgID+`","name":"P","key":"PROJ","visibility":"private"}`),
		Opts{Org: orgID})
	if err != nil {
		t.Fatalf("project.create: %v", err)
	}
	projID := mustParseID(t, projOut)

	// Template.
	in := map[string]any{
		"org_id":         orgID,
		"project_id":     projID,
		"name":           "Weekly report",
		"title_template": "Report",
	}
	raw, _ := json.Marshal(in)
	tmplOut, _ := d.Dispatch(ctx, userActor(), "template.create", raw, Opts{Org: orgID, Proj: projID})
	tmplID := mustParseID(t, tmplOut)

	// Create rule.
	recIn := map[string]any{
		"org_id":      orgID,
		"project_id":  projID,
		"template_id": tmplID,
		"cron_expr":   "0 9 * * 1",
	}
	raw2, _ := json.Marshal(recIn)
	recOut, _ := d.Dispatch(ctx, userActor(), "recurring.create", raw2, Opts{Org: orgID, Proj: projID})
	ruleID := mustParseID(t, recOut)

	// Update: disable.
	updIn := map[string]any{
		"id":        ruleID,
		"org_id":    orgID,
		"cron_expr": "0 9 * * 1",
		"enabled":   0,
	}
	raw3, _ := json.Marshal(updIn)
	updOut, err := d.Dispatch(ctx, userActor(), "recurring.update", raw3, Opts{Org: orgID, Proj: projID})
	if err != nil {
		t.Fatalf("recurring.update: %v", err)
	}
	got := mustJSON(t, updOut)
	if !strings.Contains(got, `"Enabled":0`) {
		t.Errorf("rule should be disabled: %s", got)
	}

	// Delete.
	delIn := map[string]any{"id": ruleID, "org_id": orgID}
	raw4, _ := json.Marshal(delIn)
	_, err = d.Dispatch(ctx, userActor(), "recurring.delete", raw4, Opts{Org: orgID, Proj: projID})
	if err != nil {
		t.Fatalf("recurring.delete: %v", err)
	}
}
