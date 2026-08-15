package action

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
	"github.com/thomasteoh/boardchestrator/internal/tenant"
)

// TestRoleCreateUpdateGrantsStr verifies role.create/role.update accept a
// comma/whitespace-separated grants_str (the htmx form value) and role.list
// round-trips the grants (WU-509 AC: role editor pages save and list).
func TestRoleCreateUpdateGrantsStr(t *testing.T) {
	reset()
	t.Cleanup(reset)
	registerOrgStorageFixtures()
	Register(Definition{
		Name: "role.create", Impact: ImpactHigh, Permission: "org.permissions", Scope: ScopeOrg,
		Input: FuncSchema(func(raw json.RawMessage) error { return nil }), Handle: handleRoleCreate,
	})
	Register(Definition{
		Name: "role.update", Impact: ImpactHigh, Permission: "org.permissions", Scope: ScopeOrg,
		Input: FuncSchema(func(raw json.RawMessage) error { return nil }), Handle: handleRoleUpdate,
	})
	Register(Definition{
		Name: "role.list", Impact: ImpactLow, Permission: "org.read", Scope: ScopeOrg,
		Input: FuncSchema(func(raw json.RawMessage) error { return nil }), Handle: handleRoleList,
	})

	db := dbtest.New(t)
	key := tenant.PadKey("test-secret-key")
	d := New(db, WithSecretKey(key))
	ctx := context.Background()

	// Seed org — handleOrgCreate grants the creator Org Owner ["*"], so the
	// actor has org.permissions to create/edit roles (WU-508 fix).
	orgOut, err := d.Dispatch(ctx, userActor(), "org.create",
		json.RawMessage(`{"name":"Role Org","slug":"roleorg","visibility":"private"}`), Opts{Org: ""})
	if err != nil {
		t.Fatalf("seed org: %v", err)
	}
	oid := extractID(t, mustJSON(t, orgOut))

	// Create a role via the comma-separated form value (grants_str).
	cr, err := d.Dispatch(ctx, userActor(), "role.create",
		json.RawMessage(`{"org_id":"`+oid+`","name":"Project Admin","grants_str":"task.*, project.read, org.read"}`),
		Opts{Org: oid})
	if err != nil {
		t.Fatalf("role.create: %v", err)
	}
	rid := extractID(t, mustJSON(t, cr))

	// role.list round-trips the role + grants. Parse the JSON to avoid
	// double-escaped GrantsJson string matching.
	lr, err := d.Dispatch(ctx, userActor(), "role.list", json.RawMessage(`{}`), Opts{Org: oid})
	if err != nil {
		t.Fatalf("role.list: %v", err)
	}
	var roles []struct {
		ID         string `json:"ID"`
		Name       string `json:"Name"`
		GrantsJson string `json:"GrantsJson"`
	}
	var b []byte
	if b, err = json.Marshal(lr); err != nil {
		t.Fatalf("marshal role.list: %v", err)
	} else if err := json.Unmarshal(b, &roles); err != nil {
		t.Fatalf("unmarshal role.list: %v", err)
	}
	found := false
	for _, r := range roles {
		if r.Name == "Project Admin" {
			found = true
			var grants []string
			if err := json.Unmarshal([]byte(r.GrantsJson), &grants); err != nil {
				t.Fatalf("role grants unmarshal: %v", err)
			}
			if len(grants) != 3 || grants[0] != "task.*" || grants[1] != "project.read" || grants[2] != "org.read" {
				t.Fatalf("created role grants wrong: %v", grants)
			}
		}
	}
	if !found {
		t.Fatalf("role.list missing Project Admin: %s", string(b))
	}

	// Update grants via grants_str (form value).
	_, err = d.Dispatch(ctx, userActor(), "role.update",
		json.RawMessage(`{"id":"`+rid+`","org_id":"`+oid+`","name":"Project Admin","grants_str":"task.*, org.read"}`),
		Opts{Org: oid})
	if err != nil {
		t.Fatalf("role.update: %v", err)
	}

	// Verify the update landed (grants_str supersedes the old grants).
	lr2, err := d.Dispatch(ctx, userActor(), "role.list", json.RawMessage(`{}`), Opts{Org: oid})
	if err != nil {
		t.Fatalf("role.list2: %v", err)
	}
	var roles2 []struct {
		Name       string `json:"Name"`
		GrantsJson string `json:"GrantsJson"`
	}
	if b2, err := json.Marshal(lr2); err != nil {
		t.Fatalf("marshal role.list2: %v", err)
	} else if err := json.Unmarshal(b2, &roles2); err != nil {
		t.Fatalf("unmarshal role.list2: %v", err)
	}
	for _, r := range roles2 {
		if r.Name == "Project Admin" {
			var grants []string
			if err := json.Unmarshal([]byte(r.GrantsJson), &grants); err != nil {
				t.Fatalf("updated grants unmarshal: %v", err)
			}
			if len(grants) != 2 || grants[0] != "task.*" || grants[1] != "org.read" {
				t.Fatalf("updated role grants wrong: %v", grants)
			}
		}
	}
}

// TestSplitGrants verifies the comma/whitespace grant-splitting helper.
func TestSplitGrants(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"task.*, project.read, org.read", []string{"task.*", "project.read", "org.read"}},
		{"task.* project.read", []string{"task.*", "project.read"}},
		{"task.*,  ,project.read", []string{"task.*", "project.read"}},
		{"", nil},
		{"  ", nil},
	}
	for _, c := range cases {
		got := splitGrants(c.in)
		if len(got) != len(c.want) {
			t.Fatalf("splitGrants(%q) len=%d want %d: %v", c.in, len(got), len(c.want), got)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("splitGrants(%q)[%d]=%q want %q", c.in, i, got[i], c.want[i])
			}
		}
	}
}
