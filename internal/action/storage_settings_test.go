package action

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
	"github.com/thomasteoh/boardchestrator/internal/tenant"
)

// TestOrgStorageConfigRoundTrip verifies org.storage.configure writes an
// encrypted S3Config to org_secrets and org.storage.status reads it back,
// masking the secret key (WU-506 AC: config round-trip).
func TestOrgStorageConfigRoundTrip(t *testing.T) {
	reset()
	t.Cleanup(reset)

	// Register storage + org actions needed to seed and configure.
	registerOrgStorageFixtures()

	db := dbtest.New(t)
	key := tenant.PadKey("test-secret-key")
	d := New(db, WithSecretKey(key))
	ctx := context.Background()

	// Seed org via org.create (platform-scoped).
	orgOut, err := d.Dispatch(ctx, userActor(), "org.create",
		json.RawMessage(`{"name":"S3 Org","slug":"s3org","visibility":"private"}`), Opts{Org: ""})
	if err != nil {
		t.Fatalf("seed org: %v", err)
	}
	oid := extractID(t, mustJSON(t, orgOut))

	// Initially local.
	st, err := d.Dispatch(ctx, userActor(), "org.storage.status", json.RawMessage(`{}`), Opts{Org: oid})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !strings.Contains(mustJSON(t, st), `"backend":"local"`) {
		t.Fatalf("initial status: %s", mustJSON(t, st))
	}

	// Configure S3.
	cfg := `{"endpoint":"http://localhost:9000","bucket":"attachments","access_key_id":"AK","secret_access_key":"SK","path_style":true,"prefix":"prod"}`
	_, err = d.Dispatch(ctx, userActor(), "org.storage.configure",
		json.RawMessage(`{"storage_config":`+cfg+`}`), Opts{Org: oid})
	if err != nil {
		t.Fatalf("configure: %v", err)
	}

	// Status round-trips the config, secret masked.
	st2, err := d.Dispatch(ctx, userActor(), "org.storage.status", json.RawMessage(`{}`), Opts{Org: oid})
	if err != nil {
		t.Fatalf("status2: %v", err)
	}
	raw := mustJSON(t, st2)
	if !strings.Contains(raw, `"backend":"s3"`) {
		t.Fatalf("backend not s3: %s", raw)
	}
	if !strings.Contains(raw, `"bucket":"attachments"`) {
		t.Fatalf("bucket missing: %s", raw)
	}
	if !strings.Contains(raw, `"access_key_id":"AK"`) {
		t.Fatalf("access key missing: %s", raw)
	}
	if strings.Contains(raw, `"secret_access_key":"SK"`) {
		t.Fatalf("secret key leaked in status: %s", raw)
	}
	if !strings.Contains(raw, `"secret_access_key":"\u2022\u2022\u2022\u2022"`) && !strings.Contains(raw, "••••") {
		t.Fatalf("secret not masked: %s", raw)
	}

	// Re-configure (upsert) is idempotent — no duplicate row error.
	_, err = d.Dispatch(ctx, userActor(), "org.storage.configure",
		json.RawMessage(`{"storage_config":`+cfg+`}`), Opts{Org: oid})
	if err != nil {
		t.Fatalf("re-configure: %v", err)
	}

	// Clearing config falls back to local.
	_, err = d.Dispatch(ctx, userActor(), "org.storage.configure",
		json.RawMessage(`{"storage_config":{}}`), Opts{Org: oid})
	if err != nil {
		t.Fatalf("clear: %v", err)
	}
	st3, err := d.Dispatch(ctx, userActor(), "org.storage.status", json.RawMessage(`{}`), Opts{Org: oid})
	if err != nil {
		t.Fatalf("status3: %v", err)
	}
	if !strings.Contains(mustJSON(t, st3), `"backend":"local"`) {
		t.Fatalf("not local after clear: %s", mustJSON(t, st3))
	}
}

// registerOrgStorageFixtures registers the org + storage actions the test needs.
func registerOrgStorageFixtures() {
	Register(Definition{
		Name: "org.create", Impact: ImpactHigh, Permission: "org.create", Scope: ScopePlatform,
		Input: FuncSchema(func(raw json.RawMessage) error { return nil }), Handle: handleOrgCreate,
	})
	Register(Definition{
		Name: "org.storage.configure", Impact: ImpactHigh, Permission: "org.storage.configure", Scope: ScopeOrg,
		Input: FuncSchema(func(raw json.RawMessage) error { return nil }), Handle: handleOrgStorageConfigure,
	})
	Register(Definition{
		Name: "org.storage.status", Impact: ImpactRead, Permission: "org.storage.status", Scope: ScopeOrg,
		Input: FuncSchema(func(raw json.RawMessage) error { return nil }), Handle: handleOrgStorageStatus,
	})
}
