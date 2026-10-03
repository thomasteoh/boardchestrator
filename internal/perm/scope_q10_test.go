package perm_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/action"
	_ "github.com/thomasteoh/boardchestrator/internal/auth/idp" // registers idp.* (ScopePlatform)
	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/perm"
	"github.com/thomasteoh/boardchestrator/internal/tenant"
)

// WU-603a / Q10: platform-scope actions are evaluated against the platform org
// only; per-user actions are ScopeSelf and can only touch the caller's rows.

const (
	q10Admin = "u-admin" // Owner of the platform sentinel org
	q10Owner = "u-owner" // Owner ("*") of org-a only
	q10Plain = "u-plain" // no memberships at all
	q10Other = "u-other" // another plain user whose rows must stay untouched
	q10Org   = "org-a"
)

var q10Key = tenant.PadKey("q10-test-secret")

// selfActions is the WU-603a classification. A new ScopeSelf action must be
// added here, which makes it pick up the cross-user tests below.
var selfActions = []string{
	"github.connect", "github.disconnect", "github.status",
	"identity.list", "identity.unlink", // WU-604
	"invite.accept",
	"notif.list", "notif.mark_all_read", "notif.mark_read", "notif.unread_count",
	"passkey.delete", "passkey.list", "passkey.rename", // WU-612
	"session.revoke",
	"user.export", "user.theme.update", "user.timezone.update",
}

func q10DB(t *testing.T) (*sql.DB, *action.Dispatcher) {
	t.Helper()
	d := dbtest.New(t)
	for _, q := range []string{
		`INSERT INTO users (id, email) VALUES ('u-admin','admin@x.test'),('u-owner','owner@x.test'),('u-plain','plain@x.test'),('u-other','other@x.test')`,
		`INSERT INTO orgs (id, name, slug) VALUES ('org-a','A','a')`,
		`INSERT INTO roles (id, org_id, name, is_system, grants_json) VALUES ('r-owner','org-a','Owner',0,'["*"]')`,
		`INSERT INTO teams (id, org_id, name, slug) VALUES ('team-a','org-a','T','ta')`,
		`INSERT INTO memberships (id, org_id, actor_id, actor_type, resource_type, resource_id, role_id) VALUES
		 ('m1','00000000000000000000000000000000','u-admin','user','org','00000000000000000000000000000000','00000000000000000000000000000000'),
		 ('m2','org-a','u-owner','user','org','org-a','r-owner'),
		 ('m3','org-a','u-owner','user','team','team-a','r-owner')`,
	} {
		if _, err := d.Exec(q); err != nil {
			t.Fatalf("seed: %v\n%s", err, q)
		}
	}
	disp := action.New(d,
		action.WithScopeResolver(action.NewDBScopeResolver(d)),
		action.WithPermissionChecker(perm.NewCheckerAdapter(d)),
		action.WithSecretKey(q10Key),
	)
	return d, disp
}

func user(id string) action.Actor { return action.Actor{Type: action.ActorUser, ID: id} }

func TestSelfActionClassification(t *testing.T) {
	var got []string
	for _, def := range action.All() {
		if def.Scope == action.ScopeSelf {
			got = append(got, def.Name)
		}
	}
	want := append([]string(nil), selfActions...)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("ScopeSelf actions = %v, want %v", got, want)
	}
}

// TestPlatformActionsRefuseOrgOwner is the registry-wide check: every
// ScopePlatform action is refused for an org Owner whatever tenant id they
// pass (and without one), and still allowed for a platform admin.
func TestPlatformActionsRefuseOrgOwner(t *testing.T) {
	d, disp := q10DB(t)
	ctx := context.Background()
	scopes := []action.Opts{
		{Org: q10Org},
		{Org: q10Org, Team: "team-a"},
		{Proj: "p-any"},
	}
	var platform []action.Definition
	for _, def := range action.All() {
		if def.Scope == action.ScopePlatform {
			platform = append(platform, def)
		}
	}
	if len(platform) < 20 {
		t.Fatalf("only %d platform actions registered; registry not loaded?", len(platform))
	}
	var orgs0 int
	_ = d.QueryRow(`SELECT COUNT(*) FROM orgs`).Scan(&orgs0)
	for _, def := range platform {
		if def.Permission == "" {
			t.Errorf("%s: platform action without a permission", def.Name)
		}
		// The tenant-id check runs before input validation, so any input will do.
		for _, o := range scopes {
			_, err := disp.Dispatch(ctx, user(q10Owner), def.Name, json.RawMessage(`{"name":"Evil","slug":"evil"}`), o)
			if !errors.Is(err, action.ErrForbidden) {
				t.Errorf("%s as org owner with %+v: err = %v, want ErrForbidden", def.Name, o, err)
			}
		}
		// Without a tenant id the permission is evaluated against the platform
		// org, where the owner holds nothing. Strict schemas may refuse "{}"
		// first; either way the handler never runs.
		if _, err := disp.Dispatch(ctx, user(q10Owner), def.Name, json.RawMessage(`{}`), action.Opts{}); !errors.Is(err, action.ErrForbidden) && !errors.Is(err, action.ErrInvalidInput) {
			t.Errorf("%s as org owner without org: err = %v, want refusal", def.Name, err)
		}
		// Platform admins too are refused a tenant id ...
		if _, err := disp.Dispatch(ctx, user(q10Admin), def.Name, json.RawMessage(`{}`), action.Opts{Org: q10Org, DryRun: true}); !errors.Is(err, action.ErrForbidden) {
			t.Errorf("%s as admin with org: err = %v, want ErrForbidden", def.Name, err)
		}
		// ... but pass scope + permission without one.
		if _, err := disp.Dispatch(ctx, user(q10Admin), def.Name, json.RawMessage(`{}`), action.Opts{DryRun: true}); errors.Is(err, action.ErrForbidden) || errors.Is(err, action.ErrScope) {
			t.Errorf("%s as platform admin: err = %v, want allowed", def.Name, err)
		}
		// Agents never run platform actions; the run engine always passes the
		// run's org.
		if _, err := disp.Dispatch(ctx, action.Actor{Type: action.ActorAgent, ID: "a1"}, def.Name, json.RawMessage(`{}`), action.Opts{Org: q10Org}); !errors.Is(err, action.ErrForbidden) {
			t.Errorf("%s as agent: err = %v, want ErrForbidden", def.Name, err)
		}
	}
	var orgs1 int
	_ = d.QueryRow(`SELECT COUNT(*) FROM orgs`).Scan(&orgs1)
	if orgs1 != orgs0 {
		t.Errorf("a refused call created an org (%d → %d)", orgs0, orgs1)
	}

	// A real (non-dry-run) platform call by the admin still executes.
	out, err := disp.Dispatch(ctx, user(q10Admin), "org.create", json.RawMessage(`{"name":"New","slug":"new"}`), action.Opts{})
	if err != nil {
		t.Fatalf("org.create as platform admin: %v", err)
	}
	if out == nil {
		t.Fatal("org.create returned nothing")
	}
}

// TestSelfActionsRefuseTenantAndNonUsers: no tenant id, and only user actors.
func TestSelfActionsRefuseTenantAndNonUsers(t *testing.T) {
	_, disp := q10DB(t)
	ctx := context.Background()
	for _, name := range selfActions {
		if _, err := disp.Dispatch(ctx, user(q10Plain), name, json.RawMessage(`{}`), action.Opts{Org: q10Org}); !errors.Is(err, action.ErrForbidden) {
			t.Errorf("%s with org id: err = %v, want ErrForbidden", name, err)
		}
		for _, a := range []action.Actor{
			{Type: action.ActorAgent, ID: "a1"},
			{Type: action.ActorAPIKey, ID: "k1", OwnerUserID: q10Plain},
			{Type: action.ActorService, ID: "github"},
		} {
			if _, err := disp.Dispatch(ctx, a, name, json.RawMessage(`{}`), action.Opts{}); !errors.Is(err, action.ErrForbidden) {
				t.Errorf("%s as %s: err = %v, want ErrForbidden", name, a.Type, err)
			}
		}
		// A user id that is not a live user (e.g. the web "placeholder") is refused.
		if _, err := disp.Dispatch(ctx, user("placeholder"), name, json.RawMessage(`{}`), action.Opts{}); !errors.Is(err, action.ErrScope) {
			t.Errorf("%s as unknown user: err = %v, want ErrScope", name, err)
		}
	}
}

func scalar(t *testing.T, d *sql.DB, q string, args ...any) string {
	t.Helper()
	var s sql.NullString
	if err := d.QueryRow(q, args...).Scan(&s); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return s.String
}

func mustOK(t *testing.T, name string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s as plain user: %v", name, err)
	}
}

func mustForbid(t *testing.T, name string, err error) {
	t.Helper()
	if !errors.Is(err, action.ErrForbidden) {
		t.Fatalf("%s naming another user: err = %v, want ErrForbidden", name, err)
	}
}

func TestSelfUserSettings(t *testing.T) {
	d, disp := q10DB(t)
	ctx := context.Background()
	for _, c := range []struct{ name, col, val string }{
		{"user.theme.update", "theme", "dark"},
		{"user.timezone.update", "timezone", "Australia/Melbourne"},
	} {
		in := `{"` + c.col + `":"` + c.val + `","user_id":"u-other","id":"u-other"}`
		_, err := disp.Dispatch(ctx, user(q10Plain), c.name, json.RawMessage(in), action.Opts{})
		mustOK(t, c.name, err)
		if got := scalar(t, d, `SELECT `+c.col+` FROM users WHERE id='u-plain'`); got != c.val {
			t.Errorf("%s: own %s = %q, want %q", c.name, c.col, got, c.val)
		}
		if got := scalar(t, d, `SELECT `+c.col+` FROM users WHERE id='u-other'`); got == c.val {
			t.Errorf("%s changed another user's %s", c.name, c.col)
		}
	}
}

func TestSelfSessionRevoke(t *testing.T) {
	d, disp := q10DB(t)
	ctx := context.Background()
	if _, err := d.Exec(`INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ('h-plain','u-plain','2099-01-01'),('h-other','u-other','2099-01-01')`); err != nil {
		t.Fatal(err)
	}
	_, err := disp.Dispatch(ctx, user(q10Plain), "session.revoke", json.RawMessage(`{"token_hash":"h-other"}`), action.Opts{})
	if err == nil {
		t.Fatal("session.revoke of another user's session succeeded")
	}
	if n := scalar(t, d, `SELECT COUNT(*) FROM sessions WHERE token_hash='h-other'`); n != "1" {
		t.Fatal("another user's session was deleted")
	}
	_, err = disp.Dispatch(ctx, user(q10Plain), "session.revoke", json.RawMessage(`{"token_hash":"h-plain"}`), action.Opts{})
	mustOK(t, "session.revoke", err)
	if n := scalar(t, d, `SELECT COUNT(*) FROM sessions WHERE token_hash='h-plain'`); n != "0" {
		t.Fatal("own session not revoked")
	}
}

func TestSelfNotifications(t *testing.T) {
	d, disp := q10DB(t)
	ctx := context.Background()
	if _, err := d.Exec(`INSERT INTO notifications (id, org_id, user_id, event_name, title) VALUES
		('n-plain','org-a','u-plain','task.create','mine'),
		('n-other','org-a','u-other','task.create','theirs'),
		('n-other2','org-a','u-other','task.create','theirs too')`); err != nil {
		t.Fatal(err)
	}
	unreadOther := func() string {
		return scalar(t, d, `SELECT COUNT(*) FROM notifications WHERE user_id='u-other' AND read_at=''`)
	}

	// Reads: own rows only; naming another user is refused.
	out, err := disp.Dispatch(ctx, user(q10Plain), "notif.list", json.RawMessage(`{}`), action.Opts{})
	mustOK(t, "notif.list", err)
	b, _ := json.Marshal(out)
	if !strings.Contains(string(b), "n-plain") || strings.Contains(string(b), "n-other") {
		t.Errorf("notif.list = %s, want own row only", b)
	}
	_, err = disp.Dispatch(ctx, user(q10Plain), "notif.list", json.RawMessage(`{"user_id":"u-other"}`), action.Opts{})
	mustForbid(t, "notif.list", err)

	out, err = disp.Dispatch(ctx, user(q10Plain), "notif.unread_count", json.RawMessage(`{}`), action.Opts{})
	mustOK(t, "notif.unread_count", err)
	if b, _ := json.Marshal(out); string(b) != `{"count":1}` {
		t.Errorf("notif.unread_count = %s, want 1", b)
	}
	_, err = disp.Dispatch(ctx, user(q10Plain), "notif.unread_count", json.RawMessage(`{"user_id":"u-other"}`), action.Opts{})
	mustForbid(t, "notif.unread_count", err)

	// Writes: another user's notification id is a no-op; naming them is refused.
	_, err = disp.Dispatch(ctx, user(q10Plain), "notif.mark_read", json.RawMessage(`{"id":"n-other"}`), action.Opts{})
	mustOK(t, "notif.mark_read", err)
	_, err = disp.Dispatch(ctx, user(q10Plain), "notif.mark_read", json.RawMessage(`{"id":"n-other","user_id":"u-other"}`), action.Opts{})
	mustForbid(t, "notif.mark_read", err)
	_, err = disp.Dispatch(ctx, user(q10Plain), "notif.mark_all_read", json.RawMessage(`{"user_id":"u-other"}`), action.Opts{})
	mustForbid(t, "notif.mark_all_read", err)
	if unreadOther() != "2" {
		t.Fatal("another user's notifications were marked read")
	}

	_, err = disp.Dispatch(ctx, user(q10Plain), "notif.mark_read", json.RawMessage(`{"id":"n-plain"}`), action.Opts{})
	mustOK(t, "notif.mark_read", err)
	if got := scalar(t, d, `SELECT read_at FROM notifications WHERE id='n-plain'`); got == "" {
		t.Error("own notification not marked read")
	}
	if _, err := d.Exec(`UPDATE notifications SET read_at='' WHERE id='n-plain'`); err != nil {
		t.Fatal(err)
	}
	_, err = disp.Dispatch(ctx, user(q10Plain), "notif.mark_all_read", json.RawMessage(`{}`), action.Opts{})
	mustOK(t, "notif.mark_all_read", err)
	if got := scalar(t, d, `SELECT read_at FROM notifications WHERE id='n-plain'`); got == "" {
		t.Error("mark_all_read missed own notification")
	}
	if unreadOther() != "2" {
		t.Fatal("mark_all_read touched another user's notifications")
	}
}

func TestSelfUserExport(t *testing.T) {
	_, disp := q10DB(t)
	ctx := context.Background()
	out, err := disp.Dispatch(ctx, user(q10Plain), "user.export", json.RawMessage(`{}`), action.Opts{})
	mustOK(t, "user.export", err)
	b, _ := json.Marshal(out)
	if !strings.Contains(string(b), `"email":"plain@x.test"`) || strings.Contains(string(b), "other@x.test") {
		t.Errorf("user.export = %s, want the caller's data only", b)
	}
	_, err = disp.Dispatch(ctx, user(q10Plain), "user.export", json.RawMessage(`{"user_id":"u-other"}`), action.Opts{})
	mustForbid(t, "user.export", err)
}

func TestSelfGithubConnection(t *testing.T) {
	d, disp := q10DB(t)
	ctx := context.Background()
	if _, err := d.Exec(`INSERT INTO github_connections (user_id, provider, token_enc, login) VALUES ('u-other','pat','x','octo-other')`); err != nil {
		t.Fatal(err)
	}
	out, err := disp.Dispatch(ctx, user(q10Plain), "github.status", json.RawMessage(`{"user_id":"u-other"}`), action.Opts{})
	mustOK(t, "github.status", err)
	if b, _ := json.Marshal(out); strings.Contains(string(b), "octo-other") {
		t.Fatalf("github.status leaked another user's connection: %s", b)
	}
	_, err = disp.Dispatch(ctx, user(q10Plain), "github.connect", json.RawMessage(`{"source":"pat","token":"ghp_x","login":"octo-plain","user_id":"u-other"}`), action.Opts{})
	mustOK(t, "github.connect", err)
	if got := scalar(t, d, `SELECT login FROM github_connections WHERE user_id='u-plain'`); got != "octo-plain" {
		t.Errorf("own connection login = %q", got)
	}
	if got := scalar(t, d, `SELECT login FROM github_connections WHERE user_id='u-other'`); got != "octo-other" {
		t.Errorf("github.connect overwrote another user's connection: %q", got)
	}
	_, err = disp.Dispatch(ctx, user(q10Plain), "github.disconnect", json.RawMessage(`{"user_id":"u-other"}`), action.Opts{})
	mustOK(t, "github.disconnect", err)
	if n := scalar(t, d, `SELECT COUNT(*) FROM github_connections`); n != "1" {
		t.Fatalf("connections after disconnect = %s, want only the other user's", n)
	}
	if n := scalar(t, d, `SELECT COUNT(*) FROM github_connections WHERE user_id='u-other'`); n != "1" {
		t.Fatal("github.disconnect removed another user's connection")
	}
}

func TestSelfInviteAccept(t *testing.T) {
	d, disp := q10DB(t)
	ctx := context.Background()
	out, err := disp.Dispatch(ctx, user(q10Owner), "member.invite",
		json.RawMessage(`{"org_id":"org-a","email":"plain@x.test","role_id":"r-owner"}`), action.Opts{Org: q10Org})
	if err != nil {
		t.Fatalf("member.invite: %v", err)
	}
	var inv struct {
		Token string `json:"token"`
	}
	b, _ := json.Marshal(out)
	_ = json.Unmarshal(b, &inv)

	if _, err := disp.Dispatch(ctx, user(q10Plain), "invite.accept", json.RawMessage(`{"token":"wrong"}`), action.Opts{}); err == nil {
		t.Fatal("invite.accept with a bad token succeeded")
	}
	_, err = disp.Dispatch(ctx, user(q10Plain), "invite.accept", json.RawMessage(`{"token":"`+inv.Token+`"}`), action.Opts{})
	mustOK(t, "invite.accept", err)
	if n := scalar(t, d, `SELECT COUNT(*) FROM memberships WHERE actor_id='u-plain' AND actor_type='user' AND org_id='org-a'`); n != "1" {
		t.Fatalf("memberships for caller = %s, want 1", n)
	}
	if n := scalar(t, d, `SELECT COUNT(*) FROM memberships WHERE actor_id='u-other'`); n != "0" {
		t.Fatal("invite.accept created a membership for someone else")
	}
	if _, err := disp.Dispatch(ctx, user(q10Other), "invite.accept", json.RawMessage(`{"token":"`+inv.Token+`"}`), action.Opts{}); err == nil {
		t.Fatal("an accepted invite was accepted again")
	}
}

// WU-604: identity.list / identity.unlink only see and touch the caller's
// identities, and never remove the last sign-in method.
func TestSelfIdentities(t *testing.T) {
	d, disp := q10DB(t)
	ctx := context.Background()
	if _, err := d.Exec(`INSERT INTO identities (id, user_id, provider, subject, email, token_enc) VALUES
		('i-p1','u-plain','google','p-g','plain@x.test',X'00'),
		('i-p2','u-plain','github','p-h','plain@x.test',NULL),
		('i-o1','u-other','google','o-g','other@x.test',NULL)`); err != nil {
		t.Fatal(err)
	}
	out, err := disp.Dispatch(ctx, user(q10Plain), "identity.list", json.RawMessage(`{}`), action.Opts{})
	mustOK(t, "identity.list", err)
	b, _ := json.Marshal(out)
	if !strings.Contains(string(b), "i-p1") || !strings.Contains(string(b), "i-p2") || strings.Contains(string(b), "i-o1") {
		t.Fatalf("identity.list = %s", b)
	}
	for _, leak := range []string{"p-g", "subject", "token"} {
		if strings.Contains(string(b), leak) {
			t.Errorf("identity.list leaks %q: %s", leak, b)
		}
	}
	_, err = disp.Dispatch(ctx, user(q10Plain), "identity.list", json.RawMessage(`{"user_id":"u-other"}`), action.Opts{})
	mustForbid(t, "identity.list", err)

	// Another user's identity: not found, untouched (also when naming them).
	if _, err := disp.Dispatch(ctx, user(q10Plain), "identity.unlink", json.RawMessage(`{"id":"i-o1"}`), action.Opts{}); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("unlink another user's identity: err = %v", err)
	}
	_, err = disp.Dispatch(ctx, user(q10Plain), "identity.unlink", json.RawMessage(`{"id":"i-o1","user_id":"u-other"}`), action.Opts{})
	mustForbid(t, "identity.unlink", err)
	if n := scalar(t, d, `SELECT COUNT(*) FROM identities WHERE user_id='u-other'`); n != "1" {
		t.Fatal("another user's identity was removed")
	}

	_, err = disp.Dispatch(ctx, user(q10Plain), "identity.unlink", json.RawMessage(`{"id":"i-p2"}`), action.Opts{})
	mustOK(t, "identity.unlink", err)
	if n := scalar(t, d, `SELECT COUNT(*) FROM identities WHERE id='i-p2'`); n != "0" {
		t.Fatal("own identity not unlinked")
	}
	// Dispatch audits the High action; the handler adds identity.unlinked.
	for _, a := range []string{"identity.unlink", "identity.unlinked"} {
		if n := scalar(t, d, `SELECT COUNT(*) FROM audit_log WHERE action=? AND actor_id='u-plain'`, a); n != "1" {
			t.Errorf("%s audit rows = %s", a, n)
		}
	}
	if _, err := disp.Dispatch(ctx, user(q10Plain), "identity.unlink", json.RawMessage(`{"id":"i-p1"}`), action.Opts{}); !errors.Is(err, action.ErrLastSignInMethod) {
		t.Errorf("last-method unlink: err = %v", err)
	}
	if n := scalar(t, d, `SELECT COUNT(*) FROM identities WHERE id='i-p1'`); n != "1" {
		t.Fatal("last sign-in method removed")
	}
	if n, err := action.SignInMethodCount(ctx, sqlc.New(d), q10Plain); err != nil || n != 1 {
		t.Errorf("SignInMethodCount = %d, %v", n, err)
	}
}

func TestSelfPasskeys(t *testing.T) {
	d, disp := q10DB(t)
	ctx := context.Background()
	if _, err := d.Exec(`INSERT INTO identities (id, user_id, provider, subject, email) VALUES ('i-p1','u-plain','google','p-g','plain@x.test')`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO webauthn_credentials (id, user_id, credential_id, public_key, name) VALUES
		('pk-p','u-plain',X'01',X'AA','Mine'),('pk-o','u-other',X'02',X'BB','Theirs')`); err != nil {
		t.Fatal(err)
	}
	out, err := disp.Dispatch(ctx, user(q10Plain), "passkey.list", json.RawMessage(`{}`), action.Opts{})
	mustOK(t, "passkey.list", err)
	b, _ := json.Marshal(out)
	if !strings.Contains(string(b), "pk-p") || strings.Contains(string(b), "pk-o") || strings.Contains(string(b), "public") {
		t.Fatalf("passkey.list = %s", b)
	}
	_, err = disp.Dispatch(ctx, user(q10Plain), "passkey.list", json.RawMessage(`{"user_id":"u-other"}`), action.Opts{})
	mustForbid(t, "passkey.list", err)
	for _, name := range []string{"passkey.rename", "passkey.delete"} {
		if _, err := disp.Dispatch(ctx, user(q10Plain), name, json.RawMessage(`{"id":"pk-o","name":"x"}`), action.Opts{}); !errors.Is(err, sql.ErrNoRows) {
			t.Errorf("%s another user's passkey: err = %v", name, err)
		}
		_, err = disp.Dispatch(ctx, user(q10Plain), name, json.RawMessage(`{"id":"pk-o","name":"x","user_id":"u-other"}`), action.Opts{})
		mustForbid(t, name, err)
	}
	if n := scalar(t, d, `SELECT COUNT(*) FROM webauthn_credentials WHERE id='pk-o' AND name='Theirs'`); n != "1" {
		t.Fatal("another user's passkey was changed")
	}
	_, err = disp.Dispatch(ctx, user(q10Plain), "passkey.rename", json.RawMessage(`{"id":"pk-p","name":"  Laptop  "}`), action.Opts{})
	mustOK(t, "passkey.rename", err)
	if n := scalar(t, d, `SELECT name FROM webauthn_credentials WHERE id='pk-p'`); n != "Laptop" {
		t.Fatalf("renamed to %q", n)
	}
	if _, err := disp.Dispatch(ctx, user(q10Plain), "passkey.rename", json.RawMessage(`{"id":"pk-p","name":""}`), action.Opts{}); !errors.Is(err, action.ErrPasskeyName) {
		t.Errorf("empty name: %v", err)
	}
	// The passkey and the identity are two methods: either may go, not both.
	_, err = disp.Dispatch(ctx, user(q10Plain), "identity.unlink", json.RawMessage(`{"id":"i-p1"}`), action.Opts{})
	mustOK(t, "identity.unlink with a passkey", err)
	if _, err := disp.Dispatch(ctx, user(q10Plain), "passkey.delete", json.RawMessage(`{"id":"pk-p"}`), action.Opts{}); !errors.Is(err, action.ErrLastSignInMethod) {
		t.Errorf("last-method passkey delete: %v", err)
	}
	if n := scalar(t, d, `SELECT COUNT(*) FROM audit_log WHERE action='passkey.delete'`); n != "0" {
		t.Errorf("refused delete audited: %s", n)
	}
}
