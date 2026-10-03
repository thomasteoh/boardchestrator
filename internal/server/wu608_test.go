package server_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/auth/oidctest"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/event"
)

// WU-608: JIT provisioning and IdP group -> role mapping (SPEC §7.5),
// end to end through the production login wiring against oidctest IdPs.

const (
	roleOwnerSys  = "00000000000000000000000000000000"
	roleTeamAdmin = "11111111111111111111111111111111"
	roleMemberSys = "22222222222222222222222222222222"
	roleViewerSys = "33333333333333333333333333333333"
)

// noGroups sends the groups claim present but empty.
var noGroups = map[string]any{"groups": []string{}}

// membership returns "role/source" for user at resource in org ("" = none).
func (h *smHarness) membership(org, userID, rt, rid string) string {
	h.t.Helper()
	rows, err := h.db.Query(`SELECT COALESCE(role_id,''), source FROM memberships
		WHERE org_id=? AND actor_type='user' AND actor_id=? AND resource_type=? AND resource_id=?`, org, userID, rt, rid)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	out := ""
	for rows.Next() {
		var role, src string
		if err := rows.Scan(&role, &src); err != nil {
			h.t.Fatal(err)
		}
		out = role + "/" + src
	}
	return out
}

// wu608Setup: org-acme owns provider acme-sso (trust_email on) and verified
// corp.example; org-b owns beta-sso and verified beta.example. Both have a
// team and a project. u-alice owns org-acme, u-admin owns org-b.
func wu608Setup(t *testing.T, o smOpts) (*smHarness, *oidctest.Server, *oidctest.Server, *action.Dispatcher) {
	h := newSMHarness(t, o)
	seedSSOOrgs(t, h)
	acme, beta := oidctest.New(t), oidctest.New(t)
	h.orgIdP("acme-sso", "org-acme", acme, true, false)
	h.orgIdP("beta-sso", "org-b", beta, true, false)
	h.verifiedDomain("org-acme", "corp.example", true)
	h.verifiedDomain("org-b", "beta.example", true)
	h.exec(`INSERT INTO teams (id, org_id, name, slug) VALUES ('t-ops','org-acme','Ops','ops'), ('t-bteam','org-b','B team','bteam')`)
	h.exec(`INSERT INTO projects (id, org_id, team_id, name, key) VALUES ('p-web','org-acme','t-ops','Web','WEB'), ('p-bproj','org-b','t-bteam','B proj','BP')`)
	d, _ := orgDispatcher(h)
	return h, acme, beta, d
}

func TestJITSettingsValidation(t *testing.T) {
	h, _, _, d := wu608Setup(t, smOpts{})
	alice := user("u-alice", "")
	sso := func(in map[string]any) error {
		_, err := call(d, alice, "org-acme", "org.sso.update", in)
		return err
	}
	for name, c := range map[string]struct {
		in   map[string]any
		want error
	}{
		"system Owner role":          {map[string]any{"jit_enabled": true, "jit_default_role_id": roleOwnerSys}, action.ErrJITOwnerRole},
		"org role granting *":        {map[string]any{"jit_enabled": true, "jit_default_role_id": "r-owner"}, action.ErrJITOwnerRole},
		"another org's role":         {map[string]any{"jit_enabled": true, "jit_default_role_id": "r-bowner"}, action.ErrMappingRole},
		"unknown role":               {map[string]any{"jit_enabled": true, "jit_default_role_id": "nope"}, action.ErrMappingRole},
		"JIT on without a role":      {map[string]any{"jit_enabled": true}, action.ErrJITNoRole},
		"group claim with a space":   {map[string]any{"group_claim": "my groups"}, action.ErrGroupClaim},
		"group claim over 256 chars": {map[string]any{"group_claim": strings.Repeat("g", 257)}, action.ErrGroupClaim},
	} {
		if err := sso(c.in); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
	}
	if h.n(`SELECT COUNT(*) FROM org_sso_settings WHERE org_id='org-acme'`) != 0 {
		t.Fatal("a refused update wrote settings")
	}
	// A system non-owner role and an org-owned role are fine.
	if err := sso(map[string]any{"jit_enabled": true, "jit_default_role_id": roleMemberSys, "group_claim": "realm_access.roles", "group_sync": true}); err != nil {
		t.Fatal(err)
	}
	out, err := call(d, alice, "org-acme", "org.sso.get", struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	v := out.(action.OrgSSOView)
	if !v.JITEnabled || v.JITDefaultRoleID != roleMemberSys || v.GroupClaim != "realm_access.roles" || !v.GroupSync || v.EnforceSSO {
		t.Fatalf("settings: %+v", v)
	}
	// A partial update keeps the other fields; enforcement is unchanged.
	if err := sso(map[string]any{"jit_default_role_id": "r-member"}); err != nil {
		t.Fatal(err)
	}
	out, _ = call(d, alice, "org-acme", "org.sso.get", struct{}{})
	if v := out.(action.OrgSSOView); !v.JITEnabled || v.JITDefaultRoleID != "r-member" || !v.GroupSync {
		t.Fatalf("partial update: %+v", v)
	}
	// Members without org.sso and other orgs' owners are refused.
	if _, err := call(d, user("u-bob", ""), "org-acme", "org.sso.update", map[string]any{"jit_enabled": false}); !errors.Is(err, action.ErrForbidden) {
		t.Errorf("member: %v", err)
	}
	if _, err := call(d, user("u-admin", ""), "org-acme", "org.sso.update", map[string]any{"jit_enabled": false}); err == nil {
		t.Error("other org's owner changed JIT settings")
	}
	if h.n(`SELECT COUNT(*) FROM audit_log WHERE action='org.sso.update' AND org_id='org-acme'`) != 2 {
		t.Error("org.sso.update not audited")
	}
}

func TestJITProvisioning(t *testing.T) {
	// corp (a platform provider) allows open sign-up and trusts email.
	h, acme, beta, d := wu608Setup(t, smOpts{corpSignup: true, corpTrust: true})
	h.exec(`INSERT INTO users (id, email, name) VALUES ('u-carol','carol@corp.example','Carol')`)
	alice := user("u-alice", "")

	// JIT off: an unknown person on the verified domain is refused.
	acme.SetUser(oidctest.User{Subject: "s-dave", Email: "dave@corp.example", EmailVerified: true})
	if end := h.signIn(oidctest.NewBrowser(t), "acme-sso"); end.Status != http.StatusForbidden {
		t.Fatalf("JIT off: %d", end.Status)
	}
	if _, err := call(d, alice, "org-acme", "org.sso.update", map[string]any{"jit_enabled": true, "jit_default_role_id": "r-member"}); err != nil {
		t.Fatal(err)
	}

	// JIT on: the user, identity and membership are created. The IdP need
	// not mark the email verified (Q8: the org vouches for its own domain).
	acme.SetUser(oidctest.User{Subject: "s-dave", Email: "dave@corp.example", EmailVerified: false, Name: "Dave"})
	if end := h.signIn(oidctest.NewBrowser(t), "acme-sso"); end.Status != http.StatusOK {
		t.Fatalf("JIT sign-up: %d %q", end.Status, end.Body)
	}
	dave := h.userID("dave@corp.example")
	if dave == "" || h.n(`SELECT COUNT(*) FROM identities WHERE provider='acme-sso' AND subject='s-dave' AND user_id=?`, dave) != 1 {
		t.Fatal("JIT did not create the user and identity")
	}
	if got := h.membership("org-acme", dave, "org", "org-acme"); got != "r-member/jit" {
		t.Fatalf("JIT membership: %q", got)
	}
	if h.n(`SELECT COUNT(*) FROM memberships WHERE actor_id=?`, dave) != 1 {
		t.Fatal("JIT granted more than the default membership")
	}
	if h.n(`SELECT COUNT(*) FROM audit_log WHERE action='auth.signup' AND actor_id=? AND json_extract(detail_json,'$.method')='jit'
		AND json_extract(detail_json,'$.org_id')='org-acme'`, dave) != 1 {
		t.Error("auth.signup method jit not audited")
	}
	if h.n(`SELECT COUNT(*) FROM audit_log WHERE action='membership.jit' AND org_id='org-acme' AND subject=?`, dave) != 1 {
		t.Error("membership.jit not audited")
	}
	// A second sign-in adds nothing.
	if end := h.signIn(oidctest.NewBrowser(t), "acme-sso"); end.Status != http.StatusOK {
		t.Fatalf("second sign-in: %d", end.Status)
	}
	if h.n(`SELECT COUNT(*) FROM memberships WHERE actor_id=?`, dave) != 1 ||
		h.n(`SELECT COUNT(*) FROM audit_log WHERE action='membership.jit' AND subject=?`, dave) != 1 {
		t.Fatal("second sign-in re-provisioned")
	}

	// Outside the org's verified domains: refused, nothing created.
	users := h.n(realUsers)
	for _, email := range []string{"eve@example.com", "erin@beta.example", "x@sub.corp.example"} {
		acme.SetUser(oidctest.User{Subject: "s-" + email, Email: email, EmailVerified: true})
		if end := h.signIn(oidctest.NewBrowser(t), "acme-sso"); end.Status != http.StatusForbidden {
			t.Errorf("%s: %d", email, end.Status)
		}
	}
	if h.n(realUsers) != users {
		t.Fatal("JIT created a user outside the org's verified domains")
	}

	// JIT never links to an existing user: carol exists, and an unverified
	// assertion of her address is refused, not linked.
	acme.SetUser(oidctest.User{Subject: "s-carol", Email: "carol@corp.example", EmailVerified: false})
	if end := h.signIn(oidctest.NewBrowser(t), "acme-sso"); end.Status != http.StatusForbidden {
		t.Fatalf("JIT linked an existing user: %d", end.Status)
	}
	if h.n(`SELECT COUNT(*) FROM identities WHERE provider='acme-sso' AND subject='s-carol'`) != 0 ||
		h.membership("org-acme", "u-carol", "org", "org-acme") != "" {
		t.Fatal("unverified JIT assertion linked or provisioned an existing user")
	}
	// Existing non-member linked by the trusted, verified step-3 rule gets
	// the JIT membership.
	acme.SetUser(oidctest.User{Subject: "s-carol", Email: "carol@corp.example", EmailVerified: true})
	if end := h.signIn(oidctest.NewBrowser(t), "acme-sso"); end.Status != http.StatusOK {
		t.Fatalf("existing user: %d %q", end.Status, end.Body)
	}
	if got := h.membership("org-acme", "u-carol", "org", "org-acme"); got != "r-member/jit" {
		t.Fatalf("existing non-member JIT membership: %q", got)
	}
	// An existing member keeps their membership untouched (bob is a manual
	// Member; give him an acme identity on the domain).
	h.exec(`UPDATE users SET email='bob@corp.example' WHERE id='u-bob'`)
	h.exec(`UPDATE memberships SET role_id='r-owner' WHERE id='m-bob'`)
	h.exec(`INSERT INTO identities (id, user_id, provider, subject, email) VALUES ('i-bob-acme','u-bob','acme-sso','s-bob','bob@corp.example')`)
	acme.SetUser(oidctest.User{Subject: "s-bob", Email: "bob@corp.example", EmailVerified: true})
	if end := h.signIn(oidctest.NewBrowser(t), "acme-sso"); end.Status != http.StatusOK {
		t.Fatalf("existing member: %d", end.Status)
	}
	if got := h.membership("org-acme", "u-bob", "org", "org-acme"); got != "r-owner/manual" {
		t.Fatalf("existing member's membership changed: %q", got)
	}

	// Platform providers never JIT: frank signs up through corp (open
	// sign-up) with a corp.example address and joins no org.
	h.corp.SetUser(oidctest.User{Subject: "s-frank", Email: "frank@corp.example", EmailVerified: true})
	if end := h.signIn(oidctest.NewBrowser(t), "corp"); end.Status != http.StatusOK {
		t.Fatalf("platform sign-up: %d", end.Status)
	}
	frank := h.userID("frank@corp.example")
	if frank == "" || h.n(`SELECT COUNT(*) FROM memberships WHERE actor_id=?`, frank) != 0 {
		t.Fatal("a platform provider sign-in created an org membership")
	}

	// Another org's provider never JITs into org-acme, and org-b (JIT off)
	// refuses its own domain.
	beta.SetUser(oidctest.User{Subject: "s-gina", Email: "gina@corp.example", EmailVerified: true})
	if end := h.signIn(oidctest.NewBrowser(t), "beta-sso"); end.Status != http.StatusForbidden {
		t.Errorf("org-b provider with an org-acme address: %d", end.Status)
	}
	beta.SetUser(oidctest.User{Subject: "s-hal", Email: "hal@beta.example", EmailVerified: true})
	if end := h.signIn(oidctest.NewBrowser(t), "beta-sso"); end.Status != http.StatusForbidden {
		t.Errorf("org-b with JIT off: %d", end.Status)
	}

	// A default role edited into an owner role after configuration stops
	// JIT instead of minting owners.
	h.exec(`UPDATE roles SET grants_json='["*"]' WHERE id='r-member'`)
	acme.SetUser(oidctest.User{Subject: "s-ivy", Email: "ivy@corp.example", EmailVerified: true})
	if end := h.signIn(oidctest.NewBrowser(t), "acme-sso"); end.Status != http.StatusForbidden {
		t.Fatalf("JIT with an owner-equivalent default role: %d", end.Status)
	}
	if h.n(`SELECT COUNT(*) FROM users WHERE email='ivy@corp.example'`) != 0 {
		t.Fatal("JIT created a user with an owner-equivalent default role")
	}
	// Never a platform role.
	if h.isPlatformOwner(dave) || h.isPlatformOwner("u-carol") {
		t.Fatal("JIT granted a platform role")
	}
}

func TestIdPMappingActions(t *testing.T) {
	h, _, _, d := wu608Setup(t, smOpts{})
	alice := user("u-alice", "")
	create := func(actor action.Actor, org string, in map[string]string) (action.IdPMappingView, error) {
		out, err := call(d, actor, org, action.ActionIdPMappingCreate, in)
		v, _ := out.(action.IdPMappingView)
		return v, err
	}
	for name, c := range map[string]struct {
		in   map[string]string
		want error
	}{
		"another org's role":     {map[string]string{"group_value": "g", "role_id": "r-bowner"}, action.ErrMappingRole},
		"another org's team":     {map[string]string{"group_value": "g", "role_id": "r-member", "resource_type": "team", "resource_id": "t-bteam"}, action.ErrMappingResource},
		"another org's project":  {map[string]string{"group_value": "g", "role_id": "r-member", "resource_type": "project", "resource_id": "p-bproj"}, action.ErrMappingResource},
		"another org as org":     {map[string]string{"group_value": "g", "role_id": "r-member", "resource_type": "org", "resource_id": "org-b"}, action.ErrMappingResource},
		"unknown resource type":  {map[string]string{"group_value": "g", "role_id": "r-member", "resource_type": "platform"}, action.ErrMappingResource},
		"another org's provider": {map[string]string{"group_value": "g", "role_id": "r-member", "provider_id": "beta-sso"}, action.ErrMappingProvider},
		"platform provider":      {map[string]string{"group_value": "g", "role_id": "r-member", "provider_id": "google"}, action.ErrMappingProvider},
		"empty group":            {map[string]string{"group_value": "  ", "role_id": "r-member"}, action.ErrMappingGroup},
	} {
		if _, err := create(alice, "org-acme", c.in); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
	}
	if _, err := call(d, alice, "org-acme", action.ActionIdPMappingCreate, map[string]any{"group_value": "g", "role_id": "r-member", "extra": 1}); !errors.Is(err, action.ErrInvalidInput) {
		t.Errorf("unknown field: %v", err)
	}
	v, err := create(alice, "org-acme", map[string]string{"group_value": " eng ", "role_id": roleMemberSys})
	if err != nil || v.ResourceType != "org" || v.ResourceID != "org-acme" || v.GroupValue != "eng" {
		t.Fatalf("create: %+v %v", v, err)
	}
	if _, err := create(alice, "org-acme", map[string]string{"group_value": "eng", "role_id": roleViewerSys}); !errors.Is(err, action.ErrMappingExists) {
		t.Errorf("duplicate: %v", err)
	}
	// Same group for one provider only is a different mapping.
	if _, err := create(alice, "org-acme", map[string]string{"group_value": "eng", "role_id": roleViewerSys, "provider_id": "acme-sso"}); err != nil {
		t.Errorf("provider-specific: %v", err)
	}
	// The DB enforces uniqueness with NULL providers too.
	if _, err := h.db.Exec(`INSERT INTO idp_group_mappings (id, org_id, provider_id, group_value, role_id, resource_type, resource_id)
		VALUES ('dup','org-acme',NULL,'eng',?,'org','org-acme')`, roleViewerSys); err == nil {
		t.Error("unique index allowed a duplicate org-wide mapping")
	}
	// Owner mappings are allowed (an org may map its admins group to Owner).
	if _, err := create(alice, "org-acme", map[string]string{"group_value": "admins", "role_id": "r-owner"}); err != nil {
		t.Errorf("owner mapping: %v", err)
	}
	// Permission and tenancy.
	if _, err := create(user("u-bob", ""), "org-acme", map[string]string{"group_value": "x", "role_id": "r-member"}); !errors.Is(err, action.ErrForbidden) {
		t.Errorf("member without org.sso: %v", err)
	}
	if _, err := create(user("u-admin", ""), "org-acme", map[string]string{"group_value": "x", "role_id": "r-member"}); err == nil {
		t.Error("other org's owner created a mapping")
	}
	out, err := call(d, user("u-admin", ""), "org-b", action.ActionIdPMappingList, struct{}{})
	if err != nil || len(out.([]action.IdPMappingView)) != 0 {
		t.Fatalf("org-b sees org-acme's mappings: %v %v", out, err)
	}
	if _, err := call(d, user("u-admin", ""), "org-b", action.ActionIdPMappingDelete, map[string]string{"id": v.ID}); !errors.Is(err, action.ErrMappingNotFound) {
		t.Errorf("cross-org delete: %v", err)
	}
	out, err = call(d, alice, "org-acme", action.ActionIdPMappingList, struct{}{})
	if err != nil || len(out.([]action.IdPMappingView)) != 3 {
		t.Fatalf("list: %v %v", out, err)
	}
	if _, err := call(d, alice, "org-acme", action.ActionIdPMappingDelete, map[string]string{"id": v.ID}); err != nil {
		t.Fatal(err)
	}
	if h.n(`SELECT COUNT(*) FROM idp_group_mappings WHERE id=?`, v.ID) != 0 {
		t.Fatal("delete did nothing")
	}
	if h.n(`SELECT COUNT(*) FROM audit_log WHERE org_id='org-acme' AND action IN ('org.idp_mapping.create','org.idp_mapping.delete')`) != 4 {
		t.Error("mapping changes not audited")
	}
}

func TestGroupSync(t *testing.T) {
	h, acme, beta, d := wu608Setup(t, smOpts{})
	sub, stop := h.srv.Bus().Subscribe(event.Filter{Names: map[string]struct{}{action.EventMembershipSynced: {}}}, 64)
	defer stop()
	alice, bAdmin := user("u-alice", ""), user("u-admin", "")
	mapping := func(actor action.Actor, org string, in map[string]string) string {
		t.Helper()
		out, err := call(d, actor, org, action.ActionIdPMappingCreate, in)
		if err != nil {
			t.Fatalf("mapping %v: %v", in, err)
		}
		return out.(action.IdPMappingView).ID
	}
	mapping(alice, "org-acme", map[string]string{"group_value": "eng", "role_id": "r-member"})
	opsID := mapping(alice, "org-acme", map[string]string{"group_value": "ops", "role_id": roleTeamAdmin, "resource_type": "team", "resource_id": "t-ops"})
	mapping(alice, "org-acme", map[string]string{"group_value": "web", "role_id": roleViewerSys, "resource_type": "project", "resource_id": "p-web", "provider_id": "acme-sso"})
	// org-b maps the same group names; they must never apply to org-acme.
	mapping(bAdmin, "org-b", map[string]string{"group_value": "eng", "role_id": roleMemberSys})
	mapping(bAdmin, "org-b", map[string]string{"group_value": "ops", "role_id": roleMemberSys, "resource_type": "team", "resource_id": "t-bteam"})
	for _, org := range []struct {
		actor action.Actor
		id    string
	}{{alice, "org-acme"}, {bAdmin, "org-b"}} {
		if _, err := call(d, org.actor, org.id, "org.sso.update", map[string]any{"group_sync": true}); err != nil {
			t.Fatal(err)
		}
	}

	// Helen has acme and beta identities, a manual project membership in
	// org-acme and a manual org membership in org-b.
	h.exec(`INSERT INTO users (id, email, name) VALUES ('u-helen','helen@corp.example','Helen')`)
	h.exec(`INSERT INTO identities (id, user_id, provider, subject, email) VALUES
		('i-helen-a','u-helen','acme-sso','s-helen','helen@corp.example'),
		('i-helen-b','u-helen','beta-sso','s-helen-b','helen@corp.example')`)
	h.exec(`INSERT INTO memberships (id, org_id, actor_id, actor_type, resource_type, resource_id, role_id) VALUES
		('m-helen-web','org-acme','u-helen','user','project','p-web','r-member'),
		('m-helen-b','org-b','u-helen','user','org','org-b',?)`, roleViewerSys)
	signInAs := func(srv *oidctest.Server, provider string, u oidctest.User) {
		t.Helper()
		srv.SetUser(u)
		if end := h.signIn(oidctest.NewBrowser(t), provider); end.Status != http.StatusOK {
			t.Fatalf("sign-in via %s: %d %q", provider, end.Status, end.Body)
		}
	}
	state := func() map[string]string {
		return map[string]string{
			"org":     h.membership("org-acme", "u-helen", "org", "org-acme"),
			"team":    h.membership("org-acme", "u-helen", "team", "t-ops"),
			"project": h.membership("org-acme", "u-helen", "project", "p-web"),
			"b-org":   h.membership("org-b", "u-helen", "org", "org-b"),
			"b-team":  h.membership("org-b", "u-helen", "team", "t-bteam"),
		}
	}
	check := func(step string, want map[string]string) {
		t.Helper()
		got := state()
		for k, w := range want {
			if got[k] != w {
				t.Errorf("%s: %s = %q, want %q", step, k, got[k], w)
			}
		}
	}

	// Groups grant org- and team-scoped memberships; the manual project
	// membership is kept (no duplicate, role unchanged); org-b untouched.
	signInAs(acme, "acme-sso", oidctest.User{Subject: "s-helen", Email: "helen@corp.example", EmailVerified: true, Groups: []string{"eng", "ops", "web", "unmapped"}})
	check("first sync", map[string]string{
		"org": "r-member/idp", "team": roleTeamAdmin + "/idp", "project": "r-member/manual",
		"b-org": roleViewerSys + "/manual", "b-team": "",
	})
	if h.n(`SELECT COUNT(*) FROM audit_log WHERE action='membership.synced' AND org_id='org-acme' AND subject='u-helen'`) != 1 {
		t.Error("sync not audited")
	}
	var detail string
	if err := h.db.QueryRow(`SELECT detail_json FROM audit_log WHERE action='membership.synced' AND org_id='org-acme'`).Scan(&detail); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(detail, "helen@") || !strings.Contains(detail, `"added"`) {
		t.Errorf("audit detail: %s", detail)
	}
	select {
	case ev := <-sub.C:
		var r action.SyncResult
		if err := json.Unmarshal(ev.Payload, &r); err != nil {
			t.Fatal(err)
		}
		if ev.Org != "org-acme" || ev.Subject != "u-helen" || len(r.Added) != 2 || len(r.Kept) != 1 || strings.Contains(string(ev.Payload), "@") {
			t.Errorf("event: %+v %s", ev, ev.Payload)
		}
	default:
		t.Fatal("no membership.synced event")
	}

	// Signing in again with the same groups changes nothing and is silent.
	signInAs(acme, "acme-sso", oidctest.User{Subject: "s-helen", Email: "helen@corp.example", EmailVerified: true, Groups: []string{"eng", "ops", "web"}})
	if h.n(`SELECT COUNT(*) FROM audit_log WHERE action='membership.synced' AND org_id='org-acme'`) != 1 {
		t.Error("no-op sync audited")
	}
	select {
	case ev := <-sub.C:
		t.Errorf("no-op sync emitted %+v", ev)
	default:
	}

	// Changing a mapping's role updates the idp membership in place.
	if _, err := call(d, alice, "org-acme", action.ActionIdPMappingDelete, map[string]string{"id": opsID}); err != nil {
		t.Fatal(err)
	}
	mapping(alice, "org-acme", map[string]string{"group_value": "ops", "role_id": roleViewerSys, "resource_type": "team", "resource_id": "t-ops"})
	signInAs(acme, "acme-sso", oidctest.User{Subject: "s-helen", Email: "helen@corp.example", EmailVerified: true, Groups: []string{"eng", "ops"}})
	check("role change", map[string]string{"org": "r-member/idp", "team": roleViewerSys + "/idp", "project": "r-member/manual"})

	// Leaving a group in the IdP removes only that idp membership.
	signInAs(acme, "acme-sso", oidctest.User{Subject: "s-helen", Email: "helen@corp.example", EmailVerified: true, Groups: []string{"ops"}})
	check("left eng", map[string]string{"org": "", "team": roleViewerSys + "/idp", "project": "r-member/manual", "b-org": roleViewerSys + "/manual"})

	// No groups (claim present, empty): every idp membership goes; manual
	// ones survive. An absent claim skips sync instead (WU-609, Q12).
	signInAs(acme, "acme-sso", oidctest.User{Subject: "s-helen", Email: "helen@corp.example", EmailVerified: true, Extra: noGroups})
	check("no groups", map[string]string{"org": "", "team": "", "project": "r-member/manual", "b-org": roleViewerSys + "/manual"})

	// Org-b syncs independently through its own provider: its mapping adds
	// the team membership, the manual org membership stays, org-acme is
	// untouched.
	signInAs(acme, "acme-sso", oidctest.User{Subject: "s-helen", Email: "helen@corp.example", EmailVerified: true, Groups: []string{"eng"}})
	signInAs(beta, "beta-sso", oidctest.User{Subject: "s-helen-b", Email: "helen@corp.example", EmailVerified: true, Groups: []string{"eng", "ops"}})
	check("org-b sync", map[string]string{"org": "r-member/idp", "b-org": roleViewerSys + "/manual", "b-team": roleMemberSys + "/idp"})
	signInAs(beta, "beta-sso", oidctest.User{Subject: "s-helen-b", Email: "helen@corp.example", EmailVerified: true, Extra: noGroups})
	check("org-b cleared", map[string]string{"org": "r-member/idp", "b-team": ""})

	// A platform provider never syncs: Helen via google keeps everything.
	h.exec(`INSERT INTO identities (id, user_id, provider, subject, email) VALUES ('i-helen-g','u-helen','google','s-helen-g','helen@corp.example')`)
	signInAs(h.google, "google", oidctest.User{Subject: "s-helen-g", Email: "helen@corp.example", EmailVerified: true})
	check("platform provider", map[string]string{"org": "r-member/idp"})

	// The org's group_claim override reads another claim.
	if _, err := call(d, alice, "org-acme", "org.sso.update", map[string]any{"group_claim": "app.roles"}); err != nil {
		t.Fatal(err)
	}
	signInAs(acme, "acme-sso", oidctest.User{Subject: "s-helen", Email: "helen@corp.example", EmailVerified: true,
		Groups: []string{"eng"}, Extra: map[string]any{"app": map[string]any{"roles": []string{"ops"}}}})
	check("group claim", map[string]string{"org": "", "team": roleViewerSys + "/idp"})

	// group_sync off: nothing is reconciled.
	if _, err := call(d, alice, "org-acme", "org.sso.update", map[string]any{"group_sync": false}); err != nil {
		t.Fatal(err)
	}
	signInAs(acme, "acme-sso", oidctest.User{Subject: "s-helen", Email: "helen@corp.example", EmailVerified: true})
	check("sync off", map[string]string{"team": roleViewerSys + "/idp"})
	if h.isPlatformOwner("u-helen") {
		t.Fatal("group sync granted a platform role")
	}
}

func TestGroupSyncWithJIT(t *testing.T) {
	// JIT and sync together: a new person gets the idp memberships and the
	// JIT default org membership; the JIT one is never removed by sync.
	h, acme, _, d := wu608Setup(t, smOpts{})
	alice := user("u-alice", "")
	if _, err := call(d, alice, "org-acme", action.ActionIdPMappingCreate, map[string]string{"group_value": "ops", "role_id": roleTeamAdmin, "resource_type": "team", "resource_id": "t-ops"}); err != nil {
		t.Fatal(err)
	}
	if _, err := call(d, alice, "org-acme", "org.sso.update", map[string]any{"jit_enabled": true, "jit_default_role_id": roleViewerSys, "group_sync": true}); err != nil {
		t.Fatal(err)
	}
	acme.SetUser(oidctest.User{Subject: "s-kim", Email: "kim@corp.example", EmailVerified: true, Groups: []string{"ops"}})
	if end := h.signIn(oidctest.NewBrowser(t), "acme-sso"); end.Status != http.StatusOK {
		t.Fatalf("sign-in: %d", end.Status)
	}
	kim := h.userID("kim@corp.example")
	if h.membership("org-acme", kim, "org", "org-acme") != roleViewerSys+"/jit" || h.membership("org-acme", kim, "team", "t-ops") != roleTeamAdmin+"/idp" {
		t.Fatalf("JIT + sync: %q %q", h.membership("org-acme", kim, "org", "org-acme"), h.membership("org-acme", kim, "team", "t-ops"))
	}
	acme.SetUser(oidctest.User{Subject: "s-kim", Email: "kim@corp.example", EmailVerified: true, Extra: noGroups})
	if end := h.signIn(oidctest.NewBrowser(t), "acme-sso"); end.Status != http.StatusOK {
		t.Fatalf("sign-in: %d", end.Status)
	}
	if h.membership("org-acme", kim, "org", "org-acme") != roleViewerSys+"/jit" || h.membership("org-acme", kim, "team", "t-ops") != "" {
		t.Fatal("sync removed the JIT membership or kept a stale idp one")
	}
}

func TestReconcileDirect(t *testing.T) {
	// The function WU-611 (SCIM) calls: provider "" applies only org-wide
	// mappings, and it never acts on the platform org.
	h, _, _, d := wu608Setup(t, smOpts{})
	alice := user("u-alice", "")
	for _, in := range []map[string]string{
		{"group_value": "eng", "role_id": "r-member"},
		{"group_value": "eng", "role_id": roleViewerSys, "resource_type": "team", "resource_id": "t-ops", "provider_id": "acme-sso"},
	} {
		if _, err := call(d, alice, "org-acme", action.ActionIdPMappingCreate, in); err != nil {
			t.Fatal(err)
		}
	}
	h.exec(`INSERT INTO users (id, email, name) VALUES ('u-scim','scim@corp.example','S')`)
	q := sqlc.New(h.db)
	res, err := action.ReconcileIdPMemberships(t.Context(), q, action.SyncInput{
		OrgID: "org-acme", UserID: "u-scim", Groups: []string{"eng"},
		Actor: action.Actor{Type: action.ActorService, ID: "scim:tok"},
	})
	if err != nil || len(res.Added) != 1 || res.Added[0].ResourceType != "org" {
		t.Fatalf("scim sync: %+v %v", res, err)
	}
	if h.n(`SELECT COUNT(*) FROM audit_log WHERE action='membership.synced' AND actor_type='service' AND actor_id='scim:tok'`) != 1 {
		t.Error("service actor not recorded")
	}
	res, err = action.ReconcileIdPMemberships(t.Context(), q, action.SyncInput{OrgID: action.PlatformOrgID, UserID: "u-scim", Groups: []string{"eng"}})
	if err != nil || res.Changed() {
		t.Fatalf("platform org: %+v %v", res, err)
	}
	// Invite acceptance records source='invite'.
	h.exec(`INSERT INTO users (id, email, name) VALUES ('u-zed','zed@corp.example','Z')`)
	tok := h.invite("zed@corp.example", future(), false)
	if _, err := action.AcceptInvite(t.Context(), q, tok, "u-zed", time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := h.membership("org-acme", "u-zed", "org", "org-acme"); got != "r-member/invite" {
		t.Fatalf("invite membership: %q", got)
	}
}

func TestProvisioningPage(t *testing.T) {
	h, _, _, _ := wu608Setup(t, smOpts{})
	b := oidctest.NewBrowser(t)
	_, csrf := h.signedIn(b, "u-alice")
	page := "/app/org/org-acme/settings/sso"
	status, _, body := h.get(b, page)
	if status != http.StatusOK || !strings.Contains(body, "Just-in-time provisioning") || !strings.Contains(body, "Group mappings") {
		t.Fatalf("page: %d", status)
	}
	// The JIT role picker offers no owner roles.
	jitSelect := body[strings.Index(body, `name="jit_default_role_id"`):]
	jitSelect = jitSelect[:strings.Index(jitSelect, "</select>")]
	if strings.Contains(jitSelect, `value="r-owner"`) || strings.Contains(jitSelect, `value="`+roleOwnerSys+`"`) || !strings.Contains(jitSelect, `value="r-member"`) {
		t.Errorf("JIT role options: %s", jitSelect)
	}
	if strings.Contains(body, "t-bteam") || strings.Contains(body, "r-bowner") {
		t.Error("page lists another org's team or role")
	}
	resp := h.postForm(b, page+"/provisioning", csrf, url.Values{"jit_enabled": {"1"}, "jit_default_role_id": {"r-owner"}})
	if loc := resp.Header.Get("Location"); !strings.HasSuffix(loc, "?error=jit_owner") {
		t.Fatalf("owner default: %d %s", resp.StatusCode, loc)
	}
	resp = h.postForm(b, page+"/provisioning", csrf, url.Values{"jit_enabled": {"1"}, "jit_default_role_id": {"r-member"}, "group_sync": {"1"}})
	if loc := resp.Header.Get("Location"); !strings.HasSuffix(loc, "?notice=provisioning_saved") {
		t.Fatalf("save: %d %s", resp.StatusCode, loc)
	}
	resp = h.postForm(b, page+"/mappings", csrf, url.Values{"group_value": {"ops"}, "role_id": {"r-member"}, "target": {"team:t-ops"}, "provider_id": {"acme-sso"}})
	if loc := resp.Header.Get("Location"); !strings.HasSuffix(loc, "?notice=mapping_created") {
		t.Fatalf("add mapping: %s", loc)
	}
	resp = h.postForm(b, page+"/mappings", csrf, url.Values{"group_value": {"x"}, "role_id": {"r-member"}, "target": {"team:t-bteam"}})
	if loc := resp.Header.Get("Location"); !strings.HasSuffix(loc, "?error=mapping_resource") {
		t.Fatalf("cross-org mapping: %s", loc)
	}
	_, _, body = h.get(b, page)
	if !strings.Contains(body, "Team: Ops") || !strings.Contains(body, "<code>ops</code>") || !strings.Contains(body, "Acme SSO") {
		t.Fatal("mapping not listed")
	}
	var id string
	if err := h.db.QueryRow(`SELECT id FROM idp_group_mappings WHERE org_id='org-acme'`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	// No CSRF token: refused.
	if resp := h.postForm(b, page+"/mappings/"+id+"/delete", "", url.Values{}); resp.StatusCode != http.StatusForbidden {
		t.Errorf("delete without CSRF: %d", resp.StatusCode)
	}
	resp = h.postForm(b, page+"/mappings/"+id+"/delete", csrf, url.Values{})
	if loc := resp.Header.Get("Location"); !strings.HasSuffix(loc, "?notice=mapping_deleted") {
		t.Fatalf("delete: %s", loc)
	}
	// A member without org.sso is refused.
	bb := oidctest.NewBrowser(t)
	_, bcsrf := h.signedIn(bb, "u-bob")
	if resp := h.postForm(bb, page+"/mappings", bcsrf, url.Values{"group_value": {"x"}, "role_id": {"r-member"}, "target": {"org:org-acme"}}); resp.StatusCode != http.StatusForbidden {
		t.Errorf("member: %d", resp.StatusCode)
	}
}
