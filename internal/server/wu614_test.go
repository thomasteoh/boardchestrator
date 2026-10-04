package server_test

import (
	"net/http"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/auth/idp"
	"github.com/thomasteoh/boardchestrator/internal/auth/oidctest"
	"github.com/thomasteoh/boardchestrator/internal/auth/samltest"
)

// WU-614: SAML group attributes are found under every common default name
// without a claim override. authentik (and ADFS) send groups as
// http://schemas.xmlsoap.org/claims/Group, which the defaults missed, so a
// real authentik login reached sign-in with its groups treated as absent
// and group sync silently skipped.
func TestSAMLDefaultGroupAttributes(t *testing.T) {
	h := newSMHarness(t, smOpts{})
	seedSSOOrgs(t, h)
	h.verifiedDomain("org-acme", "corp.example", true)
	h.exec(`INSERT INTO users (id, email, name) VALUES ('u-carol','carol@corp.example','Carol')`)
	h.exec(`INSERT INTO org_sso_settings (org_id, group_sync) VALUES ('org-acme', 1)`)
	h.exec(`INSERT INTO idp_group_mappings (id, org_id, provider_id, group_value, role_id, resource_type, resource_id)
		VALUES ('m-eng','org-acme',NULL,'Engineers',?,'org','org-acme')`, roleMemberSys)
	ip := samltest.New(t)
	d, _ := orgDispatcher(h)
	if _, err := call(d, user("u-alice", ""), "org-acme", idp.ActionOrgCreate, map[string]any{
		"id": "acme-saml", "preset": "saml", "metadata_xml": ip.MetadataXML(), "trust_email": true,
	}); err != nil {
		t.Fatal(err)
	}
	h.srv.IdP().Invalidate()
	for _, attr := range []string{
		"http://schemas.microsoft.com/ws/2008/06/identity/claims/groups", // Entra
		"http://schemas.xmlsoap.org/claims/Group",                        // authentik, ADFS
		"groups",
		"memberOf",
	} {
		h.exec(`DELETE FROM memberships WHERE actor_id='u-carol' AND org_id='org-acme'`)
		end := h.samlLogin(oidctest.NewBrowser(t), "acme-saml", ip, samltest.ResponseOptions{
			NameID: "s-carol", Attributes: map[string][]string{"mail": {"carol@corp.example"}, attr: {"Engineers"}},
		})
		if end.Status != http.StatusOK {
			t.Fatalf("%s: login %d %s", attr, end.Status, end.Body)
		}
		if h.n(`SELECT COUNT(*) FROM memberships WHERE actor_id='u-carol' AND org_id='org-acme' AND source='idp' AND role_id=?`, roleMemberSys) != 1 {
			t.Errorf("%s: groups not read from the default attribute", attr)
		}
	}
}
