package server_test

import (
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/auth/idp"
	"github.com/thomasteoh/boardchestrator/internal/auth/oidctest"
	"github.com/thomasteoh/boardchestrator/internal/auth/samltest"
)

// WU-610: SAML 2.0 service provider, end to end through the production
// wiring against the in-process samltest IdP.

// samlProvider creates a platform SAML provider through idp.create (so the
// SP key pair is generated the production way) and returns its certificate.
func (h *smHarness) samlProvider(id string, ip *samltest.IdP, in map[string]any) *x509.Certificate {
	h.t.Helper()
	if err := grantPlatformOwner(h, "u-admin"); err != nil && !strings.Contains(err.Error(), "UNIQUE") {
		h.t.Fatal(err)
	}
	d, _ := orgDispatcher(h)
	body := map[string]any{"id": id, "preset": "saml", "metadata_xml": ip.MetadataXML()}
	for k, v := range in {
		body[k] = v
	}
	if _, err := call(d, user("u-admin", ""), "", idp.ActionCreate, body); err != nil {
		h.t.Fatalf("idp.create saml: %v", err)
	}
	h.srv.IdP().Invalidate()
	return h.spCert(id)
}

func (h *smHarness) spCert(id string) *x509.Certificate {
	h.t.Helper()
	var certPEM string
	if err := h.db.QueryRow(`SELECT sp_cert FROM auth_providers WHERE id = ?`, id).Scan(&certPEM); err != nil {
		h.t.Fatal(err)
	}
	b, _ := pem.Decode([]byte(certPEM))
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		h.t.Fatal(err)
	}
	return cert
}

// samlBegin starts a login and returns the decoded AuthnRequest.
func (h *smHarness) samlBegin(b *oidctest.Browser, id, query string) *samltest.AuthnRequest {
	h.t.Helper()
	resp, err := b.Get(h.app.URL + "/auth/" + id + query)
	if err != nil {
		h.t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		h.t.Fatalf("begin %s: status %d", id, resp.StatusCode)
	}
	ar, err := samltest.ParseAuthnRequest(resp.Header.Get("Location"), h.spCert(id))
	if err != nil {
		h.t.Fatal(err)
	}
	return ar
}

// samlPost posts a SAMLResponse to the ACS and follows the redirects.
func (h *smHarness) samlPost(b *oidctest.Browser, id, samlResponse, relayState string) oidctest.Step {
	h.t.Helper()
	form := url.Values{"SAMLResponse": {samlResponse}, "RelayState": {relayState}}
	req, _ := http.NewRequest(http.MethodPost, auth.SAMLACSURL(h.app.URL, id), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := b.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		return oidctest.Step{URL: req.URL.String(), Status: resp.StatusCode, Body: string(body)}
	}
	return h.follow(b, resp.Header.Get("Location"))
}

// samlLogin runs a full SP-initiated login; o.InResponseTo and o.ACS
// default to the real request's.
func (h *smHarness) samlLogin(b *oidctest.Browser, id string, ip *samltest.IdP, o samltest.ResponseOptions) oidctest.Step {
	h.t.Helper()
	ar := h.samlBegin(b, id, "")
	if o.InResponseTo == "" {
		o.InResponseTo = ar.Request.ID
	}
	if o.ACS == "" {
		o.ACS = auth.SAMLACSURL(h.app.URL, id)
	}
	return h.samlPost(b, id, ip.Response(auth.SAMLEntityID(h.app.URL, id), o), ar.RelayState)
}

func TestSAMLLogin(t *testing.T) {
	h := newSMHarness(t, smOpts{})
	ip := samltest.New(t)
	h.samlProvider("corp-saml", ip, map[string]any{"trust_email": true, "allow_signup": true})

	// The AuthnRequest is signed by the SP key, asks for the POST binding at
	// the ACS, and the flow cookie is SameSite=None (SPEC §7.2).
	b := oidctest.NewBrowser(t)
	ar := h.samlBegin(b, "corp-saml", "")
	if !ar.Signed || ar.Request.AssertionConsumerServiceURL != auth.SAMLACSURL(h.app.URL, "corp-saml") ||
		ar.Request.ProtocolBinding != saml.HTTPPostBinding || ar.Request.Issuer.Value != auth.SAMLEntityID(h.app.URL, "corp-saml") {
		t.Fatalf("authn request: %+v signed=%v", ar.Request, ar.Signed)
	}
	flowCookie := func(b *oidctest.Browser) *http.Cookie {
		for i := len(b.SetCookies) - 1; i >= 0; i-- {
			if c := b.SetCookies[i]; c.Name == auth.FlowCookieName && c.Value != "" {
				return c
			}
		}
		t.Fatal("no flow cookie set")
		return nil
	}
	if c := flowCookie(b); c.SameSite != http.SameSiteNoneMode || !c.Secure || !c.HttpOnly {
		t.Fatalf("SAML flow cookie: %+v", c)
	}
	// OIDC flows keep SameSite=Lax.
	ob := oidctest.NewBrowser(t)
	if resp, err := ob.Get(h.app.URL + "/auth/google"); err != nil || resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("oidc begin: %v", err)
	}
	if c := flowCookie(ob); c.SameSite != http.SameSiteLaxMode {
		t.Fatalf("OIDC flow cookie SameSite = %v", c.SameSite)
	}

	// The trusted provider links Bob by email (§7.3 step 3).
	end := h.samlPost(b, "corp-saml", ip.Response(auth.SAMLEntityID(h.app.URL, "corp-saml"), samltest.ResponseOptions{
		InResponseTo: ar.Request.ID, ACS: auth.SAMLACSURL(h.app.URL, "corp-saml"),
		NameID: "bob-persistent", SessionIndex: "si-1",
		Attributes: map[string][]string{
			"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": {"bob@example.com"},
			"displayName": {"Bob B"},
		},
	}), ar.RelayState)
	if end.Status != http.StatusOK {
		t.Fatalf("saml login: %d %s", end.Status, end.Body)
	}
	if h.n(`SELECT COUNT(*) FROM identities WHERE provider='corp-saml' AND subject='bob-persistent' AND user_id='u-bob'`) != 1 {
		t.Fatal("SAML login did not link Bob")
	}
	if h.n(`SELECT COUNT(*) FROM sessions WHERE user_id='u-bob' AND provider_id='corp-saml' AND auth_method='saml'
		AND idp_sid='si-1' AND idp_subject='bob-persistent' AND id_token_enc <> ''`) != 1 {
		t.Fatal("session provenance not recorded")
	}
	if h.n(`SELECT COUNT(*) FROM audit_log WHERE action='identity.linked_by_email' AND subject LIKE '%corp-saml%'`)+
		h.n(`SELECT COUNT(*) FROM audit_log WHERE action='identity.linked_by_email'`) == 0 {
		t.Fatal("no link audit")
	}
	// Second login: identity hit, same user.
	if end := h.samlLogin(oidctest.NewBrowser(t), "corp-saml", ip, samltest.ResponseOptions{NameID: "bob-persistent"}); end.Status != http.StatusOK {
		t.Fatalf("second login: %d", end.Status)
	}
	// A new person signs up (allow_signup) with a signed response only.
	if end := h.samlLogin(oidctest.NewBrowser(t), "corp-saml", ip, samltest.ResponseOptions{
		NameID: "carol-p", Unsigned: true, SignResponse: true,
		Attributes: map[string][]string{"mail": {"carol@example.net"}, "givenName": {"Carol"}, "sn": {"Smith"}},
	}); end.Status != http.StatusOK {
		t.Fatalf("signed-response sign-up: %d %s", end.Status, end.Body)
	}
	if h.n(`SELECT COUNT(*) FROM users u JOIN identities i ON i.user_id=u.id WHERE i.provider='corp-saml'
		AND i.subject='carol-p' AND u.email='carol@example.net' AND u.name='Carol Smith'`) != 1 {
		t.Fatal("sign-up did not create Carol from the attributes")
	}
	// No secret or key material in the audit log.
	assertAuditClean(t, h, "PRIVATE KEY")
}

func TestSAMLRejections(t *testing.T) {
	h := newSMHarness(t, smOpts{})
	ip := samltest.New(t)
	h.samlProvider("corp-saml", ip, map[string]any{"trust_email": true, "allow_signup": true})
	entity := auth.SAMLEntityID(h.app.URL, "corp-saml")
	mail := map[string][]string{"mail": {"new@example.net"}}
	now := time.Now()

	cases := []struct {
		name string
		o    samltest.ResponseOptions
	}{
		{"unsigned assertion", samltest.ResponseOptions{Unsigned: true}},
		{"wrong key", samltest.ResponseOptions{WrongKey: true}},
		{"tampered NameID", samltest.ResponseOptions{TamperNameID: "evil"}},
		{"wrong audience", samltest.ResponseOptions{Audience: "https://other.example/sp"}},
		{"no audience", samltest.ResponseOptions{OmitAudience: true}},
		{"expired", samltest.ResponseOptions{NotOnOrAfter: now.Add(-3 * time.Minute)}},
		{"expired within crewjam's skew but not ours", samltest.ResponseOptions{NotOnOrAfter: now.Add(-150 * time.Second)}},
		{"not yet valid", samltest.ResponseOptions{NotBefore: now.Add(5 * time.Minute), NotOnOrAfter: now.Add(10 * time.Minute)}},
		{"unsolicited", samltest.ResponseOptions{OmitInResponseTo: true}},
		{"wrong InResponseTo", samltest.ResponseOptions{InResponseTo: "id-not-ours"}},
		{"wrong issuer", samltest.ResponseOptions{Issuer: "https://evil.example/idp"}},
		{"wrong recipient", samltest.ResponseOptions{ACS: h.app.URL + "/auth/saml/other/acs"}},
		{"transient NameID", samltest.ResponseOptions{NameIDFormat: string(saml.TransientNameIDFormat)}},
		{"email NameID without opt-in", samltest.ResponseOptions{NameIDFormat: string(saml.EmailAddressNameIDFormat)}},
		{"signature wrapping", samltest.ResponseOptions{Inject: &samltest.ResponseOptions{
			NameID: "evil-sub", Attributes: map[string][]string{"mail": {"bob@example.com"}},
		}}},
		{"signature wrapping, signed response", samltest.ResponseOptions{SignResponse: true, Inject: &samltest.ResponseOptions{
			NameID: "evil-sub", Attributes: map[string][]string{"mail": {"bob@example.com"}},
		}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sessions := h.n(`SELECT COUNT(*) FROM sessions`)
			o := tc.o
			o.NameID = "victim-" + strings.ReplaceAll(tc.name, " ", "-")
			o.Attributes = mail
			if o.Inject != nil {
				o.Inject.ACS = auth.SAMLACSURL(h.app.URL, "corp-saml")
			}
			b := oidctest.NewBrowser(t)
			ar := h.samlBegin(b, "corp-saml", "")
			if o.InResponseTo == "" {
				o.InResponseTo = ar.Request.ID
			}
			if o.Inject != nil {
				o.Inject.InResponseTo = ar.Request.ID
			}
			if o.ACS == "" {
				o.ACS = auth.SAMLACSURL(h.app.URL, "corp-saml")
			}
			end := h.samlPost(b, "corp-saml", ip.Response(entity, o), ar.RelayState)
			if end.Status < 400 {
				t.Fatalf("accepted: %d", end.Status)
			}
			if h.n(`SELECT COUNT(*) FROM sessions`) != sessions {
				t.Fatal("a session was created")
			}
			if h.n(`SELECT COUNT(*) FROM identities WHERE provider='corp-saml'`) != 0 {
				t.Fatal("an identity was created")
			}
			if strings.Contains(end.Body, "InResponseTo") || strings.Contains(end.Body, "audience") {
				t.Fatalf("internal error reflected: %s", end.Body)
			}
		})
	}

	// Replay: the same assertion id in a second, otherwise valid response.
	o := samltest.ResponseOptions{NameID: "replay-sub", AssertionID: "a-fixed-id", Attributes: mail}
	if end := h.samlLogin(oidctest.NewBrowser(t), "corp-saml", ip, o); end.Status != http.StatusOK {
		t.Fatalf("first use: %d %s", end.Status, end.Body)
	}
	if end := h.samlLogin(oidctest.NewBrowser(t), "corp-saml", ip, o); end.Status < 400 {
		t.Fatalf("replayed assertion accepted: %d", end.Status)
	}
	// The same response posted again to its own flow: the flow cookie is gone.
	b := oidctest.NewBrowser(t)
	ar := h.samlBegin(b, "corp-saml", "")
	resp := ip.Response(entity, samltest.ResponseOptions{
		InResponseTo: ar.Request.ID, ACS: auth.SAMLACSURL(h.app.URL, "corp-saml"), NameID: "twice", Attributes: mail,
	})
	if end := h.samlPost(b, "corp-saml", resp, ar.RelayState); end.Status != http.StatusOK {
		t.Fatalf("first post: %d", end.Status)
	}
	if end := h.samlPost(b, "corp-saml", resp, ar.RelayState); end.Status < 400 {
		t.Fatalf("second post accepted: %d", end.Status)
	}
	// RelayState must match the flow, and the flow must be present.
	b = oidctest.NewBrowser(t)
	ar = h.samlBegin(b, "corp-saml", "")
	resp = ip.Response(entity, samltest.ResponseOptions{InResponseTo: ar.Request.ID, ACS: auth.SAMLACSURL(h.app.URL, "corp-saml"), NameID: "rs", Attributes: mail})
	if end := h.samlPost(b, "corp-saml", resp, "not-the-state"); end.Status != http.StatusBadRequest {
		t.Fatalf("relay state mismatch: %d", end.Status)
	}
	if end := h.samlPost(oidctest.NewBrowser(t), "corp-saml", resp, ar.RelayState); end.Status != http.StatusBadRequest {
		t.Fatalf("no flow cookie: %d", end.Status)
	}
	// An OIDC callback URL never accepts a SAML provider.
	if r, _ := oidctest.NewBrowser(t).Get(h.app.URL + "/auth/corp-saml/callback?state=x"); r.StatusCode != http.StatusNotFound {
		t.Fatalf("callback for SAML provider: %d", r.StatusCode)
	}
	if h.n(`SELECT COUNT(*) FROM identities WHERE subject='evil-sub'`) != 0 {
		t.Fatal("the injected unsigned assertion was used")
	}
}

// The wrapped (unsigned, injected) assertion is never the one used, even
// when the IdP would otherwise allow the user: here both name real users.
func TestSAMLSignatureWrappingNeverUsesUnsigned(t *testing.T) {
	h := newSMHarness(t, smOpts{})
	ip := samltest.New(t)
	h.samlProvider("corp-saml", ip, map[string]any{"trust_email": true})
	h.exec(`INSERT INTO identities (id, user_id, provider, subject, email) VALUES ('i-alice-s','u-alice','corp-saml','alice-p','alice@example.com'),
		('i-bob-s','u-bob','corp-saml','bob-p','bob@example.com')`)
	for _, signResp := range []bool{false, true} {
		end := h.samlLogin(oidctest.NewBrowser(t), "corp-saml", ip, samltest.ResponseOptions{
			NameID: "alice-p", SignResponse: signResp,
			Inject: &samltest.ResponseOptions{NameID: "bob-p", ACS: auth.SAMLACSURL(h.app.URL, "corp-saml")},
		})
		if end.Status < 400 {
			t.Fatalf("wrapped response accepted (signed response %v)", signResp)
		}
	}
	if h.n(`SELECT COUNT(*) FROM sessions WHERE user_id IN ('u-alice','u-bob')`) != 0 {
		t.Fatal("a session was issued for a wrapped response")
	}
}

func TestSAMLMetadataAndCertificate(t *testing.T) {
	h := newSMHarness(t, smOpts{})
	ip := samltest.New(t)
	cert := h.samlProvider("corp-saml", ip, nil)
	resp, err := http.Get(h.app.URL + "/auth/saml/corp-saml/metadata")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Header.Get("Content-Type"), "samlmetadata+xml") {
		t.Fatalf("metadata: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	var md saml.EntityDescriptor
	if err := xml.Unmarshal(body, &md); err != nil {
		t.Fatalf("metadata is not valid SAML metadata: %v", err)
	}
	if md.EntityID != auth.SAMLEntityID(h.app.URL, "corp-saml") || len(md.SPSSODescriptors) != 1 {
		t.Fatalf("entity: %+v", md)
	}
	sp := md.SPSSODescriptors[0]
	if len(sp.AssertionConsumerServices) != 1 || sp.AssertionConsumerServices[0].Binding != saml.HTTPPostBinding ||
		sp.AssertionConsumerServices[0].Location != auth.SAMLACSURL(h.app.URL, "corp-saml") {
		t.Fatalf("ACS: %+v", sp.AssertionConsumerServices)
	}
	slo := map[string]string{}
	for _, e := range sp.SingleLogoutServices {
		slo[e.Binding] = e.Location
	}
	if slo[saml.HTTPRedirectBinding] != auth.SAMLSLOURL(h.app.URL, "corp-saml") || slo[saml.HTTPPostBinding] == "" {
		t.Fatalf("SLO: %+v", sp.SingleLogoutServices)
	}
	found := false
	for _, kd := range sp.KeyDescriptors {
		for _, c := range kd.KeyInfo.X509Data.X509Certificates {
			if strings.Contains(c.Data, strings.TrimSpace(pemBody(cert))) {
				found = true
			}
		}
	}
	if !found || strings.Contains(string(body), "PRIVATE") {
		t.Fatal("metadata lacks the SP certificate (or leaks the key)")
	}
	r2, err := http.Get(h.app.URL + "/auth/saml/corp-saml/certificate")
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, _ := io.ReadAll(r2.Body)
	_ = r2.Body.Close()
	if blk, _ := pem.Decode(pemBytes); blk == nil || blk.Type != "CERTIFICATE" || string(blk.Bytes) != string(cert.Raw) {
		t.Fatal("certificate download")
	}
	// Unknown, disabled and non-SAML providers have no metadata.
	h.exec(`UPDATE auth_providers SET enabled = 0 WHERE id = 'corp-saml'`)
	h.srv.IdP().Invalidate()
	for _, p := range []string{"corp-saml", "google", "nope"} {
		if r, _ := http.Get(h.app.URL + "/auth/saml/" + p + "/metadata"); r.StatusCode != http.StatusNotFound {
			t.Errorf("metadata for %s: %d", p, r.StatusCode)
		}
	}
	// Key material is never returned by the actions.
	d, _ := orgDispatcher(h)
	out, err := call(d, user("u-admin", ""), "", idp.ActionGet, map[string]string{"id": "corp-saml"})
	if err != nil {
		t.Fatal(err)
	}
	if v := out.(idp.ProviderView); v.SPCert == "" || strings.Contains(v.SPCert, "PRIVATE") {
		t.Fatalf("view: cert %q", v.SPCert)
	}
}

func pemBody(c *x509.Certificate) string {
	s := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	s = strings.TrimPrefix(s, "-----BEGIN CERTIFICATE-----\n")
	s = strings.TrimSuffix(s, "-----END CERTIFICATE-----\n")
	return strings.ReplaceAll(s, "\n", "")[:40]
}

func TestSAMLSPInitiatedLogout(t *testing.T) {
	h := newSMHarness(t, smOpts{})
	ip := samltest.New(t)
	cert := h.samlProvider("corp-saml", ip, map[string]any{"trust_email": true})
	b := oidctest.NewBrowser(t)
	if end := h.samlLogin(b, "corp-saml", ip, samltest.ResponseOptions{
		NameID: "bob-p", SessionIndex: "si-bob", Attributes: map[string][]string{"mail": {"bob@example.com"}},
	}); end.Status != http.StatusOK {
		t.Fatalf("login: %d", end.Status)
	}
	resp := h.post(b, "/auth/logout", h.csrfOf(b))
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(loc, ip.SLOURL()+"?") {
		t.Fatalf("logout redirect: %d %s", resp.StatusCode, loc)
	}
	lr, relay, err := samltest.ParseLogoutRequest(loc, cert)
	if err != nil {
		t.Fatalf("LogoutRequest not signed by the SP: %v", err)
	}
	if lr.NameID == nil || lr.NameID.Value != "bob-p" || lr.SessionIndex == nil || lr.SessionIndex.Value != "si-bob" ||
		lr.Issuer.Value != auth.SAMLEntityID(h.app.URL, "corp-saml") || lr.Destination != ip.SLOURL() {
		t.Fatalf("LogoutRequest: %+v", lr)
	}
	if h.n(`SELECT COUNT(*) FROM sessions WHERE user_id='u-bob'`) != 0 {
		t.Fatal("session not revoked")
	}
	if h.n(`SELECT COUNT(*) FROM audit_log WHERE action='auth.logout' AND detail_json LIKE '%"idp_logout":"1"%'`) != 1 {
		t.Fatal("logout audit")
	}
	// The IdP answers at the SLO endpoint: back to the signed-out page.
	end := h.follow(b, ip.LogoutResponseURL(auth.SAMLSLOURL(h.app.URL, "corp-saml"), lr.ID, relay, false))
	if end.Status != http.StatusOK || !strings.Contains(end.URL, "/login?signed_out=1") {
		t.Fatalf("logout response: %d %s", end.Status, end.URL)
	}
	// Even an unsigned (bad) response only lands on the signed-out page.
	end = h.follow(oidctest.NewBrowser(t), ip.LogoutResponseURL(auth.SAMLSLOURL(h.app.URL, "corp-saml"), lr.ID, relay, true))
	if !strings.Contains(end.URL, "/login?signed_out=1") {
		t.Fatalf("unsigned logout response: %s", end.URL)
	}

	// IdP sign-out off, or no SLO endpoint: local logout only.
	for _, setup := range []func(){
		func() { h.exec(`UPDATE auth_providers SET idp_logout = 0 WHERE id='corp-saml'`) },
		func() {
			h.exec(`UPDATE auth_providers SET idp_logout = 1 WHERE id='corp-saml'`)
			ip.SetSLOSupported(false)
			h.exec(`UPDATE auth_providers SET saml_metadata_xml = ? WHERE id='corp-saml'`, ip.MetadataXML())
		},
	} {
		setup()
		h.srv.IdP().Invalidate()
		b := oidctest.NewBrowser(t)
		if end := h.samlLogin(b, "corp-saml", ip, samltest.ResponseOptions{
			NameID: "bob-p", Attributes: map[string][]string{"mail": {"bob@example.com"}},
		}); end.Status != http.StatusOK {
			t.Fatalf("login: %d", end.Status)
		}
		resp := h.post(b, "/auth/logout", h.csrfOf(b))
		if resp.Header.Get("Location") != auth.SignedOutURL {
			t.Fatalf("expected local logout, got %s", resp.Header.Get("Location"))
		}
	}
}

func TestSAMLIdPInitiatedLogout(t *testing.T) {
	h := newSMHarness(t, smOpts{})
	ip := samltest.New(t)
	cert := h.samlProvider("corp-saml", ip, map[string]any{"trust_email": true})
	slo := auth.SAMLSLOURL(h.app.URL, "corp-saml")
	login := func(si string) *oidctest.Browser {
		b := oidctest.NewBrowser(t)
		if end := h.samlLogin(b, "corp-saml", ip, samltest.ResponseOptions{
			NameID: "bob-p", SessionIndex: si, Attributes: map[string][]string{"mail": {"bob@example.com"}},
		}); end.Status != http.StatusOK {
			t.Fatalf("login: %d", end.Status)
		}
		return b
	}
	sessions := func(si string) int {
		return h.n(`SELECT COUNT(*) FROM sessions WHERE provider_id='corp-saml' AND idp_sid=?`, si)
	}
	login("si-1")
	login("si-2")
	login("si-3")

	// Refused: unsigned, wrong key, wrong issuer, wrong destination, stale;
	// nothing is revoked.
	bad := []samltest.LogoutOptions{
		{SLO: slo, NameID: "bob-p", Unsigned: true},
		{SLO: slo, NameID: "bob-p", WrongKey: true},
		{SLO: slo, NameID: "bob-p", Issuer: "https://evil.example/idp"},
		{SLO: h.app.URL + "/auth/saml/other/slo", NameID: "bob-p"},
		{SLO: slo, NameID: "bob-p", IssueInstant: time.Now().Add(-10 * time.Minute)},
	}
	for i, o := range bad {
		u := ip.LogoutRequestURL(o)
		if o.SLO != slo {
			u = slo + u[strings.Index(u, "?"):]
		}
		r, err := oidctest.NewBrowser(t).Get(u)
		if err != nil {
			t.Fatal(err)
		}
		if r.StatusCode != http.StatusBadRequest {
			t.Errorf("bad redirect logout %d: %d", i, r.StatusCode)
		}
		form := url.Values{"SAMLRequest": {ip.LogoutRequestPost(o)}}
		if pr := browserPost(t, slo, form); pr.StatusCode != http.StatusBadRequest {
			t.Errorf("bad POST logout %d: %d", i, pr.StatusCode)
		}
	}
	if sessions("si-1")+sessions("si-2")+sessions("si-3") != 3 {
		t.Fatal("a refused logout request revoked sessions")
	}

	// Redirect binding naming SessionIndex si-1: only that session goes, and
	// the browser returns to the IdP with a signed LogoutResponse.
	r, err := oidctest.NewBrowser(t).Get(ip.LogoutRequestURL(samltest.LogoutOptions{
		SLO: slo, NameID: "bob-p", SessionIndexes: []string{"si-1"}, ID: "lr-one", RelayState: "rs-1",
	}))
	if err != nil {
		t.Fatal(err)
	}
	loc := r.Header.Get("Location")
	if r.StatusCode != http.StatusSeeOther || !strings.HasPrefix(loc, ip.SLOURL()+"?") {
		t.Fatalf("IdP logout: %d %s", r.StatusCode, loc)
	}
	lresp, err := samltest.ParseLogoutResponse(loc, cert)
	if err != nil {
		t.Fatalf("LogoutResponse: %v", err)
	}
	if lresp.InResponseTo != "lr-one" || lresp.Status.StatusCode.Value != saml.StatusSuccess || lresp.Destination != ip.SLOURL() {
		t.Fatalf("LogoutResponse: %+v", lresp)
	}
	if u, _ := url.Parse(loc); u.Query().Get("RelayState") != "rs-1" {
		t.Fatal("RelayState not echoed")
	}
	if sessions("si-1") != 0 || sessions("si-2")+sessions("si-3") != 2 {
		t.Fatal("session-index logout revoked the wrong sessions")
	}
	if h.n(`SELECT COUNT(*) FROM audit_log WHERE action='auth.saml_logout' AND actor_type='service' AND actor_id='idp:corp-saml'`) != 1 {
		t.Fatal("audit")
	}
	// Replay of the same LogoutRequest id is refused.
	r, _ = oidctest.NewBrowser(t).Get(ip.LogoutRequestURL(samltest.LogoutOptions{
		SLO: slo, NameID: "bob-p", SessionIndexes: []string{"si-2"}, ID: "lr-one",
	}))
	if r.StatusCode != http.StatusBadRequest || sessions("si-2") != 1 {
		t.Fatalf("replayed logout request: %d", r.StatusCode)
	}
	// POST binding (CSRF-exempt, no token), NameID only: every session of
	// that NameID goes.
	pr := browserPost(t, slo, url.Values{"SAMLRequest": {ip.LogoutRequestPost(samltest.LogoutOptions{SLO: slo, NameID: "bob-p"})}})
	if pr.StatusCode != http.StatusSeeOther || !strings.HasPrefix(pr.Header.Get("Location"), ip.SLOURL()+"?") {
		t.Fatalf("POST logout: %d %s", pr.StatusCode, pr.Header.Get("Location"))
	}
	if h.n(`SELECT COUNT(*) FROM sessions WHERE provider_id='corp-saml'`) != 0 {
		t.Fatal("NameID logout left sessions")
	}
}

// Org-owned SAML providers: created by the org owner through org.idp.*,
// trusted for email only on the org's verified domains (§7.3/§7.4).
func TestSAMLOrgProvider(t *testing.T) {
	h := newSMHarness(t, smOpts{})
	seedSSOOrgs(t, h)
	h.verifiedDomain("org-acme", "corp.example", true)
	h.exec(`INSERT INTO users (id, email, name) VALUES ('u-carol','carol@corp.example','Carol')`)
	ip := samltest.New(t)
	d, _ := orgDispatcher(h)
	alice := user("u-alice", "")
	in := map[string]any{"id": "acme-saml", "preset": "entra-saml", "metadata_url": ip.MetadataURL(), "trust_email": true}
	if _, err := call(d, alice, "org-acme", idp.ActionOrgCreate, in); err != nil {
		t.Fatalf("org.idp.create saml: %v", err)
	}
	// Validation: OIDC fields, both or neither metadata, bad XML.
	for _, bad := range []map[string]any{
		{"id": "acme-s2", "preset": "saml", "metadata_url": ip.MetadataURL(), "client_id": "x"},
		{"id": "acme-s3", "preset": "saml"},
		{"id": "acme-s4", "preset": "saml", "metadata_url": ip.MetadataURL(), "metadata_xml": ip.MetadataXML()},
		{"id": "acme-s5", "preset": "saml", "metadata_xml": "<nope/>"},
		{"id": "acme-s6", "preset": "saml", "metadata_url": "ftp://x"},
		{"id": "acme-s7", "preset": "saml", "metadata_url": ip.MetadataURL(), "claim_map": map[string]string{"picture": "x"}},
	} {
		if _, err := call(d, alice, "org-acme", idp.ActionOrgCreate, bad); !errors.Is(err, action.ErrInvalidInput) {
			t.Errorf("%v: %v", bad, err)
		}
	}
	var keyEnc, cert string
	if err := h.db.QueryRow(`SELECT sp_key_enc, sp_cert FROM auth_providers WHERE id='acme-saml'`).Scan(&keyEnc, &cert); err != nil || keyEnc == "" ||
		strings.Contains(keyEnc, "PRIVATE") || !strings.Contains(cert, "CERTIFICATE") {
		t.Fatalf("SP key pair not generated and sealed: %v", err)
	}
	out, err := call(d, alice, "org-acme", idp.ActionOrgGet, map[string]string{"id": "acme-saml"})
	if err != nil {
		t.Fatal(err)
	}
	if v := out.(idp.ProviderView); v.Kind != idp.KindSAML || v.MetadataURL != ip.MetadataURL() {
		t.Fatalf("org view: %+v", v)
	}
	h.srv.IdP().Invalidate()
	attrs := func(email string) map[string][]string { return map[string][]string{"mail": {email}} }

	// Outside the verified domain: never links (Bob exists with that email).
	if end := h.samlLogin(oidctest.NewBrowser(t), "acme-saml", ip, samltest.ResponseOptions{NameID: "s-bob", Attributes: attrs("bob@example.com")}); end.Status != http.StatusForbidden {
		t.Fatalf("outside domain: %d", end.Status)
	}
	// On the verified domain, trusted: links Carol.
	if end := h.samlLogin(oidctest.NewBrowser(t), "acme-saml", ip, samltest.ResponseOptions{NameID: "s-carol", Attributes: attrs("carol@corp.example")}); end.Status != http.StatusOK {
		t.Fatalf("verified domain: %d %s", end.Status, end.Body)
	}
	if h.n(`SELECT COUNT(*) FROM identities WHERE provider='acme-saml' AND subject='s-carol' AND user_id='u-carol'`) != 1 {
		t.Fatal("org SAML provider did not link on its verified domain")
	}
	// No open sign-up through an org provider.
	if end := h.samlLogin(oidctest.NewBrowser(t), "acme-saml", ip, samltest.ResponseOptions{NameID: "s-dave", Attributes: attrs("dave@corp.example")}); end.Status != http.StatusForbidden {
		t.Fatalf("org sign-up: %d", end.Status)
	}
	if h.n(`SELECT COUNT(*) FROM identities WHERE subject IN ('s-bob','s-dave')`) != 0 {
		t.Fatal("org provider created identities outside policy")
	}
	// Untrusted: no link even on the verified domain (SAML has no
	// email-verified flag; trust_email is the only source).
	if _, err := call(d, alice, "org-acme", idp.ActionOrgUpdate, map[string]any{
		"id": "acme-saml", "preset": "entra-saml", "metadata_url": ip.MetadataURL(), "trust_email": false,
	}); err != nil {
		t.Fatal(err)
	}
	h.srv.IdP().Invalidate()
	h.exec(`INSERT INTO users (id, email, name) VALUES ('u-erin','erin@corp.example','Erin')`)
	if end := h.samlLogin(oidctest.NewBrowser(t), "acme-saml", ip, samltest.ResponseOptions{NameID: "s-erin", Attributes: attrs("erin@corp.example")}); end.Status != http.StatusForbidden {
		t.Fatalf("untrusted link: %d", end.Status)
	}
	// Home-realm discovery reaches the SAML provider.
	resp, _ := oidctest.NewBrowser(t).Get(h.app.URL + "/auth/sso/discover?email=carol@corp.example")
	if !strings.HasPrefix(resp.Header.Get("Location"), "/auth/acme-saml?") {
		t.Fatalf("discovery: %s", resp.Header.Get("Location"))
	}
}

// SAML groups feed group sync, keyed by attribute name; the subject can
// come from an attribute (with the NameID still used for logout).
func TestSAMLAttributesAndGroups(t *testing.T) {
	h := newSMHarness(t, smOpts{})
	ip := samltest.New(t)
	h.samlProvider("corp-saml", ip, map[string]any{
		"allow_signup": true, "trust_email": true,
		"claim_map": map[string]string{"subject": "employeeId", "groups": "roles"},
	})
	b := oidctest.NewBrowser(t)
	if end := h.samlLogin(b, "corp-saml", ip, samltest.ResponseOptions{
		NameID: "transient-ish", NameIDFormat: string(saml.TransientNameIDFormat), SessionIndex: "si-x",
		Attributes: map[string][]string{"employeeId": {"E123"}, "mail": {"e123@example.net"}, "roles": {"eng", "ops"}},
	}); end.Status != http.StatusOK {
		t.Fatalf("attribute subject login: %d %s", end.Status, end.Body)
	}
	if h.n(`SELECT COUNT(*) FROM identities WHERE provider='corp-saml' AND subject='E123'`) != 1 {
		t.Fatal("subject attribute not used")
	}
	if h.n(`SELECT COUNT(*) FROM sessions WHERE provider_id='corp-saml' AND idp_subject='transient-ish' AND idp_sid='si-x'`) != 1 {
		t.Fatal("session idp_subject should be the NameID")
	}
	// Missing subject attribute: refused.
	if end := h.samlLogin(oidctest.NewBrowser(t), "corp-saml", ip, samltest.ResponseOptions{
		NameID: "p2", Attributes: map[string][]string{"mail": {"x@example.net"}},
	}); end.Status != http.StatusForbidden {
		t.Fatalf("missing subject attribute: %d", end.Status)
	}
	// NameID opt-in accepts an email-format NameID, which also fills email.
	d, _ := orgDispatcher(h)
	if _, err := call(d, user("u-admin", ""), "", idp.ActionUpdate, map[string]any{
		"id": "corp-saml", "preset": "saml", "metadata_xml": ip.MetadataXML(), "allow_signup": true,
		"claim_map": map[string]string{"subject": idp.SAMLSubjectNameID},
	}); err != nil {
		t.Fatal(err)
	}
	h.srv.IdP().Invalidate()
	if end := h.samlLogin(oidctest.NewBrowser(t), "corp-saml", ip, samltest.ResponseOptions{
		NameID: "frank@example.net", NameIDFormat: string(saml.EmailAddressNameIDFormat),
	}); end.Status != http.StatusOK {
		t.Fatalf("email NameID opt-in: %d %s", end.Status, end.Body)
	}
	if h.n(`SELECT COUNT(*) FROM users WHERE email='frank@example.net'`) != 1 {
		t.Fatal("email-format NameID did not supply the email")
	}
}

// An explicit link through a SAML provider finishes on a same-site GET that
// carries the session cookie (the ACS POST cannot).
func TestSAMLExplicitLink(t *testing.T) {
	h := newSMHarness(t, smOpts{})
	ip := samltest.New(t)
	cert := h.samlProvider("corp-saml", ip, nil)
	b := oidctest.NewBrowser(t)
	_, csrf := h.signedIn(b, "u-bob")
	loc := h.startLink(b, "corp-saml", csrf)
	ar, err := samltest.ParseAuthnRequest(loc, cert)
	if err != nil || !ar.Signed {
		t.Fatalf("link authn request: %v", err)
	}
	resp := ip.Response(auth.SAMLEntityID(h.app.URL, "corp-saml"), samltest.ResponseOptions{
		InResponseTo: ar.Request.ID, ACS: auth.SAMLACSURL(h.app.URL, "corp-saml"), NameID: "bob-link",
	})
	end := h.samlPost(b, "corp-saml", resp, ar.RelayState)
	if end.Status != http.StatusOK || !strings.Contains(end.URL, "notice=linked") {
		t.Fatalf("link: %d %s", end.Status, end.URL)
	}
	if h.n(`SELECT COUNT(*) FROM identities WHERE provider='corp-saml' AND subject='bob-link' AND user_id='u-bob'`) != 1 {
		t.Fatal("not linked")
	}
	// The link cookie alone (no session) links nothing.
	b2 := oidctest.NewBrowser(t)
	_, csrf2 := h.signedIn(b2, "u-alice")
	loc = h.startLink(b2, "corp-saml", csrf2)
	ar, _ = samltest.ParseAuthnRequest(loc, nil)
	b2.DeleteCookie(h.app.URL, auth.CookieName)
	resp = ip.Response(auth.SAMLEntityID(h.app.URL, "corp-saml"), samltest.ResponseOptions{
		InResponseTo: ar.Request.ID, ACS: auth.SAMLACSURL(h.app.URL, "corp-saml"), NameID: "alice-link",
	})
	h.samlPost(b2, "corp-saml", resp, ar.RelayState)
	if h.n(`SELECT COUNT(*) FROM identities WHERE subject='alice-link'`) != 0 {
		t.Fatal("linked without the session")
	}
}

// The ACS and SLO endpoints sit under the /auth/* sign-in rate limit.
func TestSAMLRateLimited(t *testing.T) {
	h := newSMHarness(t, smOpts{defaultRateLimit: true})
	ip := samltest.New(t)
	h.samlProvider("corp-saml", ip, nil)
	limited := false
	for i := 0; i < 30 && !limited; i++ {
		r, err := http.PostForm(auth.SAMLACSURL(h.app.URL, "corp-saml"), url.Values{"SAMLResponse": {"x"}})
		if err != nil {
			t.Fatal(err)
		}
		limited = r.StatusCode == http.StatusTooManyRequests
	}
	if !limited {
		t.Fatal("ACS is not rate limited")
	}
	if r, _ := http.PostForm(auth.SAMLSLOURL(h.app.URL, "corp-saml"), url.Values{"SAMLRequest": {"x"}}); r.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("SLO not rate limited: %d", r.StatusCode)
	}
}

func (h *smHarness) postValues(b *oidctest.Browser, path string, form url.Values) (*http.Response, string) {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, h.app.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := b.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, string(body)
}

// The platform and org provider forms offer the SAML presets, show the SP
// details to register, create through the actions and never show the key.
func TestSAMLAdminPages(t *testing.T) {
	h := newSMHarness(t, smOpts{})
	seedSSOOrgs(t, h)
	if err := grantPlatformOwner(h, "u-admin"); err != nil {
		t.Fatal(err)
	}
	ip := samltest.New(t)
	b := oidctest.NewBrowser(t)
	_, csrf := h.signedIn(b, "u-admin")

	list := h.follow(b, "/admin/identity-providers")
	for _, p := range []string{"new?preset=entra-saml", "new?preset=okta-saml", "new?preset=saml"} {
		if !strings.Contains(list.Body, p) {
			t.Errorf("list lacks %s", p)
		}
	}
	form := h.follow(b, "/admin/identity-providers/new?preset=entra-saml")
	for _, want := range []string{
		auth.SAMLACSURL(h.app.URL, "your-id"), auth.SAMLSLOURL(h.app.URL, "your-id"), auth.SAMLEntityID(h.app.URL, "your-id"),
		`name="metadata_url"`, `name="metadata_xml"`, `name="claim_subject"`, "persistent", `name="idp_logout"`,
	} {
		if !strings.Contains(form.Body, want) {
			t.Errorf("SAML form lacks %q", want)
		}
	}
	if strings.Contains(form.Body, `name="client_secret"`) {
		t.Error("SAML form asks for a client secret")
	}
	resp, body := h.postValues(b, "/admin/identity-providers", url.Values{
		"csrf_token": {csrf}, "preset": {"entra-saml"}, "id": {"entra"}, "metadata_xml": {ip.MetadataXML()},
		"claim_groups": {"roles"}, "trust_email": {"1"}, "idp_logout": {"1"}, "enabled": {"1"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("create via form: %d %s", resp.StatusCode, body)
	}
	if h.n(`SELECT COUNT(*) FROM auth_providers WHERE id='entra' AND kind='saml' AND sp_key_enc <> '' AND claim_map_json='{"groups":"roles"}'`) != 1 {
		t.Fatal("form did not create the SAML provider")
	}
	edit := h.follow(b, "/admin/identity-providers/entra/edit")
	if !strings.Contains(edit.Body, "BEGIN CERTIFICATE") || strings.Contains(edit.Body, "PRIVATE KEY") ||
		!strings.Contains(edit.Body, auth.SAMLACSURL(h.app.URL, "entra")) || !strings.Contains(edit.Body, "/auth/saml/entra/certificate") {
		t.Fatal("edit page: certificate / SP details")
	}
	// Sign-in page lists it like any other provider.
	h.srv.IdP().Invalidate()
	if login := h.follow(oidctest.NewBrowser(t), "/login"); !strings.Contains(login.Body, `href="/auth/entra"`) {
		t.Fatal("/login lacks the SAML provider")
	}
	// Bad metadata re-renders with our message.
	resp, body = h.postValues(b, "/admin/identity-providers", url.Values{
		"csrf_token": {csrf}, "preset": {"saml"}, "id": {"bad"}, "metadata_xml": {"<x/>"},
	})
	if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "metadata") {
		t.Fatalf("bad metadata: %d", resp.StatusCode)
	}

	// Org owner: the SSO page offers SAML presets and the form works.
	ab := oidctest.NewBrowser(t)
	_, acsrf := h.signedIn(ab, "u-alice")
	sso := h.follow(ab, "/app/org/org-acme/settings/sso")
	if !strings.Contains(sso.Body, "preset=saml") {
		t.Fatal("org SSO page lacks SAML")
	}
	of := h.follow(ab, "/app/org/org-acme/settings/sso/providers/new?preset=saml")
	if !strings.Contains(of.Body, auth.SAMLACSURL(h.app.URL, "acme-your-id")) {
		t.Fatal("org SAML form lacks the prefixed ACS URL")
	}
	resp, body = h.postValues(ab, "/app/org/org-acme/settings/sso/providers", url.Values{
		"csrf_token": {acsrf}, "preset": {"saml"}, "id": {"acme-saml"}, "metadata_url": {ip.MetadataURL()}, "enabled": {"1"},
	})
	if resp.StatusCode != http.StatusSeeOther || h.n(`SELECT COUNT(*) FROM auth_providers WHERE id='acme-saml' AND org_id='org-acme' AND kind='saml'`) != 1 {
		t.Fatalf("org create via form: %d %s", resp.StatusCode, body)
	}
}

// An org provider's metadata URL is fetched through the org SSRF guard:
// loopback is refused unless BC_ORG_IDP_ALLOW_PRIVATE (Q11).
func TestSAMLOrgMetadataSSRFGuard(t *testing.T) {
	h := newSMHarness(t, smOpts{blockOrgPrivate: true})
	seedSSOOrgs(t, h)
	ip := samltest.New(t)
	d, _ := orgDispatcher(h)
	if _, err := call(d, user("u-alice", ""), "org-acme", idp.ActionOrgCreate, map[string]any{
		"id": "acme-saml", "preset": "saml", "metadata_url": ip.MetadataURL(),
	}); err != nil {
		t.Fatal(err)
	}
	h.srv.IdP().Invalidate()
	r, err := oidctest.NewBrowser(t).Get(h.app.URL + "/auth/acme-saml")
	if err != nil {
		t.Fatal(err)
	}
	if r.StatusCode != http.StatusBadGateway {
		t.Fatalf("loopback metadata fetched for an org provider: %d", r.StatusCode)
	}
}

// browserPost posts a form with a fresh browser (no cookies, no redirects).
func browserPost(t *testing.T, u string, form url.Values) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, u, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := oidctest.NewBrowser(t).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp
}
