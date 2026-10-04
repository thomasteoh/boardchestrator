// Package samltest is an in-process SAML 2.0 identity provider for tests
// (WU-610). It publishes metadata, signs responses, assertions and logout
// messages with a test key using goxmldsig, and has knobs for the
// misbehaviours the SP must refuse: unsigned or wrongly signed assertions,
// wrong audience/issuer/recipient, stale or future conditions, missing or
// wrong InResponseTo, replay and signature wrapping.
package samltest

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
)

// Signer is a test key pair.
type Signer struct {
	Key  *rsa.PrivateKey
	Cert *x509.Certificate
}

var (
	keyOnce    sync.Once
	mainSigner Signer
	evilSigner Signer
)

func newSigner(cn string) Signer {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return Signer{Key: key, Cert: cert}
}

// signers returns the shared IdP key and a second "attacker" key; every fake
// IdP shares them, like oidctest, so cross-provider tests fail on issuer.
func signers() (Signer, Signer) {
	keyOnce.Do(func() {
		mainSigner, evilSigner = newSigner("samltest idp"), newSigner("samltest evil")
	})
	return mainSigner, evilSigner
}

// IdP is a fake identity provider served over httptest.
type IdP struct {
	t      testing.TB
	Server *httptest.Server
	Signer Signer
	Evil   Signer

	mu sync.Mutex
	// SLORequests records every query string received at /slo.
	SLORequests []url.Values
	sloOff      bool
}

// New starts a fake IdP; it is closed when the test ends.
func New(t testing.TB) *IdP {
	s, e := signers()
	i := &IdP{t: t, Signer: s, Evil: e}
	mux := http.NewServeMux()
	mux.HandleFunc("/metadata", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		_, _ = io.WriteString(w, i.MetadataXML())
	})
	mux.HandleFunc("/slo", func(w http.ResponseWriter, r *http.Request) {
		i.mu.Lock()
		i.SLORequests = append(i.SLORequests, r.URL.Query())
		i.mu.Unlock()
		_, _ = io.WriteString(w, "signed out at the IdP")
	})
	i.Server = httptest.NewServer(mux)
	t.Cleanup(i.Server.Close)
	return i
}

// EntityID is the IdP entity id (its metadata URL).
func (i *IdP) EntityID() string { return i.Server.URL + "/metadata" }

// MetadataURL is where the metadata is served.
func (i *IdP) MetadataURL() string { return i.Server.URL + "/metadata" }

// SSOURL and SLOURL are the IdP's redirect-binding endpoints.
func (i *IdP) SSOURL() string { return i.Server.URL + "/sso" }
func (i *IdP) SLOURL() string { return i.Server.URL + "/slo" }

// SetSLOSupported(false) leaves SingleLogoutService out of the metadata.
func (i *IdP) SetSLOSupported(on bool) {
	i.mu.Lock()
	i.sloOff = !on
	i.mu.Unlock()
}

// MetadataXML is the IdP metadata document.
func (i *IdP) MetadataXML() string {
	i.mu.Lock()
	sloOff := i.sloOff
	i.mu.Unlock()
	cert := base64.StdEncoding.EncodeToString(i.Signer.Cert.Raw)
	slo := ""
	if !sloOff {
		slo = fmt.Sprintf(`<md:SingleLogoutService Binding="%s" Location="%s"/>`, saml.HTTPRedirectBinding, i.SLOURL())
	}
	return fmt.Sprintf(`<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
    %s
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
    <md:SingleSignOnService Binding="%s" Location="%s"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>`, i.EntityID(), cert, slo, saml.HTTPRedirectBinding, i.SSOURL())
}

// AuthnRequest is a decoded SP AuthnRequest.
type AuthnRequest struct {
	Request    saml.AuthnRequest
	RelayState string
	// Signed reports a valid query signature by the SP certificate given to
	// ParseAuthnRequest (false when none was given).
	Signed bool
}

// ParseAuthnRequest decodes the redirect-binding AuthnRequest in loc and,
// when spCert is non-nil, verifies its query signature.
func ParseAuthnRequest(loc string, spCert *x509.Certificate) (*AuthnRequest, error) {
	u, err := url.Parse(loc)
	if err != nil {
		return nil, err
	}
	raw, err := inflateParam(u.Query().Get("SAMLRequest"))
	if err != nil {
		return nil, err
	}
	var out AuthnRequest
	if err := xml.Unmarshal(raw, &out.Request); err != nil {
		return nil, err
	}
	out.RelayState = u.Query().Get("RelayState")
	if spCert != nil {
		out.Signed = VerifyRedirectSignature(u.RawQuery, "SAMLRequest", spCert) == nil
	}
	return &out, nil
}

// ParseLogoutRequest decodes a redirect-binding LogoutRequest URL (the SP's
// SP-initiated logout) and verifies its signature with spCert.
func ParseLogoutRequest(loc string, spCert *x509.Certificate) (*saml.LogoutRequest, string, error) {
	u, err := url.Parse(loc)
	if err != nil {
		return nil, "", err
	}
	if err := VerifyRedirectSignature(u.RawQuery, "SAMLRequest", spCert); err != nil {
		return nil, "", err
	}
	raw, err := inflateParam(u.Query().Get("SAMLRequest"))
	if err != nil {
		return nil, "", err
	}
	var lr saml.LogoutRequest
	if err := xml.Unmarshal(raw, &lr); err != nil {
		return nil, "", err
	}
	return &lr, u.Query().Get("RelayState"), nil
}

// ParseLogoutResponse decodes and verifies a redirect-binding LogoutResponse.
func ParseLogoutResponse(loc string, spCert *x509.Certificate) (*saml.LogoutResponse, error) {
	u, err := url.Parse(loc)
	if err != nil {
		return nil, err
	}
	if err := VerifyRedirectSignature(u.RawQuery, "SAMLResponse", spCert); err != nil {
		return nil, err
	}
	raw, err := inflateParam(u.Query().Get("SAMLResponse"))
	if err != nil {
		return nil, err
	}
	var lr saml.LogoutResponse
	if err := xml.Unmarshal(raw, &lr); err != nil {
		return nil, err
	}
	return &lr, nil
}

func inflateParam(v string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(flate.NewReader(bytes.NewReader(b)))
}

// VerifyRedirectSignature checks an RSA-SHA256 redirect-binding signature.
func VerifyRedirectSignature(rawQuery, param string, cert *x509.Certificate) error {
	vals := map[string]string{}
	for _, kv := range strings.Split(rawQuery, "&") {
		k, v, _ := strings.Cut(kv, "=")
		vals[k] = v
	}
	signed := param + "=" + vals[param]
	if rs, ok := vals["RelayState"]; ok {
		signed += "&RelayState=" + rs
	}
	signed += "&SigAlg=" + vals["SigAlg"]
	alg, _ := url.QueryUnescape(vals["SigAlg"])
	if alg != dsig.RSASHA256SignatureMethod {
		return fmt.Errorf("samltest: SigAlg %q", alg)
	}
	s, _ := url.QueryUnescape(vals["Signature"])
	sig, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(signed))
	return rsa.VerifyPKCS1v15(cert.PublicKey.(*rsa.PublicKey), crypto.SHA256, sum[:], sig)
}

// ResponseOptions builds one SAMLResponse. Zero values are the well-behaved
// defaults; set fields to misbehave.
type ResponseOptions struct {
	// InResponseTo is the AuthnRequest id (on the response and the subject
	// confirmation). OmitInResponseTo sends an unsolicited response.
	InResponseTo     string
	OmitInResponseTo bool
	// ACS is the SP's ACS URL (Destination and Recipient).
	ACS string
	// Audience defaults to the SP entity id; OmitAudience drops the
	// AudienceRestriction.
	Audience     string
	OmitAudience bool
	// Issuer overrides the IdP entity id (wrong issuer).
	Issuer       string
	NameID       string
	NameIDFormat string // default persistent
	SessionIndex string
	// Attributes, by attribute Name.
	Attributes map[string][]string
	// Now shifts the clock the assertion is built around (default now);
	// NotBefore/NotOnOrAfter override the conditions directly.
	Now          time.Time
	NotBefore    time.Time
	NotOnOrAfter time.Time
	AssertionID  string
	// Unsigned sends the assertion without a signature; SignResponse signs
	// the Response too (or instead, with Unsigned).
	Unsigned     bool
	SignResponse bool
	// WrongKey signs with a key the SP does not trust.
	WrongKey bool
	// TamperNameID changes the NameID after signing (breaks the digest).
	TamperNameID string
	// Inject adds a second, unsigned assertion before the real one
	// (signature wrapping).
	Inject *ResponseOptions
}

// Response returns a base64 SAMLResponse for an SP whose entity id is
// spEntityID.
func (i *IdP) Response(spEntityID string, o ResponseOptions) string {
	i.t.Helper()
	now := o.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	signer := i.Signer
	if o.WrongKey {
		signer = i.Evil
	}
	issuer := i.EntityID()
	if o.Issuer != "" {
		issuer = o.Issuer
	}
	resp := saml.Response{
		ID: "resp-" + randHex(), Version: "2.0", IssueInstant: now, Destination: o.ACS,
		Issuer: &saml.Issuer{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity", Value: issuer},
		Status: saml.Status{StatusCode: saml.StatusCode{Value: saml.StatusSuccess}},
	}
	if !o.OmitInResponseTo {
		resp.InResponseTo = o.InResponseTo
	}
	el := resp.Element()
	if o.Inject != nil {
		inj := *o.Inject
		inj.Unsigned = true
		el.AddChild(i.assertion(spEntityID, inj, now, signer))
	}
	el.AddChild(i.assertion(spEntityID, o, now, signer))
	if o.SignResponse {
		signed, err := signingContext(signer).SignEnveloped(el)
		if err != nil {
			i.t.Fatal(err)
		}
		el = signed
	}
	doc := etree.NewDocument()
	doc.SetRoot(el)
	raw, err := doc.WriteToBytes()
	if err != nil {
		i.t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func (i *IdP) assertion(spEntityID string, o ResponseOptions, now time.Time, signer Signer) *etree.Element {
	issuer := i.EntityID()
	if o.Issuer != "" {
		issuer = o.Issuer
	}
	format := o.NameIDFormat
	if format == "" {
		format = string(saml.PersistentNameIDFormat)
	}
	id := o.AssertionID
	if id == "" {
		id = "a-" + randHex()
	}
	nb, na := o.NotBefore, o.NotOnOrAfter
	if nb.IsZero() {
		nb = now.Add(-30 * time.Second)
	}
	if na.IsZero() {
		na = now.Add(5 * time.Minute)
	}
	irt := o.InResponseTo
	if o.OmitInResponseTo {
		irt = ""
	}
	a := saml.Assertion{
		ID: id, IssueInstant: now, Version: "2.0",
		Issuer: saml.Issuer{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity", Value: issuer},
		Subject: &saml.Subject{
			NameID: &saml.NameID{Format: format, Value: o.NameID},
			SubjectConfirmations: []saml.SubjectConfirmation{{
				Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
				SubjectConfirmationData: &saml.SubjectConfirmationData{
					InResponseTo: irt, NotOnOrAfter: na, Recipient: o.ACS,
				},
			}},
		},
		Conditions: &saml.Conditions{NotBefore: nb, NotOnOrAfter: na},
		AuthnStatements: []saml.AuthnStatement{{
			AuthnInstant: now, SessionIndex: o.SessionIndex,
			AuthnContext: saml.AuthnContext{AuthnContextClassRef: &saml.AuthnContextClassRef{
				Value: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
			}},
		}},
	}
	if !o.OmitAudience {
		aud := spEntityID
		if o.Audience != "" {
			aud = o.Audience
		}
		a.Conditions.AudienceRestrictions = []saml.AudienceRestriction{{Audience: saml.Audience{Value: aud}}}
	}
	if len(o.Attributes) > 0 {
		var st saml.AttributeStatement
		for name, vals := range o.Attributes {
			at := saml.Attribute{Name: name, NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"}
			for _, v := range vals {
				at.Values = append(at.Values, saml.AttributeValue{Type: "xs:string", Value: v})
			}
			st.Attributes = append(st.Attributes, at)
		}
		a.AttributeStatements = []saml.AttributeStatement{st}
	}
	if !o.Unsigned {
		signed, err := signingContext(signer).SignEnveloped(a.Element())
		if err != nil {
			i.t.Fatal(err)
		}
		a.Signature = signed.ChildElements()[len(signed.ChildElements())-1]
	}
	el := a.Element()
	if o.TamperNameID != "" {
		if n := el.FindElement(".//NameID"); n != nil {
			n.SetText(o.TamperNameID)
		}
	}
	return el
}

func signingContext(s Signer) *dsig.SigningContext {
	ctx := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore(tls.Certificate{
		Certificate: [][]byte{s.Cert.Raw}, PrivateKey: s.Key, Leaf: s.Cert,
	}))
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	_ = ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod)
	return ctx
}

// LogoutOptions builds an IdP-initiated LogoutRequest.
type LogoutOptions struct {
	// SLO is the SP's SLO URL (Destination).
	SLO            string
	NameID         string
	SessionIndexes []string
	RelayState     string
	ID             string
	Issuer         string
	IssueInstant   time.Time
	// Unsigned omits the signature; WrongKey signs with an untrusted key.
	Unsigned bool
	WrongKey bool
}

func (i *IdP) logoutRequest(o LogoutOptions) *etree.Element {
	id := o.ID
	if id == "" {
		id = "lr-" + randHex()
	}
	issued := o.IssueInstant
	if issued.IsZero() {
		issued = time.Now()
	}
	issuer := i.EntityID()
	if o.Issuer != "" {
		issuer = o.Issuer
	}
	el := etree.NewElement("samlp:LogoutRequest")
	el.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	el.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	el.CreateAttr("ID", id)
	el.CreateAttr("Version", "2.0")
	el.CreateAttr("IssueInstant", issued.UTC().Format(time.RFC3339))
	el.CreateAttr("Destination", o.SLO)
	el.CreateElement("saml:Issuer").SetText(issuer)
	n := el.CreateElement("saml:NameID")
	n.CreateAttr("Format", string(saml.PersistentNameIDFormat))
	n.SetText(o.NameID)
	for _, si := range o.SessionIndexes {
		el.CreateElement("samlp:SessionIndex").SetText(si)
	}
	return el
}

// LogoutRequestURL is an IdP-initiated LogoutRequest by HTTP-Redirect,
// query-signed (RSA-SHA256).
func (i *IdP) LogoutRequestURL(o LogoutOptions) string {
	i.t.Helper()
	signer := i.Signer
	if o.WrongKey {
		signer = i.Evil
	}
	return redirect(i.t, o.SLO, "SAMLRequest", i.logoutRequest(o), o.RelayState, signer, !o.Unsigned)
}

// LogoutRequestPost is an IdP-initiated LogoutRequest for the HTTP-POST
// binding (enveloped signature), as the base64 SAMLRequest form value.
func (i *IdP) LogoutRequestPost(o LogoutOptions) string {
	i.t.Helper()
	el := i.logoutRequest(o)
	if !o.Unsigned {
		signer := i.Signer
		if o.WrongKey {
			signer = i.Evil
		}
		signed, err := signingContext(signer).SignEnveloped(el)
		if err != nil {
			i.t.Fatal(err)
		}
		el = signed
	}
	doc := etree.NewDocument()
	doc.SetRoot(el)
	raw, _ := doc.WriteToBytes()
	return base64.StdEncoding.EncodeToString(raw)
}

// LogoutResponseURL answers an SP-initiated LogoutRequest by HTTP-Redirect.
func (i *IdP) LogoutResponseURL(slo, inResponseTo, relayState string, unsigned bool) string {
	i.t.Helper()
	el := etree.NewElement("samlp:LogoutResponse")
	el.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	el.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	el.CreateAttr("ID", "lresp-"+randHex())
	el.CreateAttr("InResponseTo", inResponseTo)
	el.CreateAttr("Version", "2.0")
	el.CreateAttr("IssueInstant", time.Now().UTC().Format(time.RFC3339))
	el.CreateAttr("Destination", slo)
	el.CreateElement("saml:Issuer").SetText(i.EntityID())
	el.CreateElement("samlp:Status").CreateElement("samlp:StatusCode").CreateAttr("Value", saml.StatusSuccess)
	return redirect(i.t, slo, "SAMLResponse", el, relayState, i.Signer, !unsigned)
}

func redirect(t testing.TB, dest, param string, el *etree.Element, relay string, s Signer, sign bool) string {
	doc := etree.NewDocument()
	doc.SetRoot(el)
	raw, err := doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	fw, _ := flate.NewWriter(&buf, flate.BestCompression)
	_, _ = fw.Write(raw)
	_ = fw.Close()
	q := param + "=" + url.QueryEscape(base64.StdEncoding.EncodeToString(buf.Bytes()))
	if relay != "" {
		q += "&RelayState=" + url.QueryEscape(relay)
	}
	if sign {
		q += "&SigAlg=" + url.QueryEscape(dsig.RSASHA256SignatureMethod)
		sum := sha256.Sum256([]byte(q))
		sig, err := rsa.SignPKCS1v15(rand.Reader, s.Key, crypto.SHA256, sum[:])
		if err != nil {
			t.Fatal(err)
		}
		q += "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
	}
	return dest + "?" + q
}

func randHex() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}
