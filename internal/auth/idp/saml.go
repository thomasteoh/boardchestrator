package idp

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	xrv "github.com/mattermost/xml-roundtrip-validator"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/tenant"
)

// SAML 2.0 service provider (SPEC §7.7) on crewjam/saml's SP primitives
// (ServiceProvider.MakeAuthenticationRequest / ParseXMLResponse / Metadata),
// not its samlsp middleware. Only the HTTP-Redirect binding is used to send
// and only HTTP-POST to receive responses; artifact resolution is never
// performed (it would make the server fetch an IdP-chosen URL).

// SAML timing (SPEC §7.7): conditions are checked with a 2 minute skew, on
// top of crewjam's own (looser) checks.
const (
	SAMLClockSkew = 2 * time.Minute
	// samlMetadataTTL is how long fetched IdP metadata is cached.
	samlMetadataTTL = time.Hour
	// maxSAMLXML bounds a decoded SAML message or metadata document.
	maxSAMLXML = 1 << 20
	// spCertValidity is the lifetime of a generated SP certificate.
	spCertValidity = 10 * 365 * 24 * time.Hour
)

// Default SAML attribute names (SPEC §7.7). Each field tries its names in
// order; an override in claim_map_json replaces the list with one name.
var (
	samlEmailAttrs = []string{
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "mail", "email",
	}
	samlNameAttrs = []string{
		"displayName", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
		"http://schemas.microsoft.com/identity/claims/displayname",
	}
	samlGivenAttrs   = []string{"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname", "givenName"}
	samlSurnameAttrs = []string{"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname", "sn", "surname"}
	samlGroupsAttrs  = []string{
		"http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
		// authentik and ADFS (WU-614, found against a real authentik).
		"http://schemas.xmlsoap.org/claims/Group",
		"groups", "memberOf",
	}
)

// SAMLSubjectNameID, as the subject override, accepts the NameID whatever
// its format (except transient), e.g. an email-format NameID. The UI warns
// that such identifiers can be reassigned.
const SAMLSubjectNameID = "NameID"

// SAMLAttrs is the parsed SAML attribute map: claim_map_json keys subject,
// email, name and groups, each one attribute name.
type SAMLAttrs struct {
	Subject string `json:"subject,omitempty"`
	Email   string `json:"email,omitempty"`
	Name    string `json:"name,omitempty"`
	Groups  string `json:"groups,omitempty"`
}

// ParseSAMLAttrs reads a SAML provider's claim_map_json; unknown keys are an
// error so a typo is not silently ignored.
func ParseSAMLAttrs(raw string) (SAMLAttrs, error) {
	var a SAMLAttrs
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "{}" {
		return a, nil
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return a, fmt.Errorf("attribute map: %w", err)
	}
	for k, v := range m {
		switch k {
		case "subject":
			a.Subject = v
		case "email":
			a.Email = v
		case "name":
			a.Name = v
		case "groups":
			a.Groups = v
		default:
			return a, fmt.Errorf("attribute map: unknown field %q (use subject, email, name or groups)", k)
		}
	}
	return a, nil
}

// SAMLConfig configures a SAML connector.
type SAMLConfig struct {
	ID      string
	BaseURL string
	// Exactly one of MetadataURL and MetadataXML describes the IdP.
	MetadataURL string
	MetadataXML string
	// KeyPEM (PKCS#8) and CertPEM are the provider's SP key pair.
	KeyPEM, CertPEM string
	Attrs           SAMLAttrs
	Policy          auth.ResolvePolicy
	// IdPLogout: sign-out continues to the IdP's SLO endpoint.
	IdPLogout bool
	// Client fetches MetadataURL (the platform or org IdP client).
	Client *http.Client
	// Replay remembers assertion ids; shared by every SAML connector of a
	// registry so rebuilding a connector does not reopen the window.
	Replay *auth.ReplayCache
	// Now overrides the clock for this connector's own checks; test-only.
	Now func() time.Time
}

// SAMLConnector signs users in with SAML 2.0 Web Browser SSO, SP-initiated
// only.
type SAMLConnector struct {
	cfg  SAMLConfig
	key  *rsa.PrivateKey
	cert *x509.Certificate

	mu        sync.Mutex
	md        *saml.EntityDescriptor
	fetchedAt time.Time
}

var _ auth.SAMLConnector = (*SAMLConnector)(nil)
var _ auth.RPLogoutConnector = (*SAMLConnector)(nil)

// NewSAMLConnector parses the key pair and, for pasted XML, the IdP
// metadata; a metadata URL is fetched on first use.
func NewSAMLConnector(cfg SAMLConfig) (*SAMLConnector, error) {
	key, cert, err := ParseSPKeyPair(cfg.KeyPEM, cfg.CertPEM)
	if err != nil {
		return nil, err
	}
	if cfg.Client == nil {
		cfg.Client = NewIdPClient(nil)
	}
	if cfg.Replay == nil {
		cfg.Replay = auth.NewReplayCache(0)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	c := &SAMLConnector{cfg: cfg, key: key, cert: cert}
	switch {
	case cfg.MetadataXML != "":
		md, err := ParseIdPMetadata([]byte(cfg.MetadataXML))
		if err != nil {
			return nil, err
		}
		c.md = md
	case cfg.MetadataURL != "":
		if err := ValidateMetadataURL(cfg.MetadataURL); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("SAML provider has no IdP metadata")
	}
	return c, nil
}

func (c *SAMLConnector) ID() string                 { return c.cfg.ID }
func (c *SAMLConnector) AuthMethod() string         { return auth.AuthMethodSAML }
func (c *SAMLConnector) Policy() auth.ResolvePolicy { return c.cfg.Policy }

func (c *SAMLConnector) entityID() string { return auth.SAMLEntityID(c.cfg.BaseURL, c.cfg.ID) }
func (c *SAMLConnector) acsURL() string   { return auth.SAMLACSURL(c.cfg.BaseURL, c.cfg.ID) }
func (c *SAMLConnector) sloURL() string   { return auth.SAMLSLOURL(c.cfg.BaseURL, c.cfg.ID) }

// idpMetadata returns the IdP metadata, fetching and caching a URL for
// samlMetadataTTL.
func (c *SAMLConnector) idpMetadata(ctx context.Context) (*saml.EntityDescriptor, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.md != nil && (c.cfg.MetadataXML != "" || time.Since(c.fetchedAt) < samlMetadataTTL) {
		return c.md, nil
	}
	md, err := FetchIdPMetadata(ctx, c.cfg.Client, c.cfg.MetadataURL)
	if err != nil {
		return nil, fmt.Errorf("saml %s: %w", c.cfg.ID, err)
	}
	c.md, c.fetchedAt = md, time.Now()
	return md, nil
}

// serviceProvider is the crewjam SP for this provider; md may be nil (SP
// metadata needs none).
func (c *SAMLConnector) serviceProvider(md *saml.EntityDescriptor) *saml.ServiceProvider {
	mustURL := func(s string) url.URL {
		u, _ := url.Parse(s)
		return *u
	}
	return &saml.ServiceProvider{
		EntityID:          c.entityID(),
		Key:               c.key,
		Certificate:       c.cert,
		MetadataURL:       mustURL(c.entityID()),
		AcsURL:            mustURL(c.acsURL()),
		SloURL:            mustURL(c.sloURL()),
		IDPMetadata:       md,
		AuthnNameIDFormat: saml.UnspecifiedNameIDFormat,
		SignatureMethod:   dsig.RSASHA256SignatureMethod,
		LogoutBindings:    []string{saml.HTTPRedirectBinding, saml.HTTPPostBinding},
		AllowIDPInitiated: false,
		// Never used: artifact resolution is not offered or performed.
		HTTPClient: &http.Client{Transport: refuseTransport{}},
	}
}

type refuseTransport struct{}

func (refuseTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("saml: outbound requests are not allowed here")
}

// SPMetadata implements auth.SAMLConnector: entity id, ACS (HTTP-POST only),
// SLO (Redirect and POST), signing/encryption certificate, persistent NameID.
func (c *SAMLConnector) SPMetadata() ([]byte, error) {
	md := c.serviceProvider(nil).Metadata()
	for i := range md.SPSSODescriptors {
		d := &md.SPSSODescriptors[i]
		var acs []saml.IndexedEndpoint
		for _, e := range d.AssertionConsumerServices {
			if e.Binding == saml.HTTPPostBinding {
				acs = append(acs, e)
			}
		}
		d.AssertionConsumerServices = acs
		d.NameIDFormats = []saml.NameIDFormat{saml.PersistentNameIDFormat}
	}
	b, err := xml.MarshalIndent(md, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("saml %s: metadata: %w", c.cfg.ID, err)
	}
	return append([]byte(xml.Header), b...), nil
}

// SPCertificatePEM implements auth.SAMLConnector.
func (c *SAMLConnector) SPCertificatePEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw})
}

// Begin sends a signed AuthnRequest with the HTTP-Redirect binding, asking
// for the response by HTTP-POST at the ACS. Its id goes into the flow, and
// the flow state is the RelayState.
func (c *SAMLConnector) Begin(ctx context.Context, flow *auth.Flow) (string, error) {
	md, err := c.idpMetadata(ctx)
	if err != nil {
		return "", err
	}
	sp := c.serviceProvider(md)
	dest := sp.GetSSOBindingLocation(saml.HTTPRedirectBinding)
	if dest == "" {
		return "", fmt.Errorf("saml %s: IdP metadata has no HTTP-Redirect single sign-on service", c.cfg.ID)
	}
	req, err := sp.MakeAuthenticationRequest(dest, saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		return "", fmt.Errorf("saml %s: authn request: %w", c.cfg.ID, err)
	}
	u, err := req.Redirect(flow.State, sp)
	if err != nil {
		return "", fmt.Errorf("saml %s: authn request: %w", c.cfg.ID, err)
	}
	flow.SAMLRequestID = req.ID
	return u.String(), nil
}

// logoutHint is what SP-initiated logout needs about a SAML session; it is
// sealed into sessions.id_token_enc (via Assertion.IDTokenRaw).
type logoutHint struct {
	NameID          string `json:"n"`
	Format          string `json:"f,omitempty"`
	NameQualifier   string `json:"nq,omitempty"`
	SPNameQualifier string `json:"spnq,omitempty"`
	SessionIndex    string `json:"si,omitempty"`
}

// Complete verifies the SAMLResponse posted to the ACS (SPEC §7.7): one
// assertion only; signed response or signed assertion (crewjam, goxmldsig
// >= 1.6.1); InResponseTo = the flow's request id, so unsolicited responses
// fail; Destination and Recipient = the ACS; issuer = the IdP entity id;
// every AudienceRestriction names our entity id; NotBefore/NotOnOrAfter
// within SAMLClockSkew; assertion id not seen before.
func (c *SAMLConnector) Complete(ctx context.Context, r *http.Request, flow *auth.Flow) (*auth.Assertion, error) {
	if flow.SAMLRequestID == "" {
		return nil, errors.New("saml: flow has no request id")
	}
	raw, err := base64.StdEncoding.DecodeString(r.PostForm.Get("SAMLResponse"))
	if err != nil || len(raw) == 0 {
		return nil, errors.New("saml: SAMLResponse missing or not base64")
	}
	if len(raw) > maxSAMLXML {
		return nil, errors.New("saml: SAMLResponse too large")
	}
	if err := singleAssertion(raw); err != nil {
		return nil, err
	}
	md, err := c.idpMetadata(ctx)
	if err != nil {
		return nil, err
	}
	sp := c.serviceProvider(md)
	sp.ValidateAudienceRestriction = c.validateAudience
	as, err := parseResponse(sp, raw, flow.SAMLRequestID, c.acsURL())
	if err != nil {
		return nil, err
	}
	now := c.cfg.Now()
	if err := c.checkTimes(as, now); err != nil {
		return nil, err
	}
	if as.Subject == nil || as.Subject.NameID == nil || strings.TrimSpace(as.Subject.NameID.Value) == "" {
		return nil, errors.New("saml: assertion has no NameID")
	}
	if as.ID == "" {
		return nil, errors.New("saml: assertion has no ID")
	}
	if !c.cfg.Replay.Use("saml\x00"+c.cfg.ID+"\x00"+as.ID, replayHorizon(as)) {
		return nil, errors.New("saml: assertion replayed")
	}
	return c.toAssertion(as)
}

// singleAssertion refuses a response carrying more than one assertion. A
// legitimate IdP sends one; extra (unsigned) assertions are how signature
// wrapping attacks smuggle in a second identity.
func singleAssertion(raw []byte) error {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil || doc.Root() == nil {
		return errors.New("saml: response is not XML")
	}
	n := 0
	for _, el := range doc.Root().ChildElements() {
		if el.NamespaceURI() == "urn:oasis:names:tc:SAML:2.0:assertion" && (el.Tag == "Assertion" || el.Tag == "EncryptedAssertion") {
			n++
		}
	}
	if n != 1 {
		return fmt.Errorf("saml: response carries %d assertions, want exactly 1", n)
	}
	return nil
}

// parseResponse runs crewjam's verification, turning its static error text
// into the detailed (logged, never shown) reason and a panic on a malformed
// assertion (crewjam dereferences Conditions) into an error.
func parseResponse(sp *saml.ServiceProvider, raw []byte, requestID, acs string) (as *saml.Assertion, err error) {
	defer func() {
		if p := recover(); p != nil {
			as, err = nil, fmt.Errorf("saml: malformed assertion: %v", p)
		}
	}()
	u, _ := url.Parse(acs)
	as, err = sp.ParseXMLResponse(raw, []string{requestID}, *u)
	if err != nil {
		var ire *saml.InvalidResponseError
		if errors.As(err, &ire) {
			return nil, fmt.Errorf("saml: invalid response: %v", ire.PrivateErr)
		}
		return nil, fmt.Errorf("saml: invalid response: %w", err)
	}
	return as, nil
}

// validateAudience requires at least one AudienceRestriction and that every
// one of them names this SP (restrictions are conjunctive, SAML core §2.5.1.4).
func (c *SAMLConnector) validateAudience(as *saml.Assertion) error {
	if as.Conditions == nil || len(as.Conditions.AudienceRestrictions) == 0 {
		return errors.New("assertion has no audience restriction")
	}
	for _, ar := range as.Conditions.AudienceRestrictions {
		if ar.Audience.Value != c.entityID() {
			return fmt.Errorf("audience %q is not %q", ar.Audience.Value, c.entityID())
		}
	}
	return nil
}

func (c *SAMLConnector) checkTimes(as *saml.Assertion, now time.Time) error {
	if as.Conditions == nil {
		return errors.New("saml: assertion has no conditions")
	}
	if nb := as.Conditions.NotBefore; !nb.IsZero() && now.Add(SAMLClockSkew).Before(nb) {
		return errors.New("saml: assertion not yet valid")
	}
	if na := as.Conditions.NotOnOrAfter; na.IsZero() || !now.Add(-SAMLClockSkew).Before(na) {
		return errors.New("saml: assertion expired")
	}
	if as.Subject != nil {
		for _, sc := range as.Subject.SubjectConfirmations {
			if d := sc.SubjectConfirmationData; d != nil && !d.NotOnOrAfter.IsZero() && !now.Add(-SAMLClockSkew).Before(d.NotOnOrAfter) {
				return errors.New("saml: subject confirmation expired")
			}
		}
	}
	return nil
}

// replayHorizon is the last moment the assertion could still be accepted.
func replayHorizon(as *saml.Assertion) time.Time {
	t := as.IssueInstant.Add(saml.MaxIssueDelay)
	if as.Conditions != nil && as.Conditions.NotOnOrAfter.After(t) {
		t = as.Conditions.NotOnOrAfter
	}
	if as.Subject != nil {
		for _, sc := range as.Subject.SubjectConfirmations {
			if d := sc.SubjectConfirmationData; d != nil && d.NotOnOrAfter.After(t) {
				t = d.NotOnOrAfter
			}
		}
	}
	return t.Add(saml.MaxClockSkew)
}

// toAssertion maps a verified SAML assertion onto auth.Assertion.
func (c *SAMLConnector) toAssertion(as *saml.Assertion) (*auth.Assertion, error) {
	attrs := map[string]any{}
	for _, st := range as.AttributeStatements {
		for _, at := range st.Attributes {
			vals := make([]any, 0, len(at.Values))
			for _, v := range at.Values {
				if s := strings.TrimSpace(v.Value); s != "" {
					vals = append(vals, s)
				}
			}
			if at.Name != "" {
				attrs[at.Name] = vals
			}
			if at.FriendlyName != "" {
				if _, taken := attrs[at.FriendlyName]; !taken {
					attrs[at.FriendlyName] = vals
				}
			}
		}
	}
	first := func(names ...string) string {
		for _, n := range names {
			if vs, ok := attrs[n].([]any); ok && len(vs) > 0 {
				return vs[0].(string)
			}
		}
		return ""
	}
	nid := as.Subject.NameID
	nameID := strings.TrimSpace(nid.Value)
	format := saml.NameIDFormat(nid.Format)

	var subject string
	switch c.cfg.Attrs.Subject {
	case "":
		if format != saml.PersistentNameIDFormat {
			return nil, fmt.Errorf("saml: NameID format %q is not persistent; configure a persistent NameID or a subject attribute", nid.Format)
		}
		subject = nameID
	case SAMLSubjectNameID:
		if format == saml.TransientNameIDFormat {
			return nil, errors.New("saml: a transient NameID cannot identify a user")
		}
		subject = nameID
	default:
		subject = first(c.cfg.Attrs.Subject)
		if subject == "" {
			return nil, fmt.Errorf("saml: subject attribute %q missing", c.cfg.Attrs.Subject)
		}
	}

	emailNames := samlEmailAttrs
	if c.cfg.Attrs.Email != "" {
		emailNames = []string{c.cfg.Attrs.Email}
	}
	email := first(emailNames...)
	if email == "" && c.cfg.Attrs.Email == "" && format == saml.EmailAddressNameIDFormat {
		email = nameID
	}
	nameNames := samlNameAttrs
	if c.cfg.Attrs.Name != "" {
		nameNames = []string{c.cfg.Attrs.Name}
	}
	name := first(nameNames...)
	if name == "" && c.cfg.Attrs.Name == "" {
		name = strings.TrimSpace(first(samlGivenAttrs...) + " " + first(samlSurnameAttrs...))
	}
	groupsPath := ""
	if c.cfg.Attrs.Groups != "" {
		groupsPath = c.cfg.Attrs.Groups
	} else {
		groupsPath = samlGroupsAttrs[0]
		for _, g := range samlGroupsAttrs {
			if _, ok := attrs[g]; ok {
				groupsPath = g
				break
			}
		}
	}
	sid := ""
	if len(as.AuthnStatements) > 0 {
		sid = as.AuthnStatements[0].SessionIndex
	}
	hint, err := json.Marshal(logoutHint{
		NameID: nameID, Format: nid.Format, NameQualifier: nid.NameQualifier,
		SPNameQualifier: nid.SPNameQualifier, SessionIndex: sid,
	})
	if err != nil {
		return nil, fmt.Errorf("saml: logout hint: %w", err)
	}
	return &auth.Assertion{
		ProviderID: c.cfg.ID,
		Subject:    subject,
		IdPSubject: nameID,
		Email:      email,
		// SAML carries no email-verified flag: a provider's emails count as
		// verified only when the admin trusts it (trust_email), and then the
		// usual §7.3 rules (org providers: verified domains only) apply.
		EmailVerified: email != "" && c.cfg.Policy.TrustEmail,
		Name:          name,
		Groups:        auth.ClaimGroups(attrs, groupsPath),
		GroupsClaim:   groupsPath,
		SID:           sid,
		IDTokenRaw:    string(hint),
		RawClaims:     attrs,
	}, nil
}

// EndSessionURL implements auth.RPLogoutConnector for SAML: a LogoutRequest
// naming the session's NameID and SessionIndex, signed for the HTTP-Redirect
// binding, to the IdP's redirect SLO endpoint. "" when IdP sign-out is off
// or the IdP publishes no such endpoint. req.IDTokenHint is the sealed
// logoutHint.
func (c *SAMLConnector) EndSessionURL(ctx context.Context, req auth.EndSessionRequest) (string, error) {
	if !c.cfg.IdPLogout {
		return "", nil
	}
	var h logoutHint
	if err := json.Unmarshal([]byte(req.IDTokenHint), &h); err != nil || h.NameID == "" {
		return "", errors.New("saml: no logout hint for this session")
	}
	md, err := c.idpMetadata(ctx)
	if err != nil {
		return "", err
	}
	dest := sloLocation(md, false)
	if dest == "" {
		return "", nil
	}
	lr := saml.LogoutRequest{
		ID: "id-" + randHex(20), Version: "2.0", IssueInstant: c.cfg.Now().UTC(), Destination: dest,
		Issuer: &saml.Issuer{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity", Value: c.entityID()},
		NameID: &saml.NameID{
			Format: h.Format, Value: h.NameID, NameQualifier: h.NameQualifier, SPNameQualifier: h.SPNameQualifier,
		},
	}
	if h.SessionIndex != "" {
		lr.SessionIndex = &saml.SessionIndex{Value: h.SessionIndex}
	}
	return c.redirectSigned(dest, "SAMLRequest", lr.Element(), req.State)
}

// LogoutResponseURL implements auth.SAMLConnector.
func (c *SAMLConnector) LogoutResponseURL(ctx context.Context, msg *auth.SAMLLogoutMessage) (string, error) {
	md, err := c.idpMetadata(ctx)
	if err != nil {
		return "", err
	}
	dest := sloLocation(md, true)
	if dest == "" {
		return "", errors.New("saml: IdP metadata has no HTTP-Redirect single logout service")
	}
	resp := saml.LogoutResponse{
		ID: "id-" + randHex(20), InResponseTo: msg.ID, Version: "2.0", IssueInstant: c.cfg.Now().UTC(),
		Destination: dest,
		Issuer:      &saml.Issuer{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity", Value: c.entityID()},
		Status:      saml.Status{StatusCode: saml.StatusCode{Value: saml.StatusSuccess}},
	}
	return c.redirectSigned(dest, "SAMLResponse", resp.Element(), msg.RelayState)
}

// sloLocation is the IdP's HTTP-Redirect SLO endpoint (its ResponseLocation
// when response is set and one is published).
func sloLocation(md *saml.EntityDescriptor, response bool) string {
	for _, d := range md.IDPSSODescriptors {
		for _, e := range d.SingleLogoutServices {
			if e.Binding != saml.HTTPRedirectBinding {
				continue
			}
			if response && e.ResponseLocation != "" {
				return e.ResponseLocation
			}
			return e.Location
		}
	}
	return ""
}

// redirectSigned encodes el for the HTTP-Redirect binding (DEFLATE, base64)
// and signs the query (SAML bindings §3.4.4.1, RSA-SHA256).
func (c *SAMLConnector) redirectSigned(dest, param string, el *etree.Element, relayState string) (string, error) {
	doc := etree.NewDocument()
	doc.SetRoot(el)
	raw, err := doc.WriteToBytes()
	if err != nil {
		return "", fmt.Errorf("saml: encode: %w", err)
	}
	var buf bytes.Buffer
	fw, _ := flate.NewWriter(&buf, flate.BestCompression)
	if _, err := fw.Write(raw); err != nil {
		return "", fmt.Errorf("saml: deflate: %w", err)
	}
	if err := fw.Close(); err != nil {
		return "", fmt.Errorf("saml: deflate: %w", err)
	}
	q := param + "=" + url.QueryEscape(base64.StdEncoding.EncodeToString(buf.Bytes()))
	if relayState != "" {
		q += "&RelayState=" + url.QueryEscape(relayState)
	}
	q += "&SigAlg=" + url.QueryEscape(dsig.RSASHA256SignatureMethod)
	sum := sha256.Sum256([]byte(q))
	sig, err := rsa.SignPKCS1v15(rand.Reader, c.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("saml: sign: %w", err)
	}
	q += "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
	sep := "?"
	if strings.Contains(dest, "?") {
		sep = "&"
	}
	return dest + sep + q, nil
}

// ParseSLO implements auth.SAMLConnector: a LogoutRequest or LogoutResponse
// by HTTP-Redirect (query signature) or HTTP-POST (enveloped signature).
// Unsigned messages are refused.
func (c *SAMLConnector) ParseSLO(ctx context.Context, r *http.Request) (*auth.SAMLLogoutMessage, error) {
	md, err := c.idpMetadata(ctx)
	if err != nil {
		return nil, err
	}
	certs, err := idpSigningCerts(md)
	if err != nil {
		return nil, err
	}
	param := "SAMLRequest"
	if r.Form.Get("SAMLResponse") != "" {
		param = "SAMLResponse"
	}
	var root *etree.Element
	if r.Method == http.MethodGet {
		raw, err := c.verifyRedirect(r.URL.RawQuery, param, certs)
		if err != nil {
			return nil, err
		}
		if root, err = parseXMLRoot(raw); err != nil {
			return nil, err
		}
	} else {
		raw, err := base64.StdEncoding.DecodeString(r.PostForm.Get(param))
		if err != nil || len(raw) == 0 || len(raw) > maxSAMLXML {
			return nil, errors.New("saml: message missing or not base64")
		}
		el, err := parseXMLRoot(raw)
		if err != nil {
			return nil, err
		}
		if root, err = verifyEnveloped(el, certs); err != nil {
			return nil, err
		}
	}
	return c.checkLogoutMessage(root, param == "SAMLResponse", md.EntityID, r.Form.Get("RelayState"))
}

func parseXMLRoot(raw []byte) (*etree.Element, error) {
	if err := xrv.Validate(bytes.NewReader(raw)); err != nil {
		return nil, fmt.Errorf("saml: invalid xml: %w", err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil || doc.Root() == nil {
		return nil, errors.New("saml: message is not XML")
	}
	return doc.Root(), nil
}

// verifyEnveloped validates an enveloped XML signature on el and returns the
// element exactly as signed.
func verifyEnveloped(el *etree.Element, certs []*x509.Certificate) (*etree.Element, error) {
	if el.FindElement("./Signature") == nil {
		return nil, errors.New("saml: message is not signed")
	}
	vc := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: certs})
	vc.IdAttribute = "ID"
	out, err := vc.Validate(el)
	if err != nil {
		return nil, fmt.Errorf("saml: signature: %w", err)
	}
	return out, nil
}

// verifyRedirect checks an HTTP-Redirect binding query signature over the
// raw (as received) parameter values and returns the inflated message.
func (c *SAMLConnector) verifyRedirect(rawQuery, param string, certs []*x509.Certificate) ([]byte, error) {
	vals := map[string]string{}
	for _, kv := range strings.Split(rawQuery, "&") {
		k, v, _ := strings.Cut(kv, "=")
		if _, dup := vals[k]; dup {
			return nil, fmt.Errorf("saml: duplicate %s parameter", k)
		}
		vals[k] = v
	}
	msg, ok := vals[param]
	if !ok || msg == "" {
		return nil, errors.New("saml: message missing")
	}
	sigAlgRaw, sigRaw := vals["SigAlg"], vals["Signature"]
	if sigAlgRaw == "" || sigRaw == "" {
		return nil, errors.New("saml: message is not signed")
	}
	signed := param + "=" + msg
	if rs, ok := vals["RelayState"]; ok {
		signed += "&RelayState=" + rs
	}
	signed += "&SigAlg=" + sigAlgRaw
	sigAlg, err1 := url.QueryUnescape(sigAlgRaw)
	sigB64, err2 := url.QueryUnescape(sigRaw)
	sig, err3 := base64.StdEncoding.DecodeString(sigB64)
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, errors.New("saml: malformed signature")
	}
	var h hash.Hash
	var ch crypto.Hash
	switch sigAlg {
	case dsig.RSASHA256SignatureMethod:
		h, ch = sha256.New(), crypto.SHA256
	case dsig.RSASHA384SignatureMethod:
		h, ch = sha512.New384(), crypto.SHA384
	case dsig.RSASHA512SignatureMethod:
		h, ch = sha512.New(), crypto.SHA512
	default:
		return nil, fmt.Errorf("saml: signature algorithm %q not accepted", sigAlg)
	}
	h.Write([]byte(signed))
	digest := h.Sum(nil)
	verified := false
	now := c.cfg.Now()
	for _, cert := range certs {
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok || now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			continue
		}
		if rsa.VerifyPKCS1v15(pub, ch, digest, sig) == nil {
			verified = true
			break
		}
	}
	if !verified {
		return nil, errors.New("saml: signature does not verify")
	}
	m, err := url.QueryUnescape(msg)
	if err != nil {
		return nil, errors.New("saml: malformed message")
	}
	deflated, err := base64.StdEncoding.DecodeString(m)
	if err != nil {
		return nil, errors.New("saml: message not base64")
	}
	out, err := io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(deflated)), maxSAMLXML+1))
	if err != nil || len(out) > maxSAMLXML {
		return nil, errors.New("saml: message does not inflate")
	}
	return out, nil
}

const (
	samlProtocolNS  = "urn:oasis:names:tc:SAML:2.0:protocol"
	samlAssertionNS = "urn:oasis:names:tc:SAML:2.0:assertion"
)

// checkLogoutMessage checks a verified LogoutRequest/LogoutResponse: issuer,
// destination (our SLO URL), IssueInstant and NotOnOrAfter.
func (c *SAMLConnector) checkLogoutMessage(root *etree.Element, response bool, idpEntity, relayState string) (*auth.SAMLLogoutMessage, error) {
	want := "LogoutRequest"
	if response {
		want = "LogoutResponse"
	}
	if root.Tag != want || root.NamespaceURI() != samlProtocolNS {
		return nil, fmt.Errorf("saml: expected %s, got %s", want, root.Tag)
	}
	child := func(el *etree.Element, ns, tag string) []*etree.Element {
		var out []*etree.Element
		for _, e := range el.ChildElements() {
			if e.Tag == tag && e.NamespaceURI() == ns {
				out = append(out, e)
			}
		}
		return out
	}
	iss := child(root, samlAssertionNS, "Issuer")
	if len(iss) != 1 || strings.TrimSpace(iss[0].Text()) != idpEntity {
		return nil, errors.New("saml: wrong issuer")
	}
	dest := root.SelectAttrValue("Destination", "")
	if dest != c.sloURL() && (!response || dest != "") {
		return nil, fmt.Errorf("saml: destination %q is not %q", dest, c.sloURL())
	}
	now := c.cfg.Now()
	issued, err := time.Parse(time.RFC3339, root.SelectAttrValue("IssueInstant", ""))
	if err != nil {
		return nil, errors.New("saml: bad IssueInstant")
	}
	if issued.After(now.Add(SAMLClockSkew)) || issued.Add(saml.MaxIssueDelay+SAMLClockSkew).Before(now) {
		return nil, errors.New("saml: message is stale or from the future")
	}
	msg := &auth.SAMLLogoutMessage{
		Response: response, ID: root.SelectAttrValue("ID", ""), RelayState: relayState,
		Expires: issued.Add(saml.MaxIssueDelay + 2*SAMLClockSkew),
	}
	if response {
		st := child(root, samlProtocolNS, "Status")
		if len(st) != 1 {
			return nil, errors.New("saml: no status")
		}
		code := child(st[0], samlProtocolNS, "StatusCode")
		if len(code) != 1 || code[0].SelectAttrValue("Value", "") != saml.StatusSuccess {
			return nil, errors.New("saml: logout did not succeed at the IdP")
		}
		return msg, nil
	}
	if na := root.SelectAttrValue("NotOnOrAfter", ""); na != "" {
		t, err := time.Parse(time.RFC3339, na)
		if err != nil || !now.Add(-SAMLClockSkew).Before(t) {
			return nil, errors.New("saml: logout request expired")
		}
	}
	nids := child(root, samlAssertionNS, "NameID")
	if len(nids) != 1 || strings.TrimSpace(nids[0].Text()) == "" {
		return nil, errors.New("saml: logout request needs exactly one NameID")
	}
	msg.NameID = strings.TrimSpace(nids[0].Text())
	for _, si := range child(root, samlProtocolNS, "SessionIndex") {
		if v := strings.TrimSpace(si.Text()); v != "" {
			msg.SessionIndexes = append(msg.SessionIndexes, v)
		}
	}
	if msg.ID == "" {
		return nil, errors.New("saml: logout request has no ID")
	}
	return msg, nil
}

// idpSigningCerts are the IdP's signing certificates from its metadata.
func idpSigningCerts(md *saml.EntityDescriptor) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for _, d := range md.IDPSSODescriptors {
		for _, kd := range d.KeyDescriptors {
			if kd.Use != "" && kd.Use != "signing" {
				continue
			}
			for _, xc := range kd.KeyInfo.X509Data.X509Certificates {
				b, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(xc.Data), ""))
				if err != nil {
					continue
				}
				if cert, err := x509.ParseCertificate(b); err == nil {
					out = append(out, cert)
				}
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("saml: IdP metadata has no signing certificate")
	}
	return out, nil
}

// ParseIdPMetadata parses IdP metadata (an EntityDescriptor, or the first
// EntityDescriptor with an IDPSSODescriptor inside an EntitiesDescriptor)
// and checks it has an entity id, an IDPSSODescriptor, an HTTP-Redirect SSO
// endpoint and a signing certificate.
func ParseIdPMetadata(raw []byte) (*saml.EntityDescriptor, error) {
	if len(raw) > maxSAMLXML {
		return nil, errors.New("IdP metadata is too large")
	}
	if err := xrv.Validate(bytes.NewReader(raw)); err != nil {
		return nil, fmt.Errorf("IdP metadata is not valid XML: %w", err)
	}
	var md *saml.EntityDescriptor
	var ed saml.EntityDescriptor
	if err := xml.Unmarshal(raw, &ed); err == nil {
		md = &ed
	} else {
		var es saml.EntitiesDescriptor
		if err2 := xml.Unmarshal(raw, &es); err2 != nil {
			return nil, fmt.Errorf("IdP metadata is not SAML metadata: %w", err)
		}
		for i := range es.EntityDescriptors {
			if len(es.EntityDescriptors[i].IDPSSODescriptors) > 0 {
				md = &es.EntityDescriptors[i]
				break
			}
		}
		if md == nil {
			return nil, errors.New("IdP metadata has no identity provider entity")
		}
	}
	if md.EntityID == "" || len(md.IDPSSODescriptors) == 0 {
		return nil, errors.New("IdP metadata has no identity provider entity")
	}
	if (&saml.ServiceProvider{IDPMetadata: md}).GetSSOBindingLocation(saml.HTTPRedirectBinding) == "" {
		return nil, errors.New("IdP metadata has no HTTP-Redirect single sign-on service")
	}
	if _, err := idpSigningCerts(md); err != nil {
		return nil, errors.New("IdP metadata has no signing certificate")
	}
	return md, nil
}

// ValidateMetadataURL requires an absolute https URL (http only for
// loopback, like issuers); a query is allowed (Entra's appid=).
func ValidateMetadataURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("metadata URL %q is not an absolute URL", s)
	}
	probe := *u
	probe.RawQuery = ""
	if err := ValidateIssuer(probe.String()); err != nil {
		return fmt.Errorf("metadata URL %q must use https", s)
	}
	return nil
}

// FetchIdPMetadata downloads and parses IdP metadata with client (the
// platform or org IdP client: 10 s, 1 MiB, no redirects, SSRF dial guard).
func FetchIdPMetadata(ctx context.Context, client *http.Client, metadataURL string) (*saml.EntityDescriptor, error) {
	if err := ValidateMetadataURL(metadataURL); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/samlmetadata+xml, application/xml, text/xml")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch IdP metadata: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch IdP metadata: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("fetch IdP metadata: %w", err)
	}
	return ParseIdPMetadata(body)
}

// GenerateSPKeyPair makes a provider's SP key pair: RSA-2048 and a
// self-signed certificate valid for ten years. The key is PKCS#8 PEM.
func GenerateSPKeyPair(providerID string) (keyPEM, certPEM string, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("saml: generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return "", "", fmt.Errorf("saml: serial: %w", err)
	}
	cn := "Boardchestrator SAML SP " + providerID
	if len(cn) > 64 {
		cn = cn[:64]
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(spCertValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", fmt.Errorf("saml: certificate: %w", err)
	}
	pk, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", fmt.Errorf("saml: marshal key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})),
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}

// ParseSPKeyPair parses a stored SP key (PKCS#8 PEM) and certificate PEM.
func ParseSPKeyPair(keyPEM, certPEM string) (*rsa.PrivateKey, *x509.Certificate, error) {
	kb, _ := pem.Decode([]byte(keyPEM))
	cb, _ := pem.Decode([]byte(certPEM))
	if kb == nil || cb == nil {
		return nil, nil, errors.New("SAML SP key pair is missing")
	}
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("SAML SP key: %w", err)
	}
	key, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("SAML SP key is not RSA")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("SAML SP certificate: %w", err)
	}
	return key, cert, nil
}

// sealSPKey encrypts an SP key with the BC_SECRET_KEY-derived key.
func sealSPKey(key []byte, keyPEM string) (string, error) {
	if len(key) != 32 {
		return "", errors.New("idp: no BC_SECRET_KEY to seal the SAML key with")
	}
	enc, err := tenant.Encrypt(key, keyPEM)
	if err != nil {
		return "", fmt.Errorf("idp: seal SAML key: %w", err)
	}
	return enc, nil
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}
