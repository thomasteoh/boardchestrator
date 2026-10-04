package idp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/action"
)

// DiscoverInput is the idp.discover input: either the id of a saved provider,
// or an unsaved preset + params from the admin form.
type DiscoverInput struct {
	ID     string            `json:"id,omitempty"`
	Preset string            `json:"preset,omitempty"`
	Params map[string]string `json:"params,omitempty"`
}

// DiscoverResult reports an OIDC discovery attempt. On failure only Ref is
// set: the upstream error is logged under that reference, never returned.
type DiscoverResult struct {
	OK                    bool   `json:"ok"`
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint,omitempty"`
	TokenEndpoint         string `json:"token_endpoint,omitempty"`
	UserinfoEndpoint      string `json:"userinfo_endpoint,omitempty"`
	JWKSURI               string `json:"jwks_uri,omitempty"`
	EndSessionEndpoint    string `json:"end_session_endpoint,omitempty"`
	// BackchannelLogout: the provider advertises OIDC back-channel logout.
	BackchannelLogout bool   `json:"backchannel_logout_supported,omitempty"`
	Ref               string `json:"ref,omitempty"`
}

// discoveryDoc is the subset of the OIDC discovery document we report.
type discoveryDoc struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
	BackchannelLogout     bool   `json:"backchannel_logout_supported"`
}

// discoveryClient fetches discovery documents for the admin "Test discovery"
// button. It is the IdP client (10 s, 1 MiB, no redirects) over a dialer that
// refuses link-local, multicast and unspecified addresses at connect time.
//
// Private and loopback addresses are deliberately allowed: self-hosted IdPs
// (Keycloak, authentik, Zitadel) commonly live on the operator's private
// network, only platform admins can trigger this, and the same admin can
// already point the login registry at any issuer. Cloud metadata endpoints
// (169.254.169.254, fd00:ec2::254) stay blocked. See QUESTIONS.md Q9.
var discoveryClient = NewIdPClient(&http.Transport{
	Proxy:                 nil,
	DialContext:           (&net.Dialer{Timeout: 5 * time.Second, Control: discoveryDialControl}).DialContext,
	TLSHandshakeTimeout:   5 * time.Second,
	ResponseHeaderTimeout: 8 * time.Second,
	MaxIdleConns:          4,
	IdleConnTimeout:       30 * time.Second,
})

var awsIPv6Metadata = net.ParseIP("fd00:ec2::254")

// discoveryDialControl runs after DNS resolution with the address actually
// being dialled, so a hostname cannot resolve its way past the check.
func discoveryDialControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("idp: discovery: unexpected address %q", address)
	}
	if blockedDiscoveryIP(ip) {
		return fmt.Errorf("idp: discovery: address %s is not allowed", ip)
	}
	return nil
}

func blockedDiscoveryIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	return ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.Equal(awsIPv6Metadata)
}

// NewOrgIdPClient is the IdP client for organisation-owned providers and
// org.idp.discover. Org owners are less trusted than platform admins, so on
// top of the platform guard it refuses loopback, private (RFC 1918, ULA),
// shared (100.64/10) and 0/8 addresses unless allowPrivate
// (BC_ORG_IDP_ALLOW_PRIVATE). The check runs at dial time on the resolved
// address, and no proxy is used, so DNS cannot route around it (Q11).
func NewOrgIdPClient(allowPrivate bool) *http.Client {
	control := func(network, address string, c syscall.RawConn) error {
		if err := discoveryDialControl(network, address, c); err != nil {
			return err
		}
		if allowPrivate {
			return nil
		}
		host, _, _ := net.SplitHostPort(address)
		if ip := net.ParseIP(host); ip != nil && privateIP(ip) {
			return fmt.Errorf("idp: organisation provider address %s is private; set BC_ORG_IDP_ALLOW_PRIVATE to allow", ip)
		}
		return nil
	}
	return NewIdPClient(&http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, Control: control}).DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 8 * time.Second,
		MaxIdleConns:          16,
		IdleConnTimeout:       30 * time.Second,
	})
}

var sharedNet = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

func privateIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
		if ip4[0] == 0 || sharedNet.Contains(ip4) {
			return true
		}
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified()
}

func handleDiscover(ctx context.Context, ac action.ActionCtx, in json.RawMessage) (any, error) {
	var input DiscoverInput
	if err := decodeStrict(in, &input); err != nil {
		return nil, err
	}
	var issuer, presetID string
	switch {
	case input.ID != "" && (input.Preset != "" || len(input.Params) > 0):
		return nil, invalid("give either a provider id or a preset with parameters, not both")
	case input.ID != "":
		row, err := ac.Tx.GetAuthProvider(ctx, input.ID)
		if err != nil || row.OrgID.Valid {
			return nil, invalid("no sign-in provider %q", input.ID)
		}
		if row.Kind != KindOIDC {
			return nil, invalid("only OpenID Connect providers publish discovery documents")
		}
		issuer, presetID = row.Issuer, row.Preset
	default:
		p, ok := LookupPreset(input.Preset)
		if !ok || input.Preset == "" {
			return nil, invalid("unknown preset %q", input.Preset)
		}
		if p.Kind != KindOIDC {
			return nil, invalid("only OpenID Connect providers publish discovery documents")
		}
		for k := range input.Params {
			if !presetHasParam(p, k) {
				return nil, invalid("preset %s has no parameter %q", p.ID, k)
			}
		}
		iss, err := p.ExpandIssuer(input.Params)
		if err != nil {
			return nil, invalid("%v", err)
		}
		issuer, presetID = iss, p.ID
	}
	res, err := discover(ctx, discoveryClient, issuer, presetID)
	if err != nil {
		ref := discoveryRef()
		slog.Warn("idp: discovery test failed", "ref", ref, "issuer", issuer, "err", err)
		return DiscoverResult{Issuer: issuer, Ref: ref}, nil
	}
	return res, nil
}

// discover fetches and checks <issuer>/.well-known/openid-configuration.
func discover(ctx context.Context, client *http.Client, issuer, presetID string) (DiscoverResult, error) {
	if err := ValidateIssuer(issuer); err != nil {
		return DiscoverResult{}, err
	}
	u := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return DiscoverResult{}, err
	}
	req.Header.Set("Accept", "application/json")
	// The URL is the admin's configured issuer (platform admins only); the
	// dialer refuses metadata and link-local targets.
	resp, err := client.Do(req)
	if err != nil {
		return DiscoverResult{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return DiscoverResult{}, fmt.Errorf("discovery status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return DiscoverResult{}, err
	}
	var doc discoveryDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return DiscoverResult{}, fmt.Errorf("discovery document: %w", err)
	}
	if !issuerMatches(doc.Issuer, issuer, presetID) {
		return DiscoverResult{}, fmt.Errorf("discovery issuer %q does not match %q", doc.Issuer, issuer)
	}
	for name, v := range map[string]string{
		"authorization_endpoint": doc.AuthorizationEndpoint,
		"token_endpoint":         doc.TokenEndpoint,
		"jwks_uri":               doc.JWKSURI,
	} {
		if v == "" {
			return DiscoverResult{}, fmt.Errorf("discovery document has no %s", name)
		}
	}
	for _, v := range []string{doc.AuthorizationEndpoint, doc.TokenEndpoint, doc.JWKSURI, doc.UserinfoEndpoint, doc.EndSessionEndpoint} {
		if v != "" && !httpURL(v) {
			return DiscoverResult{}, errors.New("discovery document has a malformed endpoint URL")
		}
	}
	return DiscoverResult{
		OK: true, Issuer: issuer,
		AuthorizationEndpoint: doc.AuthorizationEndpoint, TokenEndpoint: doc.TokenEndpoint,
		UserinfoEndpoint: doc.UserinfoEndpoint, JWKSURI: doc.JWKSURI,
		EndSessionEndpoint: doc.EndSessionEndpoint, BackchannelLogout: doc.BackchannelLogout,
	}, nil
}

// issuerMatches applies OIDC Discovery §4.3 (the document's issuer equals the
// configured one), allowing Entra's templated multi-tenant issuer.
func issuerMatches(got, want, presetID string) bool {
	if got == want {
		return true
	}
	if presetID == "microsoft" {
		if t, multi := entraTenant(want); multi {
			return got == strings.Replace(want, "/"+t+"/", "/{tenantid}/", 1)
		}
	}
	return false
}

func httpURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.User == nil
}

func discoveryRef() string {
	b := make([]byte, 5)
	if _, err := rand.Read(b); err != nil {
		return "UNKNOWN"
	}
	return strings.ToUpper(hex.EncodeToString(b))
}
