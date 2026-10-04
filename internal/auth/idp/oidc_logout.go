package idp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/thomasteoh/boardchestrator/internal/auth"
)

var (
	_ auth.RPLogoutConnector          = (*OIDCConnector)(nil)
	_ auth.BackChannelLogoutConnector = (*OIDCConnector)(nil)
)

// maxLogoutToken bounds a logout token before any parsing.
const maxLogoutToken = 16 << 10

// logoutMetadata is the part of the discovery document logout needs.
type logoutMetadata struct {
	EndSessionEndpoint         string `json:"end_session_endpoint"`
	BackchannelLogoutSupported bool   `json:"backchannel_logout_supported"`
}

// EndSessionURL implements auth.RPLogoutConnector (OIDC RP-Initiated
// Logout 1.0): the provider's end_session_endpoint with id_token_hint,
// client_id, post_logout_redirect_uri and state. "" when IdP sign-out is off
// for this provider or discovery publishes no endpoint.
func (c *OIDCConnector) EndSessionURL(ctx context.Context, req auth.EndSessionRequest) (string, error) {
	if !c.cfg.IdPLogout {
		return "", nil
	}
	p, err := c.discover(ctx)
	if err != nil {
		return "", err
	}
	var md logoutMetadata
	if err := p.Claims(&md); err != nil {
		return "", fmt.Errorf("oidc %s: discovery metadata: %w", c.cfg.ID, err)
	}
	if md.EndSessionEndpoint == "" {
		return "", nil
	}
	u, err := url.Parse(md.EndSessionEndpoint)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || !secureScheme(u) {
		return "", fmt.Errorf("oidc %s: unusable end_session_endpoint", c.cfg.ID)
	}
	q := u.Query()
	q.Set("id_token_hint", req.IDTokenHint)
	q.Set("client_id", c.cfg.ClientID)
	q.Set("post_logout_redirect_uri", req.PostLogoutRedirectURI)
	q.Set("state", req.State)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// secureScheme: https, or http to a loopback host (as ValidateIssuer).
func secureScheme(u *url.URL) bool {
	switch u.Scheme {
	case "https":
		return true
	case "http":
		host := u.Hostname()
		ip := net.ParseIP(host)
		return host == "localhost" || (ip != nil && ip.IsLoopback())
	}
	return false
}

// VerifyLogoutToken implements auth.BackChannelLogoutConnector (OIDC
// Back-Channel Logout 1.0 §2.6): signature against the provider's JWKS, iss,
// aud = our client id, iat within auth.LogoutTokenSkew of now, exp (when
// present) not passed, an events object with the back-channel logout member,
// sid or sub, a jti, and no nonce (which is what keeps an ID token from being
// replayed as a logout token). A typ header, when present, must be JWT or
// logout+jwt.
func (c *OIDCConnector) VerifyLogoutToken(ctx context.Context, raw string) (*auth.LogoutToken, error) {
	if len(raw) > maxLogoutToken {
		return nil, errors.New("logout token too large")
	}
	if err := checkLogoutTyp(raw); err != nil {
		return nil, err
	}
	p, err := c.discover(ctx)
	if err != nil {
		return nil, err
	}
	// Expiry is checked below: exp is optional in a logout token, and
	// go-oidc would treat a missing one as expired.
	v := p.Verifier(&oidc.Config{ClientID: c.cfg.ClientID, SkipIssuerCheck: c.cfg.EntraMultiTenant, SkipExpiryCheck: true})
	tok, err := v.Verify(c.clientCtx(ctx), raw)
	if err != nil {
		return nil, fmt.Errorf("oidc %s: logout token: %w", c.cfg.ID, err)
	}
	claims := map[string]any{}
	if err := tok.Claims(&claims); err != nil {
		return nil, fmt.Errorf("oidc %s: logout token claims: %w", c.cfg.ID, err)
	}
	if c.cfg.EntraMultiTenant {
		if err := c.checkEntraIssuer(tok.Issuer, claims); err != nil {
			return nil, err
		}
	}
	now := time.Now()
	iat, ok := numericDate(claims["iat"])
	if !ok {
		return nil, errors.New("logout token has no iat")
	}
	if d := now.Sub(iat); d > auth.LogoutTokenSkew || d < -auth.LogoutTokenSkew {
		return nil, fmt.Errorf("logout token iat is %s from now", d.Round(time.Second))
	}
	if rawExp, present := claims["exp"]; present {
		exp, ok := numericDate(rawExp)
		if !ok || !now.Before(exp) {
			return nil, errors.New("logout token expired")
		}
	}
	if _, present := claims["nonce"]; present {
		return nil, errors.New("logout token carries a nonce")
	}
	events, _ := claims["events"].(map[string]any)
	if _, ok := events[auth.BackChannelLogoutEvent].(map[string]any); !ok {
		return nil, errors.New("logout token has no back-channel logout event")
	}
	sid, _ := claims["sid"].(string)
	if sid == "" && tok.Subject == "" {
		return nil, errors.New("logout token names neither sid nor sub")
	}
	jti, _ := claims["jti"].(string)
	if jti == "" {
		return nil, errors.New("logout token has no jti")
	}
	return &auth.LogoutToken{Subject: tok.Subject, SID: sid, JTI: jti, IssuedAt: iat}, nil
}

// checkLogoutTyp refuses a JOSE typ other than JWT or logout+jwt (an access
// token's at+jwt, say). A missing typ is accepted.
func checkLogoutTyp(raw string) error {
	head, _, ok := strings.Cut(raw, ".")
	if !ok {
		return errors.New("logout token is not a JWT")
	}
	b, err := base64.RawURLEncoding.DecodeString(head)
	if err != nil {
		return errors.New("logout token header is not base64url")
	}
	var h struct {
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(b, &h); err != nil {
		return errors.New("logout token header is not JSON")
	}
	switch strings.ToLower(h.Typ) {
	case "", "jwt", "logout+jwt", "application/logout+jwt":
		return nil
	}
	return fmt.Errorf("logout token typ %q", h.Typ)
}

// numericDate reads a JWT NumericDate claim.
func numericDate(v any) (time.Time, bool) {
	f, ok := v.(float64)
	if !ok || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > 1e11 {
		return time.Time{}, false
	}
	sec, frac := math.Modf(f)
	return time.Unix(int64(sec), int64(frac*1e9)), true
}
