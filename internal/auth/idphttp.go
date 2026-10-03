package auth

import (
	"io"
	"net/http"
	"time"
)

// IdP HTTP limits (SPEC §7.1): every outbound request to an identity provider
// (discovery, JWKS, token, userinfo, GitHub API) runs with a 10 s timeout and
// reads at most 1 MiB of response body.
const (
	IdPTimeout      = 10 * time.Second
	IdPMaxBodyBytes = 1 << 20
)

// NewIdPClient returns the shared HTTP client for identity-provider traffic.
// base is the transport to wrap (nil = http.DefaultTransport); tests pass an
// httptest server's transport.
func NewIdPClient(base http.RoundTripper) *http.Client {
	if base == nil {
		base = http.DefaultTransport
	}
	return &http.Client{
		Timeout:   IdPTimeout,
		Transport: limitTransport{base: base},
		// Token and API endpoints never legitimately redirect; refusing keeps
		// a credential-bearing POST from being replayed elsewhere.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// limitTransport caps every response body at IdPMaxBodyBytes, so libraries
// that io.ReadAll the body (go-oidc discovery/JWKS, x/oauth2 token exchange)
// are bounded too.
type limitTransport struct{ base http.RoundTripper }

func (t limitTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	resp.Body = limitedBody{Reader: io.LimitReader(resp.Body, IdPMaxBodyBytes), Closer: resp.Body}
	return resp, nil
}

type limitedBody struct {
	io.Reader
	io.Closer
}
