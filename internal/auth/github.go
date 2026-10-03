package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// GitHub endpoints. GitHub is OAuth 2.0, not OIDC (SPEC §7.1).
const (
	GitHubWebBase = "https://github.com"
	GitHubAPIBase = "https://api.github.com"
)

// GitHubConfig holds GitHub OAuth application credentials.
type GitHubConfig struct {
	ClientID     string
	ClientSecret string
	BaseURL      string // Boardchestrator's BC_BASE_URL
	// WebBase and APIBase override https://github.com and
	// https://api.github.com (tests point them at httptest fakes).
	WebBase string
	APIBase string
	// Client is the IdP HTTP client; nil = NewIdPClient(nil).
	Client *http.Client
}

// GitHubConnector signs users in with GitHub OAuth. Credentials travel in the
// POST body of the token exchange, never the URL.
type GitHubConnector struct {
	cfg GitHubConfig
	// Endpoint URLs, fixed at construction from operator config.
	tokenURL, userURL, emailsURL string
}

// NewGitHubConnector builds the GitHub connector.
func NewGitHubConnector(cfg GitHubConfig) *GitHubConnector {
	if cfg.WebBase == "" {
		cfg.WebBase = GitHubWebBase
	}
	if cfg.APIBase == "" {
		cfg.APIBase = GitHubAPIBase
	}
	cfg.WebBase = strings.TrimRight(cfg.WebBase, "/")
	cfg.APIBase = strings.TrimRight(cfg.APIBase, "/")
	if cfg.Client == nil {
		cfg.Client = NewIdPClient(nil)
	}
	return &GitHubConnector{
		cfg:       cfg,
		tokenURL:  cfg.WebBase + "/login/oauth/access_token",
		userURL:   cfg.APIBase + "/user",
		emailsURL: cfg.APIBase + "/user/emails",
	}
}

func (c *GitHubConnector) ID() string         { return "github" }
func (c *GitHubConnector) AuthMethod() string { return AuthMethodGitHub }

// Policy: GitHub returns only verified emails here, so it is trusted for
// email linking; sign-up allowed until WU-604.
func (c *GitHubConnector) Policy() ResolvePolicy {
	return ResolvePolicy{TrustEmail: true, AllowSignup: true}
}

func (c *GitHubConnector) redirectURL() string { return c.cfg.BaseURL + "/auth/github/callback" }

// Begin returns GitHub's authorisation URL for flow.
func (c *GitHubConnector) Begin(_ context.Context, flow *Flow) (string, error) {
	v := url.Values{
		"client_id":    {c.cfg.ClientID},
		"redirect_uri": {c.redirectURL()},
		"state":        {flow.State},
		"scope":        {"read:user user:email"},
	}
	if flow.LoginHint != "" {
		v.Set("login", flow.LoginHint)
	}
	return c.cfg.WebBase + "/login/oauth/authorize?" + v.Encode(), nil
}

// Complete exchanges the code and reads the user's id, profile and primary
// verified email.
func (c *GitHubConnector) Complete(ctx context.Context, r *http.Request, _ *Flow) (*Assertion, error) {
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		return nil, fmt.Errorf("github: authorisation error %q", e)
	}
	code := q.Get("code")
	if code == "" {
		return nil, errors.New("github: no code")
	}
	token, err := c.exchange(ctx, code)
	if err != nil {
		return nil, err
	}

	var user struct {
		ID     int64  `json:"id"`
		Login  string `json:"login"`
		Name   string `json:"name"`
		Avatar string `json:"avatar_url"`
	}
	if err := c.getJSON(ctx, token, c.userURL, &user); err != nil {
		return nil, err
	}
	if user.ID == 0 {
		return nil, errors.New("github: /user returned no id")
	}
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := c.getJSON(ctx, token, c.emailsURL, &emails); err != nil {
		return nil, err
	}
	email := ""
	for _, e := range emails {
		if e.Primary && e.Verified {
			email = e.Email
			break
		}
	}
	if email == "" {
		return nil, errors.New("github: no verified primary email")
	}
	name := user.Name
	if name == "" {
		name = user.Login
	}
	return &Assertion{
		ProviderID:    "github",
		Subject:       strconv.FormatInt(user.ID, 10),
		Email:         email,
		EmailVerified: true,
		Name:          name,
		Picture:       user.Avatar,
		RawClaims:     map[string]any{"login": user.Login},
		AccessToken:   token,
	}, nil
}

func (c *GitHubConnector) exchange(ctx context.Context, code string) (string, error) {
	form := url.Values{
		"client_id":     {c.cfg.ClientID},
		"client_secret": {c.cfg.ClientSecret},
		"code":          {code},
		"redirect_uri":  {c.redirectURL()},
	}
	// gosec G704 taints this request because the callback's code is in the
	// body. The target URL is fixed operator config (github.com by default),
	// never request-derived, so there is no SSRF; credentials are in the body.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(form.Encode())) //nolint:gosec // G704: URL is operator config, see above

	if err != nil {
		return "", fmt.Errorf("github: token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.cfg.Client.Do(req) //nolint:gosec // G704: URL is operator config, see above
	if err != nil {
		return "", fmt.Errorf("github: token exchange: %w", err)
	}
	defer drainClose(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github: token exchange: status %d", resp.StatusCode)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("github: decode token response: %w", err)
	}
	if tr.AccessToken == "" {
		return "", fmt.Errorf("github: no access_token (error %q)", tr.Error)
	}
	return tr.AccessToken, nil
}

func (c *GitHubConnector) getJSON(ctx context.Context, token, endpoint string, out any) error {
	path := strings.TrimPrefix(endpoint, c.cfg.APIBase)
	// G704: endpoint is c.userURL/c.emailsURL, fixed from operator config at
	// construction; only the bearer token comes from the exchange.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil) //nolint:gosec // G704: config-fixed URL, see above
	if err != nil {
		return fmt.Errorf("github: %s request: %w", path, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := c.cfg.Client.Do(req) //nolint:gosec // G704: config-fixed URL, see above
	if err != nil {
		return fmt.Errorf("github: %s: %w", path, err)
	}
	defer drainClose(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("github: %s: status %d", path, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("github: %s: decode: %w", path, err)
	}
	return nil
}

func drainClose(rc io.ReadCloser) {
	_, _ = io.Copy(io.Discard, rc)
	_ = rc.Close()
}
