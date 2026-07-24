package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// GitHubConfig holds GitHub OAuth application credentials.
type GitHubConfig struct {
	ClientID     string
	ClientSecret string
	BaseURL      string
}

// GitHubProvider wraps the GitHub OAuth flow (no OIDC — GitHub uses a
// separate user-info endpoint).
type GitHubProvider struct {
	cfg GitHubConfig
}

// NewGitHubProvider creates a GitHub OAuth provider.
func NewGitHubProvider(cfg GitHubConfig) *GitHubProvider {
	return &GitHubProvider{cfg: cfg}
}

// GitHubUser is the GitHub API user object returned by /user.
type GitHubUser struct {
	ID      int64  `json:"id"`
	Login   string `json:"login"`
	Email   string `json:"email"`
	Name    string `json:"name"`
	Avatar  string `json:"avatar_url"`
	Primary bool   `json:"primary"` // from /emails endpoint
	Verified bool `json:"verified"`
}

// AuthURL returns the GitHub OAuth URL and a state nonce.
func (p *GitHubProvider) AuthURL(state string) string {
	return fmt.Sprintf(
		"https://github.com/login/oauth/authorize?client_id=%s&redirect_uri=%s&state=%s&scope=user:email",
		p.cfg.ClientID, p.cfg.BaseURL+"/auth/github/callback", state,
	)
}

// Exchange exchanges the code for an access token and fetches user info.
// It returns the primary verified email and profile details.
func (p *GitHubProvider) Exchange(ctx context.Context, code, state string) (*GitHubUser, error) {
	// POST to GitHub token endpoint.
	tokenURL := fmt.Sprintf(
		"https://github.com/login/oauth/access_token?client_id=%s&client_secret=%s&code=%s",
		p.cfg.ClientID, p.cfg.ClientSecret, code,
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, nil)
	if err != nil {
		return nil, fmt.Errorf("github: token request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github: token exchange: %w", err)
	}
	defer resp.Body.Close()

	var tokResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokResp); err != nil {
		return nil, fmt.Errorf("github: decode token response: %w", err)
	}
	if tokResp.AccessToken == "" {
		return nil, fmt.Errorf("github: no access_token in response")
	}

	// Fetch user profile.
	user, err := fetchGitHubUser(ctx, tokResp.AccessToken)
	if err != nil {
		return nil, err
	}

	// Fetch primary verified email if not already visible.
	if user.Email == "" || !user.Verified {
		emails, err := fetchGitHubEmails(ctx, tokResp.AccessToken)
		if err != nil {
			return nil, err
		}
		for _, e := range emails {
			if e.Primary && e.Verified {
				user.Email = e.Email
				user.Verified = true
				break
			}
		}
	}

	if user.Email == "" || !user.Verified {
		return nil, fmt.Errorf("github: no verified primary email — ensure user:email scope is granted")
	}
	if user.Name == "" {
		user.Name = user.Login
	}

	return user, nil
}

func fetchGitHubUser(ctx context.Context, token string) (*GitHubUser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", nil)
	if err != nil {
		return nil, fmt.Errorf("github: user request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github: fetch user: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, fmt.Errorf("github: read user: %w", err)
	}
	var user GitHubUser
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, fmt.Errorf("github: parse user: %w", err)
	}
	return &user, nil
}

func fetchGitHubEmails(ctx context.Context, token string) ([]struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/emails", nil)
	if err != nil {
		return nil, fmt.Errorf("github: emails request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github: fetch emails: %w", err)
	}
	defer resp.Body.Close()
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return nil, fmt.Errorf("github: parse emails: %w", err)
	}
	return emails, nil
}
