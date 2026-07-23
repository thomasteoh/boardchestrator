package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// OIDCConfig holds Google OIDC client configuration.
type OIDCConfig struct {
	ClientID     string
	ClientSecret string
	BaseURL      string
}

// OIDCProvider wraps the Google OIDC flow.
type OIDCProvider struct {
	cfg    OIDCConfig
	oauth2 oauth2.Config
}

// NewOIDCProvider creates a provider wired to Google's OIDC discovery.
func NewOIDCProvider(cfg OIDCConfig) *OIDCProvider {
	return &OIDCProvider{
		cfg: cfg,
		oauth2: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     google.Endpoint,
			Scopes:       []string{"openid", "email", "profile"},
			RedirectURL:  cfg.BaseURL + "/auth/google/callback",
		},
	}
}

// AuthURL returns the Google OAuth URL and a state nonce for CSRF protection.
func (p *OIDCProvider) AuthURL() (string, string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("oidc: generate state: %w", err)
	}
	state := hex.EncodeToString(b)
	u := p.oauth2.AuthCodeURL(state, oauth2.AccessTypeOnline)
	return u, state, nil
}

// GoogleClaims is the subset of the Google ID token we extract.
type GoogleClaims struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

// Exchange exchanges the auth code for a token, verifies the state nonce,
// and returns the parsed ID token claims.
func (p *OIDCProvider) Exchange(ctx context.Context, code, storedState, presentedState string) (*GoogleClaims, error) {
	if presentedState != storedState {
		return nil, errors.New("oidc: state mismatch — CSRF detected")
	}
	tok, err := p.oauth2.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("oidc: token exchange: %w", err)
	}
	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, errors.New("oidc: no id_token in response")
	}
	parts := strings.Split(rawIDToken, ".")
	if len(parts) != 3 {
		return nil, errors.New("oidc: malformed id_token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("oidc: decode id_token payload: %w", err)
	}
	var claims GoogleClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("oidc: parse id_token claims: %w", err)
	}
	if !claims.EmailVerified {
		return nil, errors.New("oidc: email not verified by Google")
	}
	if claims.Email == "" {
		return nil, errors.New("oidc: no email in id_token")
	}
	return &claims, nil
}

// FetchGoogleUserInfo is a fallback for providers without id_token support.
func FetchGoogleUserInfo(ctx context.Context, accessToken string) (*GoogleClaims, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc: userinfo: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, fmt.Errorf("oidc: read userinfo: %w", err)
	}
	var claims GoogleClaims
	if err := json.Unmarshal(body, &claims); err != nil {
		return nil, fmt.Errorf("oidc: parse userinfo: %w", err)
	}
	return &claims, nil
}

// IdentityStore is the interface for finding/creating users and linking identities.
type IdentityStore interface {
	FindUserByEmail(ctx context.Context, email string) (string, error)
	CreateUser(ctx context.Context, email, name, avatarURL string) (string, error)
	LinkIdentity(ctx context.Context, userID, provider, subject, email string) error
}

// BootstrapChecker gates first-user-as-admin setup.
type BootstrapChecker interface {
	IsBootstrapped(ctx context.Context) (bool, error)
	IsAdminEmail(email string) bool
	MarkBootstrapped(ctx context.Context) error
}

// LinkOrCreate resolves a Google login to a user account.
func LinkOrCreate(ctx context.Context, store IdentityStore, claims *GoogleClaims) (string, error) {
	userID, err := store.FindUserByEmail(ctx, claims.Email)
	if err != nil {
		return "", fmt.Errorf("auth: find user by email: %w", err)
	}
	if userID == "" {
		userID, err = store.CreateUser(ctx, claims.Email, claims.Name, claims.Picture)
		if err != nil {
			return "", fmt.Errorf("auth: create user: %w", err)
		}
	}
	if err := store.LinkIdentity(ctx, userID, "google", claims.Sub, claims.Email); err != nil {
		return "", fmt.Errorf("auth: link identity: %w", err)
	}
	return userID, nil
}

// HashToken256 returns hex SHA-256 of a token.
func HashToken256(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
