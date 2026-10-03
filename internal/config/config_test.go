package config_test

import (
	"os"
	"strings"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/config"
)

func TestLoadDefaults(t *testing.T) {
	os.Clearenv()
	os.Setenv("BC_SECRET_KEY", "test-secret-key")
	os.Setenv("BC_SESSION_SECRET", "a-really-long-session-secret-that-is-at-least-thirty-two-chars")
	os.Setenv("BC_GOOGLE_CLIENT_ID", "google-client-id")
	os.Setenv("BC_GOOGLE_CLIENT_SECRET", "google-client-secret")
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if cfg.DBPath != "bc.db" {
		t.Errorf("DBPath = %q, want bc.db", cfg.DBPath)
	}
	if cfg.DataDir != "./data" {
		t.Errorf("DataDir = %q, want ./data", cfg.DataDir)
	}
	if cfg.BaseURL != "http://localhost:8080" {
		t.Errorf("BaseURL = %q, want http://localhost:8080", cfg.BaseURL)
	}
	if cfg.Bind != "0.0.0.0:8080" {
		t.Errorf("Bind = %q, want 0.0.0.0:8080", cfg.Bind)
	}
	if cfg.LogLevelStr != "info" {
		t.Errorf("LogLevelStr = %q, want info", cfg.LogLevelStr)
	}
	if cfg.AgentWorkers != 4 {
		t.Errorf("AgentWorkers = %d, want 4", cfg.AgentWorkers)
	}
}

func TestLoadOverrides(t *testing.T) {
	os.Clearenv()
	os.Setenv("BC_SECRET_KEY", "test-secret-key")
	os.Setenv("BC_SESSION_SECRET", "session-secret-for-test-minimum-thirty-two-chars")
	os.Setenv("BC_GOOGLE_CLIENT_ID", "google-client-id")
	os.Setenv("BC_GOOGLE_CLIENT_SECRET", "google-client-secret")
	os.Setenv("BC_DB_PATH", "/data/custom.db")
	os.Setenv("BC_DATA_DIR", "/data")
	os.Setenv("BC_BASE_URL", "https://board.example.com")
	os.Setenv("BC_BIND", "127.0.0.1:9090")
	os.Setenv("BC_LOG_LEVEL", "debug")
	os.Setenv("BC_AGENT_WORKERS", "8")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if cfg.DBPath != "/data/custom.db" {
		t.Errorf("DBPath = %q", cfg.DBPath)
	}
	if cfg.DataDir != "/data" {
		t.Errorf("DataDir = %q", cfg.DataDir)
	}
	if cfg.BaseURL != "https://board.example.com" {
		t.Errorf("BaseURL = %q", cfg.BaseURL)
	}
	if cfg.Bind != "127.0.0.1:9090" {
		t.Errorf("Bind = %q", cfg.Bind)
	}
	if cfg.LogLevelStr != "debug" {
		t.Errorf("LogLevelStr = %q", cfg.LogLevelStr)
	}
	if cfg.AgentWorkers != 8 {
		t.Errorf("AgentWorkers = %d, want 8", cfg.AgentWorkers)
	}
}

func TestLoadInvalidLogLevel(t *testing.T) {
	os.Clearenv()
	os.Setenv("BC_SECRET_KEY", "test-secret-key")
	os.Setenv("BC_SESSION_SECRET", "a-really-long-session-secret-that-is-at-least-thirty-two-chars")
	os.Setenv("BC_GOOGLE_CLIENT_ID", "google-client-id")
	os.Setenv("BC_GOOGLE_CLIENT_SECRET", "google-client-secret")
	os.Setenv("BC_LOG_LEVEL", "trace")
	_, err := config.Load()
	if err == nil {
		t.Fatal("Load() should error on invalid log level")
	}
}

func TestLoadMissingSecretKey(t *testing.T) {
	os.Clearenv()
	os.Setenv("BC_SESSION_SECRET", "a-really-long-session-secret-that-is-at-least-thirty-two-chars")
	os.Setenv("BC_GOOGLE_CLIENT_ID", "google-client-id")
	os.Setenv("BC_GOOGLE_CLIENT_SECRET", "google-client-secret")
	_, err := config.Load()
	if err == nil {
		t.Fatal("Load() should error when BC_SECRET_KEY is missing")
	}
}

func TestLoadAdminEmails(t *testing.T) {
	os.Clearenv()
	os.Setenv("BC_SECRET_KEY", "test-secret-key")
	os.Setenv("BC_SESSION_SECRET", "a-really-long-session-secret-that-is-at-least-thirty-two-chars")
	os.Setenv("BC_GOOGLE_CLIENT_ID", "google-client-id")
	os.Setenv("BC_GOOGLE_CLIENT_SECRET", "google-client-secret")
	os.Setenv("BC_ADMIN_EMAILS", "alice@example.com,bob@example.com")
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if len(cfg.AdminEmails) != 2 {
		t.Fatalf("AdminEmails = %d entries, want 2", len(cfg.AdminEmails))
	}
	if cfg.AdminEmails[0] != "alice@example.com" {
		t.Errorf("AdminEmails[0] = %q", cfg.AdminEmails[0])
	}
	if cfg.AdminEmails[1] != "bob@example.com" {
		t.Errorf("AdminEmails[1] = %q", cfg.AdminEmails[1])
	}
}

func TestLoadRequiresSessionSecret(t *testing.T) {
	os.Clearenv()
	os.Setenv("BC_SECRET_KEY", "test-secret-key")
	os.Setenv("BC_GOOGLE_CLIENT_ID", "google-client-id")
	os.Setenv("BC_GOOGLE_CLIENT_SECRET", "google-client-secret")
	_, err := config.Load()
	if err == nil {
		t.Fatal("Load() should error when BC_SESSION_SECRET is missing")
	}
}

func TestLoadSessionSecretTooShort(t *testing.T) {
	os.Clearenv()
	os.Setenv("BC_SECRET_KEY", "test-secret-key")
	os.Setenv("BC_SESSION_SECRET", "short")
	os.Setenv("BC_GOOGLE_CLIENT_ID", "google-client-id")
	os.Setenv("BC_GOOGLE_CLIENT_SECRET", "google-client-secret")
	_, err := config.Load()
	if err == nil {
		t.Fatal("Load() should error when BC_SESSION_SECRET is too short")
	}
}

func baseEnv() {
	os.Clearenv()
	os.Setenv("BC_SECRET_KEY", "test-secret-key")
	os.Setenv("BC_SESSION_SECRET", "a-really-long-session-secret-that-is-at-least-thirty-two-chars")
}

// WU-602: Google is no longer mandatory.
func TestLoadWithoutGoogle(t *testing.T) {
	baseEnv()
	if _, err := config.Load(); err != nil {
		t.Fatalf("Load() without Google: %v", err)
	}
	os.Setenv("BC_GOOGLE_CLIENT_ID", "only-the-id")
	if _, err := config.Load(); err == nil {
		t.Fatal("half-configured Google should error")
	}
}

func TestLoadOIDCProviders(t *testing.T) {
	baseEnv()
	os.Setenv("BC_OIDC_CORP_SSO_ISSUER", "https://idp.example.com")
	os.Setenv("BC_OIDC_CORP_SSO_CLIENT_ID", "cid")
	os.Setenv("BC_OIDC_CORP_SSO_CLIENT_SECRET", "csec")
	os.Setenv("BC_OIDC_CORP_SSO_PRESET", "Keycloak")
	os.Setenv("BC_OIDC_CORP_SSO_DISPLAY_NAME", "Corp SSO")
	os.Setenv("BC_OIDC_CORP_SSO_TRUST_EMAIL", "true")
	os.Setenv("BC_OIDC_CORP_SSO_ALLOW_SIGNUP", "false")
	os.Setenv("BC_OIDC_CORP_SSO_SCOPES", "openid email,groups")
	os.Setenv("BC_OIDC_CORP_SSO_GROUPS_CLAIM", "realm_access.roles")
	os.Setenv("BC_OIDC_OKTA_CLIENT_ID", "okta-id")
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.OIDCProviders) != 2 {
		t.Fatalf("providers = %+v", cfg.OIDCProviders)
	}
	p := cfg.OIDCProviders[0]
	if p.ID != "corp-sso" || p.Issuer != "https://idp.example.com" || p.ClientID != "cid" ||
		p.ClientSecret != "csec" || p.Preset != "keycloak" || p.DisplayName != "Corp SSO" ||
		p.GroupsClaim != "realm_access.roles" {
		t.Errorf("parsed %+v", p)
	}
	if p.TrustEmail == nil || !*p.TrustEmail || p.AllowSignup == nil || *p.AllowSignup {
		t.Errorf("booleans %v %v", p.TrustEmail, p.AllowSignup)
	}
	if strings.Join(p.Scopes, " ") != "openid email groups" {
		t.Errorf("scopes %q", p.Scopes)
	}
	if q := cfg.OIDCProviders[1]; q.ID != "okta" || q.TrustEmail != nil {
		t.Errorf("second %+v", q)
	}
}

func TestLoadOIDCProvidersInvalid(t *testing.T) {
	for name, env := range map[string][2]string{
		"unknown suffix": {"BC_OIDC_X_CLIENTID", "a"},
		"no client id":   {"BC_OIDC_X_ISSUER", "https://idp.example.com"},
		"bad bool":       {"BC_OIDC_X_TRUST_EMAIL", "yes please"},
		"bad name":       {"BC_OIDC_X.Y_CLIENT_ID", "a"},
		"reserved":       {"BC_OIDC_GOOGLE_CLIENT_ID", "a"},
	} {
		t.Run(name, func(t *testing.T) {
			baseEnv()
			os.Setenv(env[0], env[1])
			if name == "bad bool" {
				os.Setenv("BC_OIDC_X_CLIENT_ID", "a")
			}
			if _, err := config.Load(); err == nil {
				t.Fatalf("%s=%s: want error", env[0], env[1])
			}
		})
	}
}

// WU-604: BC_ALLOW_SIGNUP defaults to true and must be a boolean.
func TestLoadAllowSignup(t *testing.T) {
	baseEnv()
	t.Setenv("BC_ALLOW_SIGNUP", "")
	c, err := config.Load()
	if err != nil || !c.AllowSignup {
		t.Fatalf("default AllowSignup = %v, %v; want true", c != nil && c.AllowSignup, err)
	}
	t.Setenv("BC_ALLOW_SIGNUP", "false")
	if c, err = config.Load(); err != nil || c.AllowSignup {
		t.Fatalf("BC_ALLOW_SIGNUP=false gave %v, %v", c != nil && c.AllowSignup, err)
	}
	t.Setenv("BC_ALLOW_SIGNUP", "maybe")
	if _, err := config.Load(); err == nil {
		t.Fatal("BC_ALLOW_SIGNUP=maybe accepted")
	}
}

func TestLoadTrustedProxies(t *testing.T) {
	baseEnv()
	t.Setenv("BC_TRUSTED_PROXIES", "")
	c, err := config.Load()
	if err != nil || len(c.TrustedProxies) != 0 {
		t.Fatalf("default TrustedProxies = %v, %v; want none", c, err)
	}
	t.Setenv("BC_TRUSTED_PROXIES", "10.0.0.0/8, 192.168.1.7 ::1,fd00::/8")
	c, err = config.Load()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range c.TrustedProxies {
		got = append(got, p.String())
	}
	if want := "10.0.0.0/8 192.168.1.7/32 ::1/128 fd00::/8"; strings.Join(got, " ") != want {
		t.Fatalf("TrustedProxies = %v, want %s", got, want)
	}
	for _, bad := range []string{"10.0.0.0/33", "proxy.example.com", "1.2.3"} {
		t.Setenv("BC_TRUSTED_PROXIES", bad)
		if _, err := config.Load(); err == nil {
			t.Errorf("BC_TRUSTED_PROXIES=%q accepted", bad)
		}
	}
}
