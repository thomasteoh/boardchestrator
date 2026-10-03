package config

import (
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// Config holds all application configuration loaded from environment variables.
type Config struct {
	DBPath             string
	DataDir            string
	BaseURL            string
	Bind               string
	LogLevel           slog.Level
	LogLevelStr        string
	SecretKey          string
	SessionSecret      string
	BootstrapToken     string
	AdminEmails        []string
	AdminEmailsStr     string
	GoogleClientID     string
	GoogleClientSecret string
	GitHubClientID     string `env:"BC_GITHUB_CLIENT_ID"`
	GitHubClientSecret string `env:"BC_GITHUB_CLIENT_SECRET"`
	// OIDCProviders are the BC_OIDC_<NAME>_* providers (SPEC s7.1), seeded
	// into auth_providers at startup.
	OIDCProviders []OIDCEnvProvider `env:"BC_OIDC_<NAME>_*"`
	// AllowSignup (BC_ALLOW_SIGNUP, default true) is the open sign-up policy
	// of every env-seeded provider: google, github, and BC_OIDC_<NAME>_* rows
	// without their own _ALLOW_SIGNUP (WU-604). Providers created in the UI
	// default to invite-only regardless.
	AllowSignup bool
	// OrgIdPAllowPrivate (BC_ORG_IDP_ALLOW_PRIVATE, default false) lets
	// organisation-owned identity providers, and org owners' "Test
	// discovery", reach private and loopback addresses (Q11). Off, only
	// public addresses are dialled for org providers.
	OrgIdPAllowPrivate bool `env:"BC_ORG_IDP_ALLOW_PRIVATE"`
	// IdP endpoint overrides. Not loaded from the environment: tests point the
	// env-seeded google/github providers at in-process fakes
	// (internal/auth/oidctest). Empty means the real provider.
	GoogleIssuer      string `env:"-"`
	GitHubWebBase     string `env:"-"`
	GitHubAPIBase     string `env:"-"`
	AgentWorkers      int
	SchedPollInterval int
	// TrustedProxies (BC_TRUSTED_PROXIES, comma-separated CIDRs or
	// addresses, default none) are the reverse proxies whose
	// X-Forwarded-For is believed when working out a client's IP for rate
	// limits and audit rows (WU-605). Empty: the TCP peer is the client.
	TrustedProxies []netip.Prefix `env:"BC_TRUSTED_PROXIES"`
	// SignInRateLimit overrides the per-IP sign-in rate limit (SPEC §7.11,
	// 20/min burst 10 when zero). Not loaded from the environment: tests
	// that sign in many times from one address raise it.
	SignInRateLimit RateLimit `env:"-"`
	// SCIMRateLimit overrides the per-token SCIM rate limit (SPEC §7.11,
	// 600/min when zero). Not loaded from the environment (tests).
	SCIMRateLimit RateLimit `env:"-"`
}

// RateLimit is a token-bucket rate: PerMinute refill, Burst capacity.
type RateLimit struct {
	PerMinute, Burst int
}

// Load reads configuration from environment variables with defaults.
func Load() (*Config, error) {
	c := &Config{}
	c.DBPath = envOrDefault("BC_DB_PATH", "bc.db")
	c.DataDir = envOrDefault("BC_DATA_DIR", "./data")
	c.BaseURL = envOrDefault("BC_BASE_URL", "http://localhost:8080")
	c.Bind = envOrDefault("BC_BIND", "0.0.0.0:8080")
	c.LogLevelStr = envOrDefault("BC_LOG_LEVEL", "info")
	c.SecretKey = envOrDefault("BC_SECRET_KEY", "")
	c.SessionSecret = envOrDefault("BC_SESSION_SECRET", "")
	c.BootstrapToken = envOrDefault("BC_BOOTSTRAP_TOKEN", "")
	c.AdminEmailsStr = envOrDefault("BC_ADMIN_EMAILS", "")
	c.GoogleClientID = envOrDefault("BC_GOOGLE_CLIENT_ID", "")
	c.GoogleClientSecret = envOrDefault("BC_GOOGLE_CLIENT_SECRET", "")
	c.GitHubClientID = envOrDefault("BC_GITHUB_CLIENT_ID", "")
	c.GitHubClientSecret = envOrDefault("BC_GITHUB_CLIENT_SECRET", "")
	c.AgentWorkers = intEnvOrDefault("BC_AGENT_WORKERS", 4)
	c.SchedPollInterval = intEnvOrDefault("BC_SCHED_POLL_INTERVAL", 60)
	c.AllowSignup = true
	if v := os.Getenv("BC_ALLOW_SIGNUP"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("invalid BC_ALLOW_SIGNUP: %q (want true or false)", v)
		}
		c.AllowSignup = b
	}
	if v := os.Getenv("BC_ORG_IDP_ALLOW_PRIVATE"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("invalid BC_ORG_IDP_ALLOW_PRIVATE: %q (want true or false)", v)
		}
		c.OrgIdPAllowPrivate = b
	}

	// Parse log level.
	switch strings.ToLower(c.LogLevelStr) {
	case "debug":
		c.LogLevel = slog.LevelDebug
	case "info":
		c.LogLevel = slog.LevelInfo
	case "warn", "warning":
		c.LogLevel = slog.LevelWarn
	case "error":
		c.LogLevel = slog.LevelError
	default:
		return nil, fmt.Errorf("invalid BC_LOG_LEVEL: %q", c.LogLevelStr)
	}

	// Parse admin emails.
	if c.AdminEmailsStr != "" {
		c.AdminEmails = strings.Split(c.AdminEmailsStr, ",")
		for i := range c.AdminEmails {
			c.AdminEmails[i] = strings.TrimSpace(c.AdminEmails[i])
		}
	}

	// Validate required fields.
	if c.SecretKey == "" {
		return nil, fmt.Errorf("BC_SECRET_KEY is required")
	}
	// SPEC §7 sessions (Q4): session secret must be set and ≥32 bytes.
	if len(c.SessionSecret) < 32 {
		return nil, fmt.Errorf("BC_SESSION_SECRET is required and must be at least 32 characters")
	}
	// Google is optional (WU-602): any provider will do, and the server warns
	// at startup when none is configured. A half-configured pair is an error.
	if (c.GoogleClientID == "") != (c.GoogleClientSecret == "") {
		return nil, fmt.Errorf("BC_GOOGLE_CLIENT_ID and BC_GOOGLE_CLIENT_SECRET must be set together")
	}
	if (c.GitHubClientID == "") != (c.GitHubClientSecret == "") {
		return nil, fmt.Errorf("BC_GITHUB_CLIENT_ID and BC_GITHUB_CLIENT_SECRET must be set together")
	}
	tp, err := ParseTrustedProxies(os.Getenv("BC_TRUSTED_PROXIES"))
	if err != nil {
		return nil, fmt.Errorf("invalid BC_TRUSTED_PROXIES: %w", err)
	}
	c.TrustedProxies = tp
	oidc, err := loadOIDCProviders(os.Environ())
	if err != nil {
		return nil, err
	}
	c.OIDCProviders = oidc

	return c, nil
}

// ParseTrustedProxies parses a comma- or space-separated list of CIDR
// prefixes or bare addresses (a bare address is a single-host prefix).
func ParseTrustedProxies(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		if strings.Contains(f, "/") {
			p, err := netip.ParsePrefix(f)
			if err != nil {
				return nil, fmt.Errorf("%q: %w", f, err)
			}
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(f)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", f, err)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func intEnvOrDefault(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}
