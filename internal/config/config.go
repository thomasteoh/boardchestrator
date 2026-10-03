package config

import (
	"fmt"
	"log/slog"
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
	// IdP endpoint overrides. Not loaded from the environment: tests point the
	// env-seeded google/github providers at in-process fakes
	// (internal/auth/oidctest). Empty means the real provider.
	GoogleIssuer      string `env:"-"`
	GitHubWebBase     string `env:"-"`
	GitHubAPIBase     string `env:"-"`
	AgentWorkers      int
	SchedPollInterval int
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
	oidc, err := loadOIDCProviders(os.Environ())
	if err != nil {
		return nil, err
	}
	c.OIDCProviders = oidc

	return c, nil
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
