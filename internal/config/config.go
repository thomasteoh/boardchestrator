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
	GitHubClientID     string
	GitHubClientSecret string
	AgentWorkers       int
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
