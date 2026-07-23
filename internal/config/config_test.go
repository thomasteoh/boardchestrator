package config_test

import (
	"os"
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
	os.Setenv("BC_LOG_LEVEL", "trace")
	_, err := config.Load()
	if err == nil {
		t.Fatal("Load() should error on invalid log level")
	}
}

func TestLoadMissingSecretKey(t *testing.T) {
	os.Clearenv()
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

func TestLoadRequiresGoogleClientID(t *testing.T) {
	os.Clearenv()
	os.Setenv("BC_SECRET_KEY", "test-secret-key")
	os.Setenv("BC_SESSION_SECRET", "a-really-long-session-secret-that-is-at-least-thirty-two-chars")
	os.Setenv("BC_GOOGLE_CLIENT_SECRET", "google-client-secret")
	_, err := config.Load()
	if err == nil {
		t.Fatal("Load() should error when BC_GOOGLE_CLIENT_ID is missing")
	}
}

func TestLoadRequiresGoogleClientSecret(t *testing.T) {
	os.Clearenv()
	os.Setenv("BC_SECRET_KEY", "test-secret-key")
	os.Setenv("BC_SESSION_SECRET", "a-really-long-session-secret-that-is-at-least-thirty-two-chars")
	os.Setenv("BC_GOOGLE_CLIENT_ID", "google-client-id")
	_, err := config.Load()
	if err == nil {
		t.Fatal("Load() should error when BC_GOOGLE_CLIENT_SECRET is missing")
	}
}
