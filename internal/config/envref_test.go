package config

import (
	"strings"
	"testing"
)

// TestEnvReferenceGeneration verifies the BC_* env reference is generated from
// the Config struct by reflection (WU-507 AC: env reference generation test).
func TestEnvReferenceGeneration(t *testing.T) {
	ref := EnvReference()
	if len(ref) == 0 {
		t.Fatal("no env entries generated")
	}

	// Every BC_* env must be present.
	want := map[string]bool{
		"BC_DB_PATH":             true,
		"BC_DATA_DIR":            true,
		"BC_BASE_URL":            true,
		"BC_BIND":                true,
		"BC_SECRET_KEY":          true,
		"BC_SESSION_SECRET":      true,
		"BC_BOOTSTRAP_TOKEN":     true,
		"BC_GOOGLE_CLIENT_ID":    true,
		"BC_AGENT_WORKERS":       true,
		"BC_SCHED_POLL_INTERVAL": true,
	}
	seen := map[string]bool{}
	for _, e := range ref {
		if !strings.HasPrefix(e.Env, "BC_") {
			t.Errorf("env %q lacks BC_ prefix", e.Env)
		}
		seen[e.Env] = true
	}
	for env := range want {
		if !seen[env] {
			t.Errorf("missing env %s", env)
		}
	}

	// Spot-check CamelCase → UPPER_SNAKE mapping.
	if !seen["BC_SCHED_POLL_INTERVAL"] {
		t.Errorf("SchedPollInterval not mapped to BC_SCHED_POLL_INTERVAL")
	}
}
