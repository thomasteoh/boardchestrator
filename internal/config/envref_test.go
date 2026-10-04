package config

import (
	"os"
	"regexp"
	"sort"
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
		"BC_DB_PATH":               true,
		"BC_DATA_DIR":              true,
		"BC_BASE_URL":              true,
		"BC_BIND":                  true,
		"BC_LOG_LEVEL":             true,
		"BC_ADMIN_EMAILS":          true,
		"BC_GOOGLE_CLIENT_SECRET":  true,
		"BC_GITHUB_CLIENT_SECRET":  true,
		"BC_SECRET_KEY":            true,
		"BC_SESSION_SECRET":        true,
		"BC_BOOTSTRAP_TOKEN":       true,
		"BC_GOOGLE_CLIENT_ID":      true,
		"BC_GITHUB_CLIENT_ID":      true,
		"BC_AGENT_WORKERS":         true,
		"BC_SCHED_POLL_INTERVAL":   true,
		"BC_ALLOW_SIGNUP":          true, // WU-604
		"BC_TRUSTED_PROXIES":       true, // WU-605
		"BC_ORG_IDP_ALLOW_PRIVATE": true, // WU-607
		// WU-602: the per-provider OIDC family, documented per suffix.
		"BC_OIDC_<NAME>_ISSUER":        true,
		"BC_OIDC_<NAME>_CLIENT_ID":     true,
		"BC_OIDC_<NAME>_CLIENT_SECRET": true,
		"BC_OIDC_<NAME>_PRESET":        true,
		"BC_OIDC_<NAME>_DISPLAY_NAME":  true,
		"BC_OIDC_<NAME>_TRUST_EMAIL":   true,
		"BC_OIDC_<NAME>_ALLOW_SIGNUP":  true,
		"BC_OIDC_<NAME>_SCOPES":        true,
		"BC_OIDC_<NAME>_GROUPS_CLAIM":  true,
	}
	seen := map[string]bool{}
	for _, e := range ref {
		if !strings.HasPrefix(e.Env, "BC_") {
			t.Errorf("env %q lacks BC_ prefix", e.Env)
		}
		if seen[e.Env] {
			t.Errorf("env %s listed twice", e.Env)
		}
		seen[e.Env] = true
	}
	for env := range want {
		if !seen[env] {
			t.Errorf("missing env %s", env)
		}
	}

	// Test-only overrides are not environment variables.
	// Parsed forms of other fields are not variables either (WU-614: the
	// reference used to list BC_LOG_LEVEL_STR and BC_ADMIN_EMAILS_STR).
	for _, notEnv := range []string{"BC_GOOGLE_ISSUER", "BC_GIT_HUB_WEB_BASE", "BC_GIT_HUB_API_BASE", "BC_OIDC_PROVIDERS",
		"BC_LOG_LEVEL_STR", "BC_ADMIN_EMAILS_STR", "BC_SIGN_IN_RATE_LIMIT", "BC_SCIM_RATE_LIMIT"} {
		if seen[notEnv] {
			t.Errorf("%s listed but is not loaded from the environment", notEnv)
		}
	}

	// Spot-check CamelCase → UPPER_SNAKE mapping.
	if !seen["BC_SCHED_POLL_INTERVAL"] {
		t.Errorf("SchedPollInterval not mapped to BC_SCHED_POLL_INTERVAL")
	}
}

// TestEnvReferenceDocs keeps the environment tables in DEPLOY.md and the
// public deployment page in step with EnvReference (WU-614): every variable
// the server reads is documented, and nothing documented is unknown.
func TestEnvReferenceDocs(t *testing.T) {
	want := map[string]bool{}
	for _, e := range EnvReference() {
		want[e.Env] = true
	}
	row := regexp.MustCompile("(?m)^\\| `(BC_[A-Z0-9_<>]+)` \\|")
	for _, doc := range []string{"../../DEPLOY.md", "../../website/content/deployment.md"} {
		b, err := os.ReadFile(doc)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]bool{}
		for _, m := range row.FindAllStringSubmatch(string(b), -1) {
			got[m[1]] = true
		}
		var missing, extra []string
		for e := range want {
			if !got[e] {
				missing = append(missing, e)
			}
		}
		for e := range got {
			if !want[e] {
				extra = append(extra, e)
			}
		}
		sort.Strings(missing)
		sort.Strings(extra)
		if len(missing) > 0 || len(extra) > 0 {
			t.Errorf("%s env table out of date: missing %v, not in config %v", doc, missing, extra)
		}
		if !strings.Contains(string(b), "BC_OIDC_<NAME>_") || !strings.Contains(string(b), "lower-cased") {
			t.Errorf("%s does not explain the BC_OIDC_<NAME>_* naming", doc)
		}
	}
}
