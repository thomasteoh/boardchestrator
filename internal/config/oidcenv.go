package config

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// OIDCEnvProvider is one provider configured by the BC_OIDC_<NAME>_* family
// (SPEC s7.1). ID is <NAME> lower-cased with '_' mapped to '-'. Optional
// booleans are nil when unset so the preset default applies.
type OIDCEnvProvider struct {
	ID           string
	Issuer       string
	ClientID     string
	ClientSecret string
	Preset       string // "" = generic
	DisplayName  string
	TrustEmail   *bool
	AllowSignup  *bool
	Scopes       []string // nil = preset default
	GroupsClaim  string   // "" = preset default
}

// OIDCEnvSuffixes are the recognised BC_OIDC_<NAME>_ suffixes, longest first
// so that a NAME ending in e.g. _CLIENT is not mistaken for part of a suffix.
var OIDCEnvSuffixes = []string{
	"CLIENT_SECRET", "DISPLAY_NAME", "GROUPS_CLAIM", "ALLOW_SIGNUP", "TRUST_EMAIL",
	"CLIENT_ID", "ISSUER", "PRESET", "SCOPES",
}

const oidcEnvPrefix = "BC_OIDC_"

var providerIDRe = regexp.MustCompile(`^[a-z0-9-]+$`)

// loadOIDCProviders parses BC_OIDC_<NAME>_* entries from environ ("K=V").
// Unknown suffixes are an error (a typo would otherwise silently drop a
// setting), as is a provider without a client id.
func loadOIDCProviders(environ []string) ([]OIDCEnvProvider, error) {
	byID := map[string]*OIDCEnvProvider{}
	for _, kv := range environ {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || !strings.HasPrefix(k, oidcEnvPrefix) || v == "" {
			continue
		}
		rest := strings.TrimPrefix(k, oidcEnvPrefix)
		var name, suffix string
		for _, s := range OIDCEnvSuffixes {
			if strings.HasSuffix(rest, "_"+s) && len(rest) > len(s)+1 {
				name, suffix = strings.TrimSuffix(rest, "_"+s), s
				break
			}
		}
		if suffix == "" {
			return nil, fmt.Errorf("%s: unknown BC_OIDC_ variable (want BC_OIDC_<NAME>_{%s})", k, strings.Join(OIDCEnvSuffixes, ","))
		}
		id := strings.ReplaceAll(strings.ToLower(name), "_", "-")
		if !providerIDRe.MatchString(id) {
			return nil, fmt.Errorf("%s: provider name must be letters, digits and underscores", k)
		}
		p := byID[id]
		if p == nil {
			p = &OIDCEnvProvider{ID: id}
			byID[id] = p
		}
		switch suffix {
		case "ISSUER":
			p.Issuer = v
		case "CLIENT_ID":
			p.ClientID = v
		case "CLIENT_SECRET":
			p.ClientSecret = v
		case "PRESET":
			p.Preset = strings.ToLower(v)
		case "DISPLAY_NAME":
			p.DisplayName = v
		case "SCOPES":
			p.Scopes = strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' })
		case "GROUPS_CLAIM":
			p.GroupsClaim = v
		case "TRUST_EMAIL", "ALLOW_SIGNUP":
			b, err := strconv.ParseBool(v)
			if err != nil {
				return nil, fmt.Errorf("%s: want true or false", k)
			}
			if suffix == "TRUST_EMAIL" {
				p.TrustEmail = &b
			} else {
				p.AllowSignup = &b
			}
		}
	}
	out := make([]OIDCEnvProvider, 0, len(byID))
	for _, p := range byID {
		if p.ClientID == "" {
			return nil, fmt.Errorf("BC_OIDC_%s_CLIENT_ID is required", envName(p.ID))
		}
		if p.ID == "google" || p.ID == "github" {
			return nil, fmt.Errorf("BC_OIDC_%s_*: id %q is reserved; use BC_%s_CLIENT_ID", envName(p.ID), p.ID, envName(p.ID))
		}
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func envName(id string) string { return strings.ToUpper(strings.ReplaceAll(id, "-", "_")) }
