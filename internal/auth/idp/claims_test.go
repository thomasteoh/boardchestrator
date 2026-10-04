package idp

import (
	"encoding/json"
	"reflect"
	"testing"
)

func decode(t *testing.T, s string) map[string]any {
	t.Helper()
	m := map[string]any{}
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestClaimGroupsShapes(t *testing.T) {
	claims := decode(t, `{
		"groups": ["eng", "ops", "eng", ""],
		"role": "admin",
		"ids": [7, "x"],
		"urn:zitadel:iam:org:project:roles": {"owner": {"123": "example.com"}, "editor": {"123": "example.com"}},
		"realm_access": {"roles": ["realm-admin"]},
		"https://example.com/claims": {"teams": ["blue"]},
		"https://example.com/groups": ["namespaced"],
		"empty": [],
		"num": 3
	}`)
	for path, want := range map[string][]string{
		"groups":                            {"eng", "ops"},
		"role":                              {"admin"},
		"ids":                               {"7", "x"},
		"urn:zitadel:iam:org:project:roles": {"editor", "owner"},
		"realm_access.roles":                {"realm-admin"},
		"https://example.com/claims.teams":  {"blue"},
		"https://example.com/groups":        {"namespaced"},
		"empty":                             nil,
		"missing":                           nil,
		"realm_access.missing":              nil,
		"num":                               nil,
	} {
		if got := ClaimGroups(claims, path); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got %v, want %v", path, got, want)
		}
	}
}

func TestClaimScalars(t *testing.T) {
	claims := decode(t, `{"email": "a@example.com", "ev": "true", "evb": true, "evf": "false",
		"profile": {"display": {"name": "Ada"}}, "n": 42}`)
	if got := claimString(claims, "profile.display.name"); got != "Ada" {
		t.Errorf("nested name = %q", got)
	}
	if got := claimString(claims, "n"); got != "42" {
		t.Errorf("number = %q", got)
	}
	if got := claimString(claims, ""); got != "" {
		t.Errorf("empty path = %q", got)
	}
	if !claimBool(claims, "ev") || !claimBool(claims, "evb") || claimBool(claims, "evf") || claimBool(claims, "missing") {
		t.Error("claimBool")
	}
}

func TestClaimMapOverlay(t *testing.T) {
	base := standardClaims
	got, err := base.Overlay(`{"groups": "realm_access.roles", "email_verified": ""}`)
	if err != nil {
		t.Fatal(err)
	}
	want := ClaimMap{Email: "email", Name: "name", Picture: "picture", Groups: "realm_access.roles"}
	if got != want {
		t.Errorf("overlay = %+v", got)
	}
	if got, err := base.Overlay(""); err != nil || got != base {
		t.Errorf("empty overlay = %+v %v", got, err)
	}
	if _, err := base.Overlay(`{"grups": "x"}`); err == nil {
		t.Error("unknown field accepted")
	}
	if _, err := base.Overlay(`not json`); err == nil {
		t.Error("bad JSON accepted")
	}
}
