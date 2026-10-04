package scim

import (
	"errors"
	"testing"
)

func testUser() map[string]any {
	return map[string]any{
		"schemas":     []any{SchemaUser},
		"id":          "abc123",
		"externalId":  "Ext-1",
		"userName":    "Alice@Corp.Example",
		"displayName": "Alice Smith",
		"active":      true,
		"name":        map[string]any{"givenName": "Alice", "familyName": "Smith"},
		"emails": []any{
			map[string]any{"value": "alice@corp.example", "type": "work", "primary": true},
			map[string]any{"value": "alice@home.example", "type": "home"},
		},
	}
}

func TestFilterMatch(t *testing.T) {
	u := testUser()
	for _, c := range []struct {
		filter string
		want   bool
	}{
		{`userName eq "alice@corp.example"`, true}, // userName is case-insensitive
		{`USERNAME EQ "ALICE@CORP.EXAMPLE"`, true}, // attribute and operator too
		{`userName eq "bob@corp.example"`, false},
		{`userName eq "5e0a8c7f-3b1d-4e6a-9f2c-1d2e3f4a5b6c"`, false}, // Entra's startup probe
		{`urn:ietf:params:scim:schemas:core:2.0:User:userName eq "alice@corp.example"`, true},
		{`externalId eq "Ext-1"`, true},
		{`externalId eq "ext-1"`, false}, // externalId is caseExact
		{`id eq "abc123"`, true},
		{`id eq "ABC123"`, false},
		{`emails[type eq "work"].value eq "alice@corp.example"`, true},
		{`emails[type eq "work"].value eq "alice@home.example"`, false},
		{`emails[type eq "home"].value eq "alice@home.example"`, true},
		{`emails.value eq "ALICE@HOME.EXAMPLE"`, true},
		{`emails[type eq "work"]`, true},
		{`emails[type eq "other"]`, false},
		{`emails[type eq "work" and primary eq true]`, true},
		{`name.givenName eq "alice"`, true},
		{`active eq true`, true},
		{`active eq false`, false},
		{`userName eq "alice@corp.example" and externalId eq "Ext-1"`, true},
		{`userName eq "alice@corp.example" and externalId eq "nope"`, false},
		{`(userName eq "alice@corp.example") and (id eq "abc123")`, true},
		{`title pr`, false},
		{`displayName pr`, true},
		{`userName eq "say \"hi\""`, false},
		{`nickName eq "x"`, false}, // unknown attributes simply never match
	} {
		f, err := ParseFilter(c.filter)
		if err != nil {
			t.Errorf("ParseFilter(%s): %v", c.filter, err)
			continue
		}
		if got := f.Match(u); got != c.want {
			t.Errorf("%s: match = %v, want %v", c.filter, got, c.want)
		}
	}
}

func TestFilterGroupMembers(t *testing.T) {
	g := map[string]any{
		"id": "g1", "displayName": "Engineering",
		"members": []any{map[string]any{"value": "u1"}, map[string]any{"value": "u2"}},
	}
	for _, c := range []struct {
		filter string
		want   bool
	}{
		{`displayName eq "engineering"`, true},
		{`members[value eq "u2"]`, true},
		{`members.value eq "u3"`, false},
		{`id eq "g1" and members[value eq "u1"]`, true},
	} {
		f, err := ParseFilter(c.filter)
		if err != nil {
			t.Fatalf("%s: %v", c.filter, err)
		}
		if got := f.Match(g); got != c.want {
			t.Errorf("%s: %v, want %v", c.filter, got, c.want)
		}
	}
}

func TestFilterInvalid(t *testing.T) {
	for _, f := range []string{
		``,
		`   `,
		`userName`,
		`userName eq`,
		`userName eq "unterminated`,
		`userName ne "x"`,
		`userName co "x"`,
		`userName sw "x"`,
		`userName gt "x"`,
		`userName eq "a" or userName eq "b"`,
		`not (userName eq "a")`,
		`userName eq "a" and`,
		`userName xx "a"`,
		`(userName eq "a"`,
		`emails[type eq "work".value eq "x"`,
		`emails[type eq "work"]. eq "x"`,
		`userName eq "a" garbage`,
		`userName eq 'single'`,
		`a.b.c eq "x"`,
		`urn:example:ext:attr eq "x"`,
		`userName eq "a" ; drop`,
		`((((((((((userName eq "a"))))))))))`,
	} {
		_, err := ParseFilter(f)
		if !errors.Is(err, errInvalidFilter) {
			t.Errorf("ParseFilter(%q) = %v, want invalid filter", f, err)
		}
	}
}

func TestParsePath(t *testing.T) {
	for _, c := range []struct {
		in      string
		path    string
		sub     bool
		subAttr string
	}{
		{`active`, "active", false, ""},
		{`name.givenName`, "name.givenname", false, ""},
		{`emails[type eq "work"].value`, "emails", true, "value"},
		{`members[value eq "u1"]`, "members", true, ""},
		{`urn:ietf:params:scim:schemas:core:2.0:User:displayName`, "displayname", false, ""},
	} {
		got, err := ParsePath(c.in)
		if err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		p := got.Path[0]
		if len(got.Path) == 2 {
			p += "." + got.Path[1]
		}
		if p != c.path || (got.Sub != nil) != c.sub || got.SubAttr != c.subAttr {
			t.Errorf("%s: %+v", c.in, got)
		}
	}
	for _, bad := range []string{``, `emails[type eq "work"`, `active extra`, `a.b.c`} {
		if _, err := ParsePath(bad); err == nil {
			t.Errorf("ParsePath(%q) accepted", bad)
		}
	}
	if !isExtensionPath("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department") ||
		isExtensionPath("urn:ietf:params:scim:schemas:core:2.0:User:userName") || isExtensionPath("active") {
		t.Error("isExtensionPath")
	}
}

func TestBooleanQuirks(t *testing.T) {
	for in, want := range map[any]bool{true: true, false: false, "False": false, "TRUE": true, "false": false} {
		got, err := boolean(in, "active")
		if err != nil || got != want {
			t.Errorf("boolean(%v) = %v, %v", in, got, err)
		}
	}
	for _, bad := range []any{"no", 1, nil} {
		if _, err := boolean(bad, "active"); err == nil {
			t.Errorf("boolean(%v) accepted", bad)
		}
	}
}
