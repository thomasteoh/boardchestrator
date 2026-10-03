package action

import (
	"errors"
	"testing"
)

func TestNormaliseDomain(t *testing.T) {
	ok := []struct{ in, want string }{
		{"Example.COM", "example.com"},
		{"  example.com.  ", "example.com"},
		{"eng.Example.com", "eng.example.com"},
		{"bücher.example", "xn--bcher-kva.example"},
		{"BÜCHER.example.", "xn--bcher-kva.example"},
		{"xn--bcher-kva.example", "xn--bcher-kva.example"},
		{"münchen.de", "xn--mnchen-3ya.de"},
		{"acme.co.uk", "acme.co.uk"},
		{"corp.internal", "corp.internal"},
	}
	for _, c := range ok {
		got, err := NormaliseDomain(c.in)
		if err != nil || got != c.want {
			t.Errorf("NormaliseDomain(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
	bad := []struct {
		in   string
		want error
	}{
		{"", ErrDomainInvalid},
		{".", ErrDomainInvalid},
		{"localhost", ErrDomainInvalid},
		{"com", ErrDomainInvalid},
		{"com.", ErrDomainInvalid},
		{"co.uk", ErrDomainPublicSuffix},
		{"github.io", ErrDomainPublicSuffix},
		{"192.0.2.10", ErrDomainIP},
		{"192.0.2.10.", ErrDomainIP},
		{"127.1", ErrDomainIP},
		{"::1", ErrDomainIP},
		{"[2001:db8::1]", ErrDomainIP},
		{"2001:db8::1", ErrDomainIP},
		{"bob@example.com", ErrDomainInvalid},
		{"example.com/path", ErrDomainInvalid},
		{"*.example.com", ErrDomainInvalid},
		{"exa mple.com", ErrDomainInvalid},
		{"ex..ample.com", ErrDomainInvalid},
		{"-example.com", ErrDomainInvalid},
		{"_dmarc.example.com", ErrDomainInvalid},
	}
	for _, c := range bad {
		got, err := NormaliseDomain(c.in)
		if !errors.Is(err, c.want) || !errors.Is(err, ErrInvalidInput) {
			t.Errorf("NormaliseDomain(%q) = %q, %v; want %v", c.in, got, err, c.want)
		}
	}
}

func TestEmailDomain(t *testing.T) {
	if d, err := EmailDomain("Alice@Corp.Example."); err != nil || d != "corp.example" {
		t.Fatalf("EmailDomain = %q, %v", d, err)
	}
	for _, e := range []string{"", "alice", "@corp.example", "alice@", "alice@com"} {
		if _, err := EmailDomain(e); err == nil {
			t.Errorf("EmailDomain(%q) accepted", e)
		}
	}
}
