package passkey_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/auth/passkey"
	"github.com/thomasteoh/boardchestrator/internal/auth/passkey/passkeytest"
)

const base = "https://boards.example.com"

func newUser(t *testing.T) passkey.User {
	t.Helper()
	h := make([]byte, passkey.HandleLen)
	if _, err := rand.Read(h); err != nil {
		t.Fatal(err)
	}
	return passkey.User{Handle: h, Name: "bob@example.com", DisplayName: "Bob"}
}

// register runs a registration ceremony and returns the stored credential.
func register(t *testing.T, rp *passkey.RP, a *passkeytest.Authenticator, u passkey.User, o passkeytest.Options) (passkey.Credential, error) {
	t.Helper()
	opts, sess, err := rp.BeginRegistration(u)
	if err != nil {
		t.Fatal(err)
	}
	body, _, err := a.Create(opts, rp.Origin(), o)
	if err != nil {
		t.Fatal(err)
	}
	return rp.FinishRegistration(u, sess, body)
}

func TestNewRefusesIPAndBadURL(t *testing.T) {
	for _, u := range []string{"http://127.0.0.1:8080", "https://[::1]", "", "not a url", "ftp://example.com"} {
		if _, err := passkey.New(u); err == nil {
			t.Errorf("New(%q) accepted", u)
		}
	}
	rp, err := passkey.New("https://Boards.Example.com:8443/")
	if err != nil {
		t.Fatal(err)
	}
	if rp.RPID() != "Boards.Example.com" || rp.Origin() != "https://Boards.Example.com:8443" {
		t.Fatalf("rp id %q origin %q", rp.RPID(), rp.Origin())
	}
}

func TestRegisterAndLogin(t *testing.T) {
	rp, err := passkey.New(base)
	if err != nil {
		t.Fatal(err)
	}
	a := passkeytest.New()
	u := newUser(t)
	cred, err := register(t, rp, a, u, passkeytest.Options{})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if !bytes.Equal(cred.AAGUID, passkeytest.AAGUID) || len(cred.ID) == 0 || !cred.UserVerified {
		t.Fatalf("credential %+v", cred)
	}
	u.Credentials = []passkey.Credential{cred}
	lookup := func(rawID, handle []byte) (passkey.User, error) {
		if !bytes.Equal(rawID, cred.ID) {
			return passkey.User{}, passkey.ErrUnknownCredential
		}
		return u, nil
	}
	opts, sess, err := rp.BeginLogin()
	if err != nil {
		t.Fatal(err)
	}
	body, err := a.Get(opts, rp.Origin(), passkeytest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := rp.FinishLogin(sess, body, lookup)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if res.Credential.SignCount != 1 || res.StoredSignCount != 0 || !res.UserVerified {
		t.Fatalf("result %+v", res)
	}

	// Each forgery is refused.
	two := uint32(2)
	for name, o := range map[string]passkeytest.Options{
		"wrong origin":    {Origin: "https://evil.example.com"},
		"wrong rp id":     {RPID: "evil.example.com"},
		"wrong challenge": {Challenge: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		"wrong type":      {Type: "webauthn.create"},
		"no user present": {NoUP: true, SignCount: &two},
		"bad signature":   {BadSignature: true},
		"other handle":    {UserHandle: []byte("someone else")},
	} {
		opts, sess, err := rp.BeginLogin()
		if err != nil {
			t.Fatal(err)
		}
		body, err := a.Get(opts, rp.Origin(), o)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rp.FinishLogin(sess, body, lookup); !errors.Is(err, passkey.ErrVerify) {
			t.Errorf("%s: err = %v, want ErrVerify", name, err)
		}
	}
}

func TestRegistrationForgeriesRefused(t *testing.T) {
	rp, err := passkey.New(base)
	if err != nil {
		t.Fatal(err)
	}
	for name, o := range map[string]passkeytest.Options{
		"wrong origin":    {Origin: "https://evil.example.com"},
		"wrong rp id":     {RPID: "evil.example.com"},
		"wrong challenge": {Challenge: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		"no user present": {NoUP: true},
		"wrong type":      {Type: "webauthn.get"},
	} {
		if _, err := register(t, rp, passkeytest.New(), newUser(t), o); !errors.Is(err, passkey.ErrVerify) {
			t.Errorf("%s: err = %v, want ErrVerify", name, err)
		}
	}
	// A session begun for one user cannot finish for another.
	u, v := newUser(t), newUser(t)
	opts, sess, err := rp.BeginRegistration(u)
	if err != nil {
		t.Fatal(err)
	}
	body, _, err := passkeytest.New().Create(opts, rp.Origin(), passkeytest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rp.FinishRegistration(v, sess, body); !errors.Is(err, passkey.ErrVerify) {
		t.Fatalf("other user: %v", err)
	}
	if _, err := rp.FinishRegistration(u, nil, body); !errors.Is(err, passkey.ErrVerify) {
		t.Fatalf("no session: %v", err)
	}
}

func TestNameForAAGUID(t *testing.T) {
	if got := passkey.NameForAAGUID(passkeytest.AAGUID); got != "iCloud Keychain" {
		t.Fatalf("known AAGUID: %q", got)
	}
	if got := passkey.NameForAAGUID(make([]byte, 16)); got != passkey.DefaultName {
		t.Fatalf("zero AAGUID: %q", got)
	}
	if got := passkey.NameForAAGUID(nil); got != passkey.DefaultName {
		t.Fatalf("no AAGUID: %q", got)
	}
}
