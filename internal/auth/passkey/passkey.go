// Package passkey wraps github.com/go-webauthn/webauthn for Boardchestrator's
// passkeys (SPEC §7.9): one relying party per instance, RP ID = the host of
// BC_BASE_URL and origin = BC_BASE_URL exactly, discoverable credentials
// (usernameless sign-in), user verification preferred and attestation none.
//
// The package is stateless: Begin* return the ceremony's session data as an
// opaque JSON blob, which the caller keeps in the sealed flow cookie (SPEC
// §7.2), and Finish* take it back. Storage, sessions and policy (sign-count
// regression, user verification latch, replay) belong to internal/auth.
package passkey

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
)

// RPName is the relying party name authenticators show.
const RPName = "Boardchestrator"

// CeremonyTimeout is how long the browser may take over a ceremony. It is
// shorter than the flow cookie's lifetime and enforced on finish.
const CeremonyTimeout = 5 * time.Minute

// HandleLen is the size of a WebAuthn user handle (random bytes; never the
// email or the user id).
const HandleLen = 32

// ErrVerify is any ceremony verification failure. The wrapped detail is for
// logs only, never for the client.
var ErrVerify = errors.New("passkey: verification failed")

// RP is the configured relying party.
type RP struct {
	wa     *webauthn.WebAuthn
	rpID   string
	origin string
}

// New builds the relying party for baseURL. It fails when the URL has no
// host or the host cannot be a WebAuthn RP ID (an IP address, for one), in
// which case passkeys are unavailable on the instance.
func New(baseURL string) (*RP, error) {
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("passkey: BC_BASE_URL %q is not an absolute http(s) URL", baseURL)
	}
	host := u.Hostname()
	if err := protocol.ValidateRPID(host); err != nil {
		return nil, fmt.Errorf("passkey: %q cannot be a relying party id: %w", host, err)
	}
	origin := u.Scheme + "://" + u.Host
	wa, err := webauthn.New(&webauthn.Config{
		RPID:                  host,
		RPDisplayName:         RPName,
		RPOrigins:             []string{origin},
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification:   protocol.VerificationPreferred,
		},
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: CeremonyTimeout, TimeoutUVD: CeremonyTimeout},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: CeremonyTimeout, TimeoutUVD: CeremonyTimeout},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("passkey: configure: %w", err)
	}
	return &RP{wa: wa, rpID: host, origin: origin}, nil
}

// RPID is the relying party id (the BC_BASE_URL host).
func (rp *RP) RPID() string { return rp.rpID }

// Origin is the only origin ceremonies are accepted from.
func (rp *RP) Origin() string { return rp.origin }

// Credential is a stored passkey as the ceremonies need it.
type Credential struct {
	ID              []byte
	PublicKey       []byte
	SignCount       uint32
	AAGUID          []byte
	Transports      []string
	AttestationType string
	AttestationFmt  string
	UserVerified    bool
	BackupEligible  bool
	BackupState     bool
}

// User is the account a ceremony is for.
type User struct {
	Handle      []byte
	Name        string // the email: what the authenticator lists the passkey under
	DisplayName string
	Credentials []Credential
}

type waUser struct{ u User }

func (w waUser) WebAuthnID() []byte          { return w.u.Handle }
func (w waUser) WebAuthnName() string        { return w.u.Name }
func (w waUser) WebAuthnDisplayName() string { return w.u.DisplayName }
func (w waUser) WebAuthnCredentials() []webauthn.Credential {
	out := make([]webauthn.Credential, 0, len(w.u.Credentials))
	for _, c := range w.u.Credentials {
		out = append(out, c.toWA())
	}
	return out
}

func (c Credential) toWA() webauthn.Credential {
	flags := protocol.FlagUserPresent
	if c.UserVerified {
		flags |= protocol.FlagUserVerified
	}
	if c.BackupEligible {
		flags |= protocol.FlagBackupEligible
	}
	if c.BackupState {
		flags |= protocol.FlagBackupState
	}
	tr := make([]protocol.AuthenticatorTransport, 0, len(c.Transports))
	for _, t := range c.Transports {
		tr = append(tr, protocol.AuthenticatorTransport(t))
	}
	return webauthn.Credential{
		ID:                c.ID,
		PublicKey:         c.PublicKey,
		AttestationType:   c.AttestationType,
		AttestationFormat: c.AttestationFmt,
		Transport:         tr,
		Flags:             webauthn.NewCredentialFlags(flags),
		Authenticator:     webauthn.Authenticator{AAGUID: c.AAGUID, SignCount: c.SignCount},
	}
}

func fromWA(c *webauthn.Credential) Credential {
	tr := make([]string, 0, len(c.Transport))
	for _, t := range c.Transport {
		tr = append(tr, string(t))
	}
	return Credential{
		ID: c.ID, PublicKey: c.PublicKey, SignCount: c.Authenticator.SignCount,
		AAGUID: c.Authenticator.AAGUID, Transports: tr,
		AttestationType: c.AttestationType, AttestationFmt: c.AttestationFormat,
		UserVerified: c.Flags.UserVerified, BackupEligible: c.Flags.BackupEligible, BackupState: c.Flags.BackupState,
	}
}

// credentialParameters are the algorithms offered: ES256 (every platform
// authenticator), EdDSA and RS256 (Windows Hello). A short list keeps the
// session data, and so the flow cookie, small.
var credentialParameters = []protocol.CredentialParameter{
	{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256},
	{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgEdDSA},
	{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgRS256},
}

// BeginRegistration starts creating a passkey for u. options is the JSON for
// navigator.credentials.create ({"publicKey": ...}); session goes into the
// flow cookie. u's existing credentials are excluded, so an authenticator
// that already holds one says so instead of making a second.
func (rp *RP) BeginRegistration(u User) (options, session []byte, err error) {
	if len(u.Handle) == 0 {
		return nil, nil, errors.New("passkey: user handle required")
	}
	excl := make([]protocol.CredentialDescriptor, 0, len(u.Credentials))
	for _, c := range u.Credentials {
		wc := c.toWA()
		excl = append(excl, wc.Descriptor())
	}
	creation, sd, err := rp.wa.BeginRegistration(waUser{u},
		webauthn.WithCredentialParameters(credentialParameters),
		webauthn.WithExclusions(excl),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("passkey: begin registration: %w", err)
	}
	return marshalPair(creation, sd)
}

// FinishRegistration verifies the browser's attestation response (body, as
// posted) against session and returns the new credential.
func (rp *RP) FinishRegistration(u User, session, body []byte) (Credential, error) {
	sd, err := unmarshalSession(session)
	if err != nil {
		return Credential{}, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(body)
	if err != nil {
		return Credential{}, fmt.Errorf("%w: parse attestation: %w", ErrVerify, err)
	}
	c, err := rp.wa.CreateCredential(waUser{u}, sd, parsed)
	if err != nil {
		return Credential{}, fmt.Errorf("%w: %w", ErrVerify, detail(err))
	}
	return fromWA(c), nil
}

// BeginLogin starts a usernameless (discoverable credential) sign-in.
func (rp *RP) BeginLogin() (options, session []byte, err error) {
	assertion, sd, err := rp.wa.BeginDiscoverableLogin(
		webauthn.WithUserVerification(protocol.VerificationPreferred),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("passkey: begin login: %w", err)
	}
	return marshalPair(assertion, sd)
}

// Lookup finds the stored credential the authenticator chose (rawID) and its
// owner. userHandle is what the authenticator returned; the library checks
// it equals the owner's handle.
type Lookup func(rawID, userHandle []byte) (User, error)

// LoginResult is a verified assertion.
type LoginResult struct {
	User User
	// Credential is the stored record advanced by this assertion: the new
	// sign count, the backup state, the user verification latch.
	Credential Credential
	// StoredSignCount is the count the record held before this assertion.
	StoredSignCount uint32
	// UserVerified is this ceremony's own UV flag.
	UserVerified bool
}

// ErrUnknownCredential is a credential id that no stored passkey has.
var ErrUnknownCredential = errors.New("passkey: unknown credential")

// FinishLogin verifies an assertion response against session: client data
// type, challenge and origin, the RP ID hash, user presence, the signature
// with the stored public key and the user handle. Policy beyond that (sign
// count, user verification latch) is the caller's.
func (rp *RP) FinishLogin(session, body []byte, lookup Lookup) (*LoginResult, error) {
	sd, err := unmarshalSession(session)
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		return nil, fmt.Errorf("%w: parse assertion: %w", ErrVerify, err)
	}
	var found User
	var stored uint32
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		u, err := lookup(rawID, userHandle)
		if err != nil {
			return nil, err
		}
		for _, c := range u.Credentials {
			if bytes.Equal(c.ID, rawID) {
				stored = c.SignCount
			}
		}
		found = u
		return waUser{u}, nil
	}
	_, c, err := rp.wa.ValidatePasskeyLogin(handler, sd, parsed)
	if err != nil {
		if errors.Is(err, ErrUnknownCredential) {
			return nil, ErrUnknownCredential
		}
		return nil, fmt.Errorf("%w: %w", ErrVerify, detail(err))
	}
	return &LoginResult{
		User:            found,
		Credential:      fromWA(c),
		StoredSignCount: stored,
		UserVerified:    parsed.Response.AuthenticatorData.Flags.HasUserVerified(),
	}, nil
}

// Challenge is the ceremony challenge in session (for single-use tracking).
func Challenge(session []byte) (string, error) {
	sd, err := unmarshalSession(session)
	if err != nil {
		return "", err
	}
	return sd.Challenge, nil
}

// SessionUserHandle is the user handle a registration session was begun for.
func SessionUserHandle(session []byte) ([]byte, error) {
	sd, err := unmarshalSession(session)
	if err != nil {
		return nil, err
	}
	return sd.UserID, nil
}

func marshalPair(options any, sd *webauthn.SessionData) ([]byte, []byte, error) {
	o, err := json.Marshal(options)
	if err != nil {
		return nil, nil, fmt.Errorf("passkey: marshal options: %w", err)
	}
	s, err := json.Marshal(sd)
	if err != nil {
		return nil, nil, fmt.Errorf("passkey: marshal session: %w", err)
	}
	return o, s, nil
}

func unmarshalSession(b []byte) (webauthn.SessionData, error) {
	var sd webauthn.SessionData
	if len(b) == 0 {
		return sd, fmt.Errorf("%w: no ceremony in progress", ErrVerify)
	}
	if err := json.Unmarshal(b, &sd); err != nil || sd.Challenge == "" {
		return sd, fmt.Errorf("%w: ceremony state unreadable", ErrVerify)
	}
	return sd, nil
}

// detail adds the protocol error's developer detail for the log.
func detail(err error) error {
	var pe *protocol.Error
	if errors.As(err, &pe) && pe.DevInfo != "" {
		return fmt.Errorf("%w (%s)", err, pe.DevInfo)
	}
	return err
}
