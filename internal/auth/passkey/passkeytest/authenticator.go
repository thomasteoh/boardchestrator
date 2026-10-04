// Package passkeytest is a software WebAuthn authenticator for tests: ECDSA
// P-256 credentials, "none" attestation, discoverable credentials, and
// switches to produce the malformed or hostile responses a relying party
// must refuse. It plays both the authenticator and the browser: it reads the
// options JSON a begin endpoint returns and produces the JSON a browser
// would post to the finish endpoint.
package passkeytest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

// Authenticator flag bits (WebAuthn §6.1).
const (
	flagUP = 0x01
	flagUV = 0x04
	flagBE = 0x08
	flagBS = 0x10
	flagAT = 0x40
)

// AAGUID is the authenticator model id the authenticator reports by default
// (iCloud Keychain's, so the relying party's name map has something to find).
var AAGUID = []byte{0xfb, 0xfc, 0x30, 0x07, 0x15, 0x4e, 0x4e, 0xcc, 0x8c, 0x0b, 0x6e, 0x02, 0x05, 0x57, 0xd7, 0xbd}

// Credential is a passkey the authenticator holds.
type Credential struct {
	ID         []byte
	RPID       string
	UserHandle []byte
	Key        *ecdsa.PrivateKey
	SignCount  uint32
}

// Authenticator holds discoverable credentials.
type Authenticator struct {
	mu    sync.Mutex
	creds []*Credential
	// AAGUID reported at registration (default AAGUID).
	AAGUID []byte
	// Synced sets the backup eligible and backup state flags.
	Synced bool
	// CountStep is added to a credential's sign count at every assertion
	// (0 = the counter stays 0, as synced passkeys do).
	CountStep uint32
}

// New returns an empty authenticator with a counter that increments.
func New() *Authenticator {
	return &Authenticator{AAGUID: AAGUID, CountStep: 1}
}

// Options alter one response, to forge what a hostile client could send.
type Options struct {
	// Origin overrides the client data origin (default: the origin passed in).
	Origin string
	// RPID overrides the relying party id whose hash goes into the
	// authenticator data (default: the options' RP id).
	RPID string
	// Challenge overrides the client data challenge (base64url).
	Challenge string
	// Type overrides the client data type.
	Type string
	// NoUP clears the user present flag; NoUV the user verified flag.
	NoUP, NoUV bool
	// SignCount, when set, is reported instead of the credential's next count.
	SignCount *uint32
	// Credential picks the credential to assert with (default: the newest
	// for the RP id).
	Credential *Credential
	// UserHandle overrides the user handle in an assertion.
	UserHandle []byte
	// BadSignature corrupts the assertion signature.
	BadSignature bool
}

var b64 = base64.RawURLEncoding

type creationOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RP        struct {
			ID string `json:"id"`
		} `json:"rp"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	} `json:"publicKey"`
}

type requestOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RPID      string `json:"rpId"`
	} `json:"publicKey"`
}

// Credentials returns the held credentials, oldest first.
func (a *Authenticator) Credentials() []*Credential {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]*Credential(nil), a.creds...)
}

// Create answers navigator.credentials.create(options) at origin and returns
// the JSON body a browser posts to the finish endpoint.
func (a *Authenticator) Create(options []byte, origin string, o Options) ([]byte, *Credential, error) {
	var opts creationOptions
	if err := json.Unmarshal(options, &opts); err != nil {
		return nil, nil, fmt.Errorf("passkeytest: creation options: %w", err)
	}
	pk := opts.PublicKey
	if pk.Challenge == "" || pk.RP.ID == "" || pk.User.ID == "" {
		return nil, nil, errors.New("passkeytest: creation options incomplete")
	}
	handle, err := b64.DecodeString(pk.User.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("passkeytest: user id: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		return nil, nil, err
	}
	cred := &Credential{ID: id, RPID: pk.RP.ID, UserHandle: handle, Key: key}
	clientData, err := clientDataJSON(firstNonEmpty(o.Type, "webauthn.create"), firstNonEmpty(o.Challenge, pk.Challenge), firstNonEmpty(o.Origin, origin))
	if err != nil {
		return nil, nil, err
	}
	cose, err := coseKey(&key.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	att := make([]byte, 0, 16+2+len(id)+len(cose))
	att = append(att, a.aaguid()...)
	att = binary.BigEndian.AppendUint16(att, uint16(len(id))) //nolint:gosec // G115: id is 32 bytes
	att = append(att, id...)
	att = append(att, cose...)
	authData := a.authData(firstNonEmpty(o.RPID, pk.RP.ID), o, flagAT, 0)
	authData = append(authData, att...)
	attObj, err := webauthncbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": authData,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("passkeytest: attestation object: %w", err)
	}
	body, err := json.Marshal(map[string]any{
		"id":    b64.EncodeToString(id),
		"rawId": b64.EncodeToString(id),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(clientData),
			"attestationObject": b64.EncodeToString(attObj),
			"transports":        []string{"internal", "hybrid"},
		},
		"clientExtensionResults":  map[string]any{},
		"authenticatorAttachment": "platform",
	})
	if err != nil {
		return nil, nil, err
	}
	a.mu.Lock()
	a.creds = append(a.creds, cred)
	a.mu.Unlock()
	return body, cred, nil
}

// Get answers navigator.credentials.get(options) at origin with a
// discoverable credential for the options' RP id and returns the JSON body a
// browser posts to the finish endpoint.
func (a *Authenticator) Get(options []byte, origin string, o Options) ([]byte, error) {
	var opts requestOptions
	if err := json.Unmarshal(options, &opts); err != nil {
		return nil, fmt.Errorf("passkeytest: request options: %w", err)
	}
	pk := opts.PublicKey
	if pk.Challenge == "" || pk.RPID == "" {
		return nil, errors.New("passkeytest: request options incomplete")
	}
	cred := o.Credential
	a.mu.Lock()
	if cred == nil {
		for i := len(a.creds) - 1; i >= 0; i-- {
			if a.creds[i].RPID == pk.RPID {
				cred = a.creds[i]
				break
			}
		}
	}
	if cred == nil {
		a.mu.Unlock()
		return nil, errors.New("passkeytest: no credential for " + pk.RPID)
	}
	cred.SignCount += a.CountStep
	count := cred.SignCount
	a.mu.Unlock()
	if o.SignCount != nil {
		count = *o.SignCount
	}
	clientData, err := clientDataJSON(firstNonEmpty(o.Type, "webauthn.get"), firstNonEmpty(o.Challenge, pk.Challenge), firstNonEmpty(o.Origin, origin))
	if err != nil {
		return nil, err
	}
	authData := a.authData(firstNonEmpty(o.RPID, pk.RPID), o, 0, count)
	sum := sha256.Sum256(clientData)
	signed := append(append([]byte(nil), authData...), sum[:]...)
	digest := sha256.Sum256(signed)
	sig, err := ecdsa.SignASN1(rand.Reader, cred.Key, digest[:])
	if err != nil {
		return nil, err
	}
	if o.BadSignature {
		digest[0] ^= 0xff
		if sig, err = ecdsa.SignASN1(rand.Reader, cred.Key, digest[:]); err != nil {
			return nil, err
		}
	}
	handle := cred.UserHandle
	if o.UserHandle != nil {
		handle = o.UserHandle
	}
	return json.Marshal(map[string]any{
		"id":    b64.EncodeToString(cred.ID),
		"rawId": b64.EncodeToString(cred.ID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(clientData),
			"authenticatorData": b64.EncodeToString(authData),
			"signature":         b64.EncodeToString(sig),
			"userHandle":        b64.EncodeToString(handle),
		},
		"clientExtensionResults":  map[string]any{},
		"authenticatorAttachment": "platform",
	})
}

func (a *Authenticator) aaguid() []byte {
	if len(a.AAGUID) == 16 {
		return a.AAGUID
	}
	return make([]byte, 16)
}

func (a *Authenticator) authData(rpID string, o Options, extra byte, count uint32) []byte {
	h := sha256.Sum256([]byte(rpID))
	flags := extra | flagUP | flagUV
	if o.NoUP {
		flags &^= flagUP
	}
	if o.NoUV {
		flags &^= flagUV
	}
	if a.Synced {
		flags |= flagBE | flagBS
	}
	out := append([]byte(nil), h[:]...)
	out = append(out, flags)
	return binary.BigEndian.AppendUint32(out, count)
}

func clientDataJSON(typ, challenge, origin string) ([]byte, error) {
	return json.Marshal(map[string]any{
		"type": typ, "challenge": challenge, "origin": origin, "crossOrigin": false,
	})
}

// coseKey encodes an EC2 P-256 public key for ES256 (RFC 9053).
func coseKey(pub *ecdsa.PublicKey) ([]byte, error) {
	raw, err := pub.Bytes() // uncompressed point 0x04 || X || Y
	if err != nil {
		return nil, err
	}
	x, y := raw[1:33], raw[33:65]
	return webauthncbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
