package auth_test

import (
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/auth"
)

func TestCSRFTokenDeterministicPerSession(t *testing.T) {
	a := auth.CSRFToken("secret", "hash-a")
	b := auth.CSRFToken("secret", "hash-a")
	if a != b {
		t.Error("CSRFToken not deterministic for same session")
	}
	if auth.CSRFToken("secret", "hash-b") == a {
		t.Error("CSRFToken collides across sessions")
	}
	if auth.CSRFToken("other-secret", "hash-a") == a {
		t.Error("CSRFToken independent of secret")
	}
}

func TestValidCSRF(t *testing.T) {
	const secret, hash = "secret", "session-hash"
	tok := auth.CSRFToken(secret, hash)

	if !auth.ValidCSRF(secret, hash, tok) {
		t.Error("valid token rejected")
	}
	if auth.ValidCSRF(secret, hash, "") {
		t.Error("empty token accepted")
	}
	if auth.ValidCSRF(secret, hash, "wrong") {
		t.Error("wrong token accepted")
	}
	// A token minted for a different session must not validate.
	other := auth.CSRFToken(secret, "different-hash")
	if auth.ValidCSRF(secret, hash, other) {
		t.Error("cross-session token accepted")
	}
}
