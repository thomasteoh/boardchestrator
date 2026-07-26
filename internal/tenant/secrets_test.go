package tenant

import (
	"crypto/rand"
	"testing"
)

func makeKey() []byte {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return key
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := makeKey()
	plaintext := "super secret value"

	ciphertext, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	decrypted, err := Decrypt(key, ciphertext)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if decrypted != plaintext {
		t.Fatalf("round-trip mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptDifferentCiphertext(t *testing.T) {
	key := makeKey()
	plaintext := "same secret"

	c1, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	if c1 == c2 {
		t.Fatal("expected different ciphertexts (nonce should differ)")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	key1 := makeKey()
	key2 := makeKey()

	ciphertext, err := Encrypt(key1, "secret")
	if err != nil {
		t.Fatal(err)
	}

	_, err = Decrypt(key2, ciphertext)
	if err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}
}

func TestDecryptTamperedCiphertext(t *testing.T) {
	key := makeKey()

	ciphertext, err := Encrypt(key, "secret")
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with the ciphertext
	b := []byte(ciphertext)
	b[len(b)-1] ^= 0xFF
	_, err = Decrypt(key, string(b))
	if err == nil {
		t.Fatal("expected error decrypting tampered ciphertext")
	}
}

func TestInvalidKeyLength(t *testing.T) {
	shortKey := []byte("tooshort")
	_, err := Encrypt(shortKey, "data")
	if err == nil {
		t.Fatal("expected error for short key in Encrypt")
	}

	_, err = Decrypt(shortKey, "YWJj")
	if err == nil {
		t.Fatal("expected error for short key in Decrypt")
	}
}

func TestPadKey(t *testing.T) {
	// Short key gets zero-padded to 32 bytes.
	short := PadKey("abc")
	if len(short) != 32 {
		t.Fatalf("PadKey short: got len %d, want 32", len(short))
	}
	if string(short[:3]) != "abc" {
		t.Fatal("PadKey short: prefix mismatch")
	}

	// Long key gets truncated to 32 bytes.
	long := make([]byte, 64)
	for i := range long {
		long[i] = byte(i)
	}
	result := PadKey(string(long))
	if len(result) != 32 {
		t.Fatalf("PadKey long: got len %d, want 32", len(result))
	}
}
