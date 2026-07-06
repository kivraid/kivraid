package secrets

import (
	"bytes"
	"testing"
)

const testSecretKey = "0123456789abcdef0123456789abcdef"

func TestSealOpenRoundTrip(t *testing.T) {
	key := DeriveKey(testSecretKey, "unit-test")
	for _, plaintext := range [][]byte{
		[]byte("hello"),
		{},
		bytes.Repeat([]byte{0xAB}, 4096),
	} {
		sealed, err := Seal(key, plaintext)
		if err != nil {
			t.Fatalf("Seal(%d bytes): %v", len(plaintext), err)
		}
		opened, err := Open(key, sealed)
		if err != nil {
			t.Fatalf("Open(%d bytes): %v", len(plaintext), err)
		}
		if !bytes.Equal(opened, plaintext) {
			t.Fatalf("round trip mismatch for %d-byte plaintext", len(plaintext))
		}
	}
}

func TestSealUsesFreshNonces(t *testing.T) {
	key := DeriveKey(testSecretKey, "unit-test")
	a, err := Seal(key, []byte("same plaintext"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Seal(key, []byte("same plaintext"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two Seal calls produced identical output: nonce reuse")
	}
}

func TestOpenRejectsTampering(t *testing.T) {
	key := DeriveKey(testSecretKey, "unit-test")
	sealed, err := Seal(key, []byte("attack at dawn"))
	if err != nil {
		t.Fatal(err)
	}
	// Flipping any single bit must fail authentication.
	for i := range sealed {
		tampered := bytes.Clone(sealed)
		tampered[i] ^= 0x01
		if _, err := Open(key, tampered); err == nil {
			t.Fatalf("tampered byte %d was accepted", i)
		}
	}
	// Truncated and empty inputs are rejected, not panics.
	if _, err := Open(key, sealed[:5]); err == nil {
		t.Fatal("truncated input was accepted")
	}
	if _, err := Open(key, nil); err == nil {
		t.Fatal("nil input was accepted")
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	sealed, err := Seal(DeriveKey(testSecretKey, "unit-test"), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(DeriveKey("another-secret-key-another-key!!", "unit-test"), sealed); err == nil {
		t.Fatal("wrong secret_key was accepted")
	}
	if _, err := Open(DeriveKey(testSecretKey, "other-purpose"), sealed); err == nil {
		t.Fatal("wrong purpose subkey was accepted")
	}
}

func TestDeriveKeyIsolatesPurposes(t *testing.T) {
	a := DeriveKey(testSecretKey, "totp-secrets")
	b := DeriveKey(testSecretKey, "ldap-bind-passwords")
	if a == b {
		t.Fatal("different purposes derived the same subkey")
	}
	if a != DeriveKey(testSecretKey, "totp-secrets") {
		t.Fatal("DeriveKey is not deterministic")
	}
}
