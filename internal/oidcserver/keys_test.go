package oidcserver

import (
	"testing"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/lporcheron/kivraid/internal/secrets"
	"github.com/lporcheron/kivraid/internal/store/storetest"
)

func TestSigningAlgorithm(t *testing.T) {
	ok := map[string]jose.SignatureAlgorithm{
		"": jose.ES256, "es256": jose.ES256, "ES256": jose.ES256,
		"rs256": jose.RS256, " RS256 ": jose.RS256,
	}
	for in, want := range ok {
		got, err := signingAlgorithm(in)
		if err != nil || got != want {
			t.Errorf("signingAlgorithm(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := signingAlgorithm("hs256"); err == nil {
		t.Error("signingAlgorithm(\"hs256\"): want error, got nil")
	}
}

func TestSigningKeyByAlgorithmAndSwitch(t *testing.T) {
	st := storetest.Open(t)
	seal := secrets.DeriveKey("test-secret-key-test-secret-key!", "signing-keys")
	cs := secrets.DeriveKey("test-secret-key-test-secret-key!", "client-secrets")
	ctx := t.Context()

	// Default ES256: signs with an EC key, one key in the JWKS.
	s1, err := NewStorage(ctx, st, seal, cs, jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	if s1.key.alg != jose.ES256 {
		t.Fatalf("signing alg: want ES256, got %s", s1.key.alg)
	}
	if len(s1.keys) != 1 {
		t.Fatalf("JWKS: want 1 key, got %d", len(s1.keys))
	}

	// Switch to RS256 on the same store: now signs RS256, but the ES256
	// key stays published so tokens issued before the switch still verify.
	s2, err := NewStorage(ctx, st, seal, cs, jose.RS256)
	if err != nil {
		t.Fatal(err)
	}
	if s2.key.alg != jose.RS256 {
		t.Fatalf("signing alg after switch: want RS256, got %s", s2.key.alg)
	}
	if len(s2.keys) != 2 {
		t.Fatalf("JWKS after switch: want both keys, got %d", len(s2.keys))
	}

	// Switching back reuses the existing keys rather than minting more.
	s3, err := NewStorage(ctx, st, seal, cs, jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	if s3.key.alg != jose.ES256 || len(s3.keys) != 2 {
		t.Fatalf("switch back: want ES256 with 2 keys, got %s with %d", s3.key.alg, len(s3.keys))
	}
}
