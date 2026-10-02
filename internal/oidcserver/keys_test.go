package oidcserver

import (
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/kivraid/kivraid/internal/secrets"
	"github.com/kivraid/kivraid/internal/store/storetest"
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
	s1, err := NewStorage(ctx, st, seal, cs, "https://sso.example.test", jose.ES256)
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
	s2, err := NewStorage(ctx, st, seal, cs, "https://sso.example.test", jose.RS256)
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
	s3, err := NewStorage(ctx, st, seal, cs, "https://sso.example.test", jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	if s3.key.alg != jose.ES256 || len(s3.keys) != 2 {
		t.Fatalf("switch back: want ES256 with 2 keys, got %s with %d", s3.key.alg, len(s3.keys))
	}
}

func TestMaintainSigningKeysRotatesAndRetires(t *testing.T) {
	st := storetest.Open(t)
	seal := secrets.DeriveKey("test-secret-key-test-secret-key!", "signing-keys")
	cs := secrets.DeriveKey("test-secret-key-test-secret-key!", "client-secrets")
	ctx := t.Context()
	s, err := NewStorage(ctx, st, seal, cs, "https://sso.example.test", jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	first := s.key.id
	created := s.SigningKeyCreated()
	const month = 30 * 24 * time.Hour

	// Young key, manual rotation: nothing to do.
	if rotated, retired, err := s.MaintainSigningKeys(ctx, 0, created.Add(time.Hour)); err != nil || rotated || retired != 0 {
		t.Fatalf("young key: rotated=%v retired=%d err=%v", rotated, retired, err)
	}
	// Due for automatic rotation: a new signer, the old key still published.
	rotated, _, err := s.MaintainSigningKeys(ctx, month, created.Add(month+time.Hour))
	if err != nil || !rotated {
		t.Fatalf("due key: rotated=%v err=%v", rotated, err)
	}
	if s.key.id == first || s.PublishedKeyCount() != 2 {
		t.Fatalf("after rotation: signer %s (first %s), %d published", s.key.id, first, s.PublishedKeyCount())
	}
	// Within the grace period the previous key stays in the JWKS...
	newCreated := s.SigningKeyCreated()
	if _, retired, _ := s.MaintainSigningKeys(ctx, month, newCreated.Add(KeyRetirementGrace-time.Hour)); retired != 0 {
		t.Fatalf("within grace: retired %d keys", retired)
	}
	// ...and is retired afterwards.
	if _, retired, err := s.MaintainSigningKeys(ctx, month, newCreated.Add(KeyRetirementGrace+time.Hour)); err != nil || retired != 1 {
		t.Fatalf("after grace: retired=%d err=%v", retired, err)
	}
	if s.PublishedKeyCount() != 1 {
		t.Fatalf("after retirement: want 1 published key, got %d", s.PublishedKeyCount())
	}
	// A restart only loads the remaining key.
	s2, err := NewStorage(ctx, st, seal, cs, "https://sso.example.test", jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	if s2.PublishedKeyCount() != 1 || s2.key.id != s.key.id {
		t.Fatal("retired keys must stay retired across restarts")
	}
}
