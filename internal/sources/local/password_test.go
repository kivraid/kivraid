package local

import (
	"strings"
	"testing"
)

func TestHashVerifyRoundtrip(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("unexpected hash format: %s", hash)
	}

	ok, err := VerifyPassword(hash, "correct horse battery staple")
	if err != nil || !ok {
		t.Fatalf("want match, got ok=%v err=%v", ok, err)
	}

	ok, err = VerifyPassword(hash, "wrong password")
	if err != nil || ok {
		t.Fatalf("want mismatch, got ok=%v err=%v", ok, err)
	}
}

func TestHashesAreSalted(t *testing.T) {
	h1, _ := HashPassword("same password")
	h2, _ := HashPassword("same password")
	if h1 == h2 {
		t.Fatal("two hashes of the same password must differ (random salt)")
	}
}

func TestVerifyRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"", "plaintext", "$argon2i$v=19$m=1,t=1,p=1$AA$AA", "$argon2id$nope"} {
		if ok, _ := VerifyPassword(bad, "x"); ok {
			t.Fatalf("garbage hash %q must not verify", bad)
		}
	}
}
