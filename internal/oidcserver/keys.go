package oidcserver

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"

	"github.com/lporcheron/kivraid/internal/secrets"
	"github.com/lporcheron/kivraid/internal/store"
	"github.com/lporcheron/kivraid/internal/store/sqlcgen"
)

// signingKey is the in-memory, decrypted form of a signing_keys row. The
// private key is an EC key for ES256 or an RSA key for RS256.
type signingKey struct {
	id      string
	alg     jose.SignatureAlgorithm
	private crypto.Signer
}

func (k *signingKey) ID() string                                  { return k.id }
func (k *signingKey) SignatureAlgorithm() jose.SignatureAlgorithm { return k.alg }
func (k *signingKey) Key() any                                    { return k.private }

// publicKey exposes a signing key's public half for the JWKS endpoint.
type publicKey struct{ *signingKey }

func (k publicKey) Use() string                        { return "sig" }
func (k publicKey) Key() any                           { return k.private.Public() }
func (k publicKey) Algorithm() jose.SignatureAlgorithm { return k.alg }

// generateKey creates a fresh private key for the given algorithm.
func generateKey(alg jose.SignatureAlgorithm) (crypto.Signer, error) {
	switch alg {
	case jose.ES256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case jose.RS256:
		return rsa.GenerateKey(rand.Reader, 2048)
	default:
		return nil, fmt.Errorf("unsupported signing algorithm %q", alg)
	}
}

// loadSigningKeys decrypts every active signing key (all are published in
// the JWKS so tokens signed before an algorithm switch still verify) and
// returns the one matching alg, generating and persisting it on first use.
func loadSigningKeys(ctx context.Context, st *store.Store, sealKey [32]byte, alg jose.SignatureAlgorithm) (active *signingKey, all []*signingKey, err error) {
	rows, err := st.GetActiveSigningKeys(ctx)
	if err != nil {
		return nil, nil, err
	}
	for _, row := range rows {
		k, err := decryptSigningKey(row, sealKey)
		if err != nil {
			return nil, nil, err
		}
		all = append(all, k)
		if k.alg == alg && active == nil {
			active = k
		}
	}
	if active != nil {
		return active, all, nil
	}

	// No key for the requested algorithm yet: generate and persist one.
	// Any existing key of a different algorithm is left active so its
	// public half stays in the JWKS.
	active, err = generateAndStoreKey(ctx, st, sealKey, alg)
	if err != nil {
		return nil, nil, err
	}
	all = append(all, active)
	return active, all, nil
}

// generateAndStoreKey creates a fresh private key for alg, seals it, and
// persists it as an active signing key. It is used both on first use of an
// algorithm and by manual rotation.
func generateAndStoreKey(ctx context.Context, st *store.Store, sealKey [32]byte, alg jose.SignatureAlgorithm) (*signingKey, error) {
	private, err := generateKey(alg)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, err
	}
	sealed, err := secrets.Seal(sealKey, der)
	if err != nil {
		return nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(private.Public())
	if err != nil {
		return nil, err
	}
	id := uuid.NewString()
	if err := st.CreateSigningKey(ctx, sqlcgen.CreateSigningKeyParams{
		ID:            id,
		Alg:           string(alg),
		PrivateKeyEnc: sealed,
		PublicKeyDer:  pubDER,
		Active:        true,
		CreatedAt:     time.Now().UTC(),
	}); err != nil {
		return nil, err
	}
	return &signingKey{id: id, alg: alg, private: private}, nil
}

func decryptSigningKey(row sqlcgen.SigningKey, sealKey [32]byte) (*signingKey, error) {
	der, err := secrets.Open(sealKey, row.PrivateKeyEnc)
	if err != nil {
		return nil, fmt.Errorf("decrypt signing key %s (was secret_key changed?): %w", row.ID, err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("signing key %s: unexpected key type %T", row.ID, parsed)
	}
	return &signingKey{id: row.ID, alg: jose.SignatureAlgorithm(row.Alg), private: signer}, nil
}
