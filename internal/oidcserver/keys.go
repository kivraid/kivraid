package oidcserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"

	"github.com/lporcheron/kivraid/internal/secrets"
	"github.com/lporcheron/kivraid/internal/store"
	"github.com/lporcheron/kivraid/internal/store/sqlcgen"
)

// signingKey is the in-memory, decrypted form of a signing_keys row.
type signingKey struct {
	id      string
	alg     jose.SignatureAlgorithm
	private *ecdsa.PrivateKey
}

func (k *signingKey) ID() string                                  { return k.id }
func (k *signingKey) SignatureAlgorithm() jose.SignatureAlgorithm { return k.alg }
func (k *signingKey) Key() any                                    { return k.private }

// publicKey exposes a signing key's public half for the JWKS endpoint.
type publicKey struct{ *signingKey }

func (k publicKey) Use() string { return "sig" }
func (k publicKey) Key() any    { return &k.private.PublicKey }
func (k publicKey) Algorithm() jose.SignatureAlgorithm {
	return k.alg
}

// loadOrCreateSigningKey returns the newest active ES256 key, generating
// and persisting one on first start. Private keys are encrypted at rest.
func loadOrCreateSigningKey(ctx context.Context, st *store.Store, sealKey [32]byte) (*signingKey, error) {
	rows, err := st.GetActiveSigningKeys(ctx)
	if err != nil {
		return nil, err
	}
	if len(rows) > 0 {
		return decryptSigningKey(rows[0], sealKey)
	}

	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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
	pubDER, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if err != nil {
		return nil, err
	}
	id := uuid.NewString()
	if err := st.CreateSigningKey(ctx, sqlcgen.CreateSigningKeyParams{
		ID:            id,
		Alg:           string(jose.ES256),
		PrivateKeyEnc: sealed,
		PublicKeyDer:  pubDER,
		Active:        true,
		CreatedAt:     time.Now().UTC(),
	}); err != nil {
		return nil, err
	}
	return &signingKey{id: id, alg: jose.ES256, private: private}, nil
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
	ec, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("signing key %s: unexpected key type %T", row.ID, parsed)
	}
	return &signingKey{id: row.ID, alg: jose.SignatureAlgorithm(row.Alg), private: ec}, nil
}
