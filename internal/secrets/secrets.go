// Package secrets provides encryption-at-rest helpers. All keys are
// derived from the instance secret_key with HKDF, one subkey per purpose,
// so rotating a purpose never affects the others.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

// DeriveKey derives a 32-byte subkey for the given purpose from the
// instance secret key.
func DeriveKey(secretKey, purpose string) [32]byte {
	var key [32]byte
	r := hkdf.New(sha256.New, []byte(secretKey), nil, []byte("kivraid/"+purpose))
	if _, err := io.ReadFull(r, key[:]); err != nil {
		panic(err) // hkdf cannot fail before 255*32 bytes
	}
	return key
}

// Seal encrypts plaintext with AES-256-GCM. Output is nonce || ciphertext.
func Seal(key [32]byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Open decrypts a Seal output.
func Open(key [32]byte, sealed []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, errors.New("sealed data too short")
	}
	return gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], nil)
}
