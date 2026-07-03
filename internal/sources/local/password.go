// Package local implements the local user source: accounts stored in the
// database with Argon2id password hashes.
package local

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters: OWASP's lighter recommended profile (m=19 MiB,
// t=2, p=1). Still strong, but far friendlier on a small host than the
// 64 MiB profile — each hash costs argonMemory KiB of RAM. Existing
// hashes store their own parameters, so old (heavier) hashes keep
// verifying after this default changes.
const (
	argonMemory  = 19 * 1024
	argonTime    = 2
	argonThreads = 1
	argonKeyLen  = 32
	argonSaltLen = 16
)

// hashSem bounds concurrent Argon2id computations so a burst of logins
// cannot exhaust memory: peak stays ~cap(hashSem) × argonMemory instead
// of unbounded. Login is not throughput-critical, so a small cap is fine
// (it also dampens brute-force). Sized to the CPUs, capped at 4.
var hashSem = make(chan struct{}, hashConcurrency())

func hashConcurrency() int {
	n := runtime.GOMAXPROCS(0)
	if n > 4 {
		n = 4
	}
	if n < 1 {
		n = 1
	}
	return n
}

// argon2Key runs argon2.IDKey under the concurrency limiter.
func argon2Key(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	hashSem <- struct{}{}
	defer func() { <-hashSem }()
	return argon2.IDKey(password, salt, time, memory, threads, keyLen)
}

var ErrInvalidHash = errors.New("invalid argon2id hash encoding")

// HashPassword returns a PHC-formatted Argon2id hash:
// $argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2Key([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword reports whether password matches the PHC-formatted hash.
// It uses the parameters stored in the hash, so old hashes keep verifying
// after the defaults change.
func VerifyPassword(hash, password string) (bool, error) {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, ErrInvalidHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, ErrInvalidHash
	}
	if version != argon2.Version {
		return false, fmt.Errorf("unsupported argon2 version %d", version)
	}
	var memory, time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return false, ErrInvalidHash
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, ErrInvalidHash
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, ErrInvalidHash
	}
	got := argon2Key([]byte(password), salt, time, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
