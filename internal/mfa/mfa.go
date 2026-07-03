// Package mfa implements TOTP two-factor authentication (authenticator
// apps) plus single-use recovery codes. TOTP secrets are encrypted at
// rest; recovery codes are stored SHA-256 hashed. MFA is source-agnostic
// — it layers on top of both local and directory authentication.
package mfa

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"image/png"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/lporcheron/kivraid/internal/secrets"
	"github.com/lporcheron/kivraid/internal/store"
	"github.com/lporcheron/kivraid/internal/store/sqlcgen"
)

const (
	issuer            = "Kivraid"
	recoveryCodeCount = 10
)

type Manager struct {
	store   *store.Store
	sealKey [32]byte
}

func NewManager(st *store.Store, sealKey [32]byte) *Manager {
	return &Manager{store: st, sealKey: sealKey}
}

// GenerateSecret returns a fresh base32 TOTP secret to enroll.
func (m *Manager) GenerateSecret(account string) (string, error) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: issuer, AccountName: account})
	if err != nil {
		return "", err
	}
	return key.Secret(), nil
}

// key rebuilds an otp.Key from a stored base32 secret for the account.
func key(account, secret string) (*otp.Key, error) {
	return otp.NewKeyFromURL(fmt.Sprintf(
		"otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		issuer, account, secret, issuer))
}

// QRCodePNG renders the enrollment QR code for account+secret as PNG.
func (m *Manager) QRCodePNG(account, secret string) ([]byte, error) {
	k, err := key(account, secret)
	if err != nil {
		return nil, err
	}
	img, err := k.Image(220, 220)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// FormatSecret groups the base32 secret for readable manual entry.
func FormatSecret(secret string) string {
	var b strings.Builder
	for i, r := range secret {
		if i > 0 && i%4 == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// ValidateCode reports whether a 6-digit code matches the secret (with a
// small skew window for clock drift).
func ValidateCode(secret, code string) bool {
	code = strings.TrimSpace(code)
	ok, _ := totp.ValidateCustom(code, secret, time.Now(), totp.ValidateOpts{
		Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	return ok
}

// Enable stores the (encrypted) secret and turns TOTP on for the user.
func (m *Manager) Enable(ctx context.Context, userID, secret string) error {
	enc, err := secrets.Seal(m.sealKey, []byte(secret))
	if err != nil {
		return err
	}
	return m.store.SetUserTOTP(ctx, sqlcgen.SetUserTOTPParams{
		TotpSecretEnc: enc, TotpEnabled: true, UpdatedAt: time.Now().UTC(), ID: userID,
	})
}

// Disable turns TOTP off and drops the secret and recovery codes.
func (m *Manager) Disable(ctx context.Context, userID string) error {
	if err := m.store.DisableUserTOTP(ctx, sqlcgen.DisableUserTOTPParams{
		UpdatedAt: time.Now().UTC(), ID: userID,
	}); err != nil {
		return err
	}
	return m.store.DeleteRecoveryCodes(ctx, userID)
}

// ValidateForUser checks a TOTP code against a user's stored secret.
func (m *Manager) ValidateForUser(user sqlcgen.User, code string) bool {
	if !user.TotpEnabled || len(user.TotpSecretEnc) == 0 {
		return false
	}
	secret, err := secrets.Open(m.sealKey, user.TotpSecretEnc)
	if err != nil {
		return false
	}
	return ValidateCode(string(secret), code)
}

func hashCode(code string) string {
	sum := sha256.Sum256([]byte(normalizeCode(code)))
	return hex.EncodeToString(sum[:])
}

// normalizeCode strips spacing/dashes and lowercases recovery codes.
func normalizeCode(code string) string {
	return strings.ToLower(strings.NewReplacer(" ", "", "-", "").Replace(strings.TrimSpace(code)))
}

// GenerateRecoveryCodes replaces the user's recovery codes with a fresh
// set, returning the plaintext codes to display once.
func (m *Manager) GenerateRecoveryCodes(ctx context.Context, userID string) ([]string, error) {
	if err := m.store.DeleteRecoveryCodes(ctx, userID); err != nil {
		return nil, err
	}
	codes := make([]string, 0, recoveryCodeCount)
	now := time.Now().UTC()
	for range recoveryCodeCount {
		raw := make([]byte, 5)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		// 8-char lowercase base32, shown grouped as xxxx-xxxx.
		s := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw))
		display := s[:4] + "-" + s[4:]
		codes = append(codes, display)
		if err := m.store.CreateRecoveryCode(ctx, sqlcgen.CreateRecoveryCodeParams{
			ID: uuid.NewString(), UserID: userID, CodeHash: hashCode(s), CreatedAt: now,
		}); err != nil {
			return nil, err
		}
	}
	return codes, nil
}

// ConsumeRecoveryCode marks a matching unused recovery code as used and
// reports success. Comparison is constant-time per candidate.
func (m *Manager) ConsumeRecoveryCode(ctx context.Context, userID, code string) (bool, error) {
	want := hashCode(code)
	rows, err := m.store.ListUnusedRecoveryCodes(ctx, userID)
	if err != nil {
		return false, err
	}
	for _, row := range rows {
		if subtle.ConstantTimeCompare([]byte(row.CodeHash), []byte(want)) == 1 {
			return true, m.store.MarkRecoveryCodeUsed(ctx, sqlcgen.MarkRecoveryCodeUsedParams{
				UsedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true}, ID: row.ID,
			})
		}
	}
	return false, nil
}

// RemainingRecoveryCodes returns how many unused recovery codes a user has.
func (m *Manager) RemainingRecoveryCodes(ctx context.Context, userID string) (int64, error) {
	return m.store.CountUnusedRecoveryCodes(ctx, userID)
}
