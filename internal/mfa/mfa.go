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

	"github.com/kivraid/kivraid/internal/secrets"
	"github.com/kivraid/kivraid/internal/store"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
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

// totpOpts are the fixed validation parameters: 30-second steps with a
// ±1 step skew window for clock drift.
var totpOpts = totp.ValidateOpts{
	Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
}

// MatchCounter reports which time-step counter a 6-digit code matches
// for the secret, within the skew window. The counter is what replay
// protection records: each accepted step is consumed exactly once.
func MatchCounter(secret, code string, t time.Time) (int64, bool) {
	code = strings.TrimSpace(code)
	step := int64(totpOpts.Period)
	current := t.Unix() / step
	for _, c := range []int64{current, current - 1, current + 1} {
		expected, err := totp.GenerateCodeCustom(secret, time.Unix(c*step, 0), totpOpts)
		if err == nil && subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return c, true
		}
	}
	return 0, false
}

// Enable stores the (encrypted) secret and turns TOTP on for the user.
// lastCounter is the time step of the enrollment code, seeding replay
// protection so that same code cannot be reused at the login prompt.
func (m *Manager) Enable(ctx context.Context, userID, secret string, lastCounter int64) error {
	enc, err := secrets.Seal(m.sealKey, []byte(secret))
	if err != nil {
		return err
	}
	return m.store.SetUserTOTP(ctx, sqlcgen.SetUserTOTPParams{
		TotpSecretEnc: enc, TotpEnabled: true, TotpLastCounter: lastCounter,
		UpdatedAt: time.Now().UTC(), ID: userID,
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

// ValidateForUser checks a TOTP code against a user's stored secret and
// consumes its time step: a given code is accepted at most once, so an
// intercepted code cannot be replayed within the skew window.
func (m *Manager) ValidateForUser(ctx context.Context, user sqlcgen.User, code string) (bool, error) {
	if !user.TotpEnabled || len(user.TotpSecretEnc) == 0 {
		return false, nil
	}
	secret, err := secrets.Open(m.sealKey, user.TotpSecretEnc)
	if err != nil {
		return false, err
	}
	counter, ok := MatchCounter(string(secret), code, time.Now())
	if !ok {
		return false, nil
	}
	rows, err := m.store.ClaimUserTOTPCounter(ctx, sqlcgen.ClaimUserTOTPCounterParams{
		TotpLastCounter: counter, UpdatedAt: time.Now().UTC(), ID: user.ID,
	})
	if err != nil {
		return false, err
	}
	return rows > 0, nil
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
