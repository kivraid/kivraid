package local

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kivraid/kivraid/internal/store"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
)

// ErrBadCredentials is returned for every authentication failure —
// unknown user, wrong password, inactive account — so callers cannot
// distinguish them (and neither can an attacker).
var ErrBadCredentials = errors.New("invalid username or password")

// dummyHash is verified against when the user does not exist, so that the
// response time does not reveal whether an account exists.
var dummyHash, _ = HashPassword("kivraid-timing-equalizer")

type Source struct {
	store *store.Store
}

func NewSource(s *store.Store) *Source { return &Source{store: s} }

// Authenticate verifies username (or email) + password against local
// accounts and returns the user on success.
func (s *Source) Authenticate(ctx context.Context, username, password string) (sqlcgen.User, error) {
	login := strings.ToLower(strings.TrimSpace(username))

	user, err := s.store.GetUserByUsername(ctx, login)
	if errors.Is(err, sql.ErrNoRows) && strings.Contains(login, "@") {
		user, err = s.store.GetUserByEmail(ctx, login)
	}
	if errors.Is(err, sql.ErrNoRows) {
		VerifyPassword(dummyHash, password)
		return sqlcgen.User{}, ErrBadCredentials
	}
	if err != nil {
		return sqlcgen.User{}, err
	}

	if user.PasswordHash == nil {
		VerifyPassword(dummyHash, password)
		return sqlcgen.User{}, ErrBadCredentials
	}
	ok, err := VerifyPassword(*user.PasswordHash, password)
	if err != nil {
		return sqlcgen.User{}, err
	}
	if !ok || !user.Active || user.Source != "local" {
		return sqlcgen.User{}, ErrBadCredentials
	}
	return user, nil
}

// ChangePassword verifies the current password and stores a new hash.
func (s *Source) ChangePassword(ctx context.Context, user sqlcgen.User, current, newPassword string) error {
	if user.Source != "local" || user.PasswordHash == nil {
		return errors.New("not a local account")
	}
	ok, err := VerifyPassword(*user.PasswordHash, current)
	if err != nil {
		return err
	}
	if !ok {
		return ErrBadCredentials
	}
	hash, err := HashPassword(newPassword)
	if err != nil {
		return err
	}
	return s.store.UpdateUserPassword(ctx, sqlcgen.UpdateUserPasswordParams{
		PasswordHash: &hash,
		UpdatedAt:    time.Now().UTC(),
		ID:           user.ID,
	})
}

// SetPassword replaces a local account's password without verifying the
// current one. Admin-only path — the portal uses ChangePassword.
func (s *Source) SetPassword(ctx context.Context, userID, newPassword string) error {
	hash, err := HashPassword(newPassword)
	if err != nil {
		return err
	}
	return s.store.UpdateUserPassword(ctx, sqlcgen.UpdateUserPasswordParams{
		PasswordHash: &hash,
		UpdatedAt:    time.Now().UTC(),
		ID:           userID,
	})
}

// CreateUser creates a local account with the given password.
func (s *Source) CreateUser(ctx context.Context, username, email, name, password string, isAdmin bool) (sqlcgen.User, error) {
	hash, err := HashPassword(password)
	if err != nil {
		return sqlcgen.User{}, err
	}
	now := time.Now().UTC()
	return s.store.CreateUser(ctx, sqlcgen.CreateUserParams{
		ID:           uuid.NewString(),
		Username:     strings.ToLower(strings.TrimSpace(username)),
		Email:        strings.ToLower(strings.TrimSpace(email)),
		Name:         name,
		PasswordHash: &hash,
		Source:       "local",
		IsAdmin:      isAdmin,
		Active:       true,
		CreatedAt:    now,
		UpdatedAt:    now,
	})
}
