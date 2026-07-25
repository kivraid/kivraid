// Package webauthn implements passkey (WebAuthn) registration and
// passwordless login on top of go-webauthn, persisting credentials in the
// store. Passkeys are discoverable/resident so login is usernameless, and
// being phishing-resistant they stand in for both password and TOTP.
package webauthn

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/kivraid/kivraid/internal/store"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
)

type Manager struct {
	store *store.Store
	web   *webauthn.WebAuthn
}

// New builds a Manager. The relying-party ID is the base URL's hostname
// and the allowed origin is the base URL itself.
func New(st *store.Store, baseURL string) (*Manager, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("webauthn: invalid base_url: %w", err)
	}
	w, err := webauthn.New(&webauthn.Config{
		RPID:          u.Hostname(),
		RPDisplayName: "Kivraid",
		RPOrigins:     []string{fmt.Sprintf("%s://%s", u.Scheme, u.Host)},
	})
	if err != nil {
		return nil, err
	}
	return &Manager{store: st, web: w}, nil
}

// webUser adapts a Kivraid user + its stored credentials to webauthn.User.
type webUser struct {
	user  sqlcgen.User
	creds []webauthn.Credential
}

func (u *webUser) WebAuthnID() []byte                         { return []byte(u.user.ID) }
func (u *webUser) WebAuthnName() string                       { return u.user.Username }
func (u *webUser) WebAuthnDisplayName() string                { return u.user.Name }
func (u *webUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func (m *Manager) loadUser(ctx context.Context, user sqlcgen.User) (*webUser, error) {
	rows, err := m.store.ListWebauthnCredentials(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	creds := make([]webauthn.Credential, 0, len(rows))
	for _, row := range rows {
		var c webauthn.Credential
		if err := json.Unmarshal([]byte(row.Data), &c); err != nil {
			return nil, err
		}
		creds = append(creds, c)
	}
	return &webUser{user: user, creds: creds}, nil
}

// discoverableOpts require a resident key with user verification so the
// credential can be found without a username at login. Verification is
// required, not preferred: a passkey assertion stands in for both the
// password and the second factor, so possession alone must not be enough.
func discoverableOpts() []webauthn.RegistrationOption {
	req := protocol.ResidentKeyRequirementRequired
	return []webauthn.RegistrationOption{
		webauthn.WithResidentKeyRequirement(req),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      req,
			UserVerification: protocol.VerificationRequired,
		}),
	}
}

// BeginRegistration starts adding a passkey; returns the creation options
// (JSON) and the opaque session data to carry to FinishRegistration.
func (m *Manager) BeginRegistration(ctx context.Context, user sqlcgen.User) (options, session []byte, err error) {
	wu, err := m.loadUser(ctx, user)
	if err != nil {
		return nil, nil, err
	}
	creation, sess, err := m.web.BeginRegistration(wu, discoverableOpts()...)
	if err != nil {
		return nil, nil, err
	}
	options, err = json.Marshal(creation)
	if err != nil {
		return nil, nil, err
	}
	session, err = json.Marshal(sess)
	return options, session, err
}

// FinishRegistration verifies the attestation and stores the credential.
func (m *Manager) FinishRegistration(ctx context.Context, user sqlcgen.User, session []byte, r *http.Request, name string) error {
	wu, err := m.loadUser(ctx, user)
	if err != nil {
		return err
	}
	var sess webauthn.SessionData
	if err := json.Unmarshal(session, &sess); err != nil {
		return err
	}
	cred, err := m.web.FinishRegistration(wu, sess, r)
	if err != nil {
		return err
	}
	data, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	if name == "" {
		name = "Passkey"
	}
	return m.store.CreateWebauthnCredential(ctx, sqlcgen.CreateWebauthnCredentialParams{
		ID:           uuid.NewString(),
		UserID:       user.ID,
		CredentialID: base64.RawURLEncoding.EncodeToString(cred.ID),
		Name:         name,
		Data:         string(data),
		CreatedAt:    time.Now().UTC(),
	})
}

// BeginLogin starts a usernameless passkey assertion. User verification
// is required since the assertion completes login on its own.
func (m *Manager) BeginLogin() (options, session []byte, err error) {
	assertion, sess, err := m.web.BeginDiscoverableLogin(
		webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return nil, nil, err
	}
	options, err = json.Marshal(assertion)
	if err != nil {
		return nil, nil, err
	}
	session, err = json.Marshal(sess)
	return options, session, err
}

// FinishLogin verifies the assertion, updates the credential's sign count
// and returns the authenticated user's ID.
func (m *Manager) FinishLogin(ctx context.Context, session []byte, r *http.Request) (string, error) {
	var sess webauthn.SessionData
	if err := json.Unmarshal(session, &sess); err != nil {
		return "", err
	}
	var resolved sqlcgen.User
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		user, err := m.store.GetUserByID(ctx, string(userHandle))
		if err != nil {
			return nil, err
		}
		if !user.Active {
			return nil, fmt.Errorf("account is deactivated")
		}
		resolved = user
		return m.loadUser(ctx, user)
	}
	cred, err := m.web.FinishDiscoverableLogin(handler, sess, r)
	if err != nil {
		return "", err
	}
	// Persist the updated sign count (clone-detection state).
	data, err := json.Marshal(cred)
	if err == nil {
		_ = m.store.UpdateWebauthnCredential(ctx, sqlcgen.UpdateWebauthnCredentialParams{
			Data:         string(data),
			LastUsedAt:   sql.NullTime{Time: time.Now().UTC(), Valid: true},
			CredentialID: base64.RawURLEncoding.EncodeToString(cred.ID),
		})
	}
	return resolved.ID, nil
}

// List returns a user's registered passkeys.
func (m *Manager) List(ctx context.Context, userID string) ([]sqlcgen.WebauthnCredential, error) {
	return m.store.ListWebauthnCredentials(ctx, userID)
}

// Count returns how many passkeys a user has.
func (m *Manager) Count(ctx context.Context, userID string) (int64, error) {
	return m.store.CountWebauthnCredentials(ctx, userID)
}

// Delete removes one of the user's passkeys.
func (m *Manager) Delete(ctx context.Context, userID, id string) error {
	return m.store.DeleteWebauthnCredential(ctx, sqlcgen.DeleteWebauthnCredentialParams{
		ID: id, UserID: userID,
	})
}
