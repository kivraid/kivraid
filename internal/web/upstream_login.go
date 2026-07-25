package web

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/lporcheron/kivraid/internal/broker"
	"github.com/lporcheron/kivraid/internal/session"
	"github.com/lporcheron/kivraid/internal/store/sqlcgen"
)

// Outcomes of federated provisioning that map to specific user-facing pages.
var (
	errSignupDisabled  = errors.New("federated sign-up disabled")
	errEmailCollision  = errors.New("email already in use")
	errAccountInactive = errors.New("account inactive")
)

func (s *Server) loadEnabledProvider(w http.ResponseWriter, r *http.Request) (sqlcgen.UpstreamProvider, bool) {
	if s.broker == nil {
		http.NotFound(w, r)
		return sqlcgen.UpstreamProvider{}, false
	}
	p, err := s.store.GetUpstreamProvider(r.Context(), r.PathValue("id"))
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !p.Enabled) {
		http.NotFound(w, r)
		return sqlcgen.UpstreamProvider{}, false
	}
	if err != nil {
		s.serverError(w, r, err)
		return sqlcgen.UpstreamProvider{}, false
	}
	return p, true
}

// handleUpstreamLoginStart kicks off the OAuth ceremony to an upstream
// provider, remembering the post-login target in the session.
func (s *Server) handleUpstreamLoginStart(w http.ResponseWriter, r *http.Request) {
	p, ok := s.loadEnabledProvider(w, r)
	if !ok {
		return
	}
	s.sessions.Put(r.Context(), session.KeyPendingNext, s.safeNext(r.URL.Query().Get("next"), "/"))
	if err := s.broker.StartLogin(w, r, p); err != nil {
		s.log.Warn("upstream login start", "provider", p.Name, "err", err)
		s.renderError(w, r, http.StatusBadGateway, "Provider unavailable",
			"Could not reach the identity provider. Please try again shortly.")
	}
}

// handleUpstreamLoginCallback completes the ceremony, provisions or links the
// federated user, and establishes the session.
func (s *Server) handleUpstreamLoginCallback(w http.ResponseWriter, r *http.Request) {
	p, ok := s.loadEnabledProvider(w, r)
	if !ok {
		return
	}
	ident, err := s.broker.HandleCallback(w, r, p)
	if err != nil {
		s.log.Warn("upstream callback", "provider", p.Name, "err", err)
		s.renderError(w, r, http.StatusBadGateway, "Sign-in failed",
			"The identity provider returned an error. Please try again.")
		return
	}
	if ident == nil {
		// The ceremony already wrote a response (e.g. invalid state).
		return
	}
	if ident.Subject == "" || ident.Email == "" {
		s.renderError(w, r, http.StatusBadGateway, "Incomplete profile",
			"The provider did not return the required subject and email claims.")
		return
	}

	user, err := s.provisionUpstreamUser(r.Context(), p, ident)
	switch {
	case errors.Is(err, errSignupDisabled):
		s.renderError(w, r, http.StatusForbidden, "No linked account",
			"This provider account isn't linked to a Kivraid user and self-service sign-up is off. Ask an administrator to create your account.")
		return
	case errors.Is(err, errEmailCollision):
		s.renderError(w, r, http.StatusConflict, "Email already in use",
			"An existing account uses this email but it hasn't been verified, so it can't be linked automatically. Ask an administrator.")
		return
	case errors.Is(err, errAccountInactive):
		s.renderError(w, r, http.StatusForbidden, "Account disabled",
			"This account is deactivated. Ask an administrator.")
		return
	case err != nil:
		s.serverError(w, r, err)
		return
	}

	next := s.safeNext(s.sessions.GetString(r.Context(), session.KeyPendingNext), "/")
	s.sessions.Remove(r.Context(), session.KeyPendingNext)
	if err := s.completeLogin(r, user, next); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.log.Info("federated login", "user", user.Username, "provider", p.Name)
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// provisionUpstreamUser resolves the federated identity to a local user:
// relink an existing federated account, link to a mutually-verified email, or
// create a new shadow user when the provider allows sign-up.
func (s *Server) provisionUpstreamUser(ctx context.Context, p sqlcgen.UpstreamProvider, ident *broker.Identity) (sqlcgen.User, error) {
	now := time.Now().UTC()

	// 1. Already linked to this provider by subject.
	u, err := s.store.GetUserByExternalID(ctx, sqlcgen.GetUserByExternalIDParams{
		UpstreamSourceID: &p.ID, ExternalID: &ident.Subject,
	})
	if err == nil {
		if !u.Active {
			return sqlcgen.User{}, errAccountInactive
		}
		return u, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return sqlcgen.User{}, err
	}

	// 2. Link to an existing account, but only on a mutually-verified email
	//    (both the upstream and the local record), to avoid account takeover.
	if ident.EmailVerified {
		existing, eerr := s.store.GetUserByEmail(ctx, ident.Email)
		if eerr == nil {
			if !existing.Active {
				return sqlcgen.User{}, errAccountInactive
			}
			if !existing.EmailVerified {
				return sqlcgen.User{}, errEmailCollision
			}
			if err := s.store.SetUserUpstreamIdentity(ctx, sqlcgen.SetUserUpstreamIdentityParams{
				UpstreamSourceID: &p.ID, ExternalID: &ident.Subject, UpdatedAt: now, ID: existing.ID,
			}); err != nil {
				return sqlcgen.User{}, err
			}
			return s.store.GetUserByID(ctx, existing.ID)
		}
		if !errors.Is(eerr, sql.ErrNoRows) {
			return sqlcgen.User{}, eerr
		}
	}

	// 3. Provision a new federated user, if the provider permits sign-up.
	if !p.AllowSignup {
		return sqlcgen.User{}, errSignupDisabled
	}
	name := ident.Name
	if name == "" {
		name = ident.Email
	}
	user, cerr := s.store.CreateUpstreamUser(ctx, sqlcgen.CreateUpstreamUserParams{
		ID: uuid.NewString(), Username: ident.Email, Email: ident.Email, Name: name,
		UpstreamSourceID: &p.ID, ExternalID: &ident.Subject, EmailVerified: ident.EmailVerified,
		CreatedAt: now, UpdatedAt: now,
	})
	if isUniqueViolation(cerr) {
		// An unverified email (or username) already exists — don't hijack it.
		return sqlcgen.User{}, errEmailCollision
	}
	return user, cerr
}
