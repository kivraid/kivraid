package web

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"

	"github.com/kivraid/kivraid/internal/audit"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
)

// canResetPassword reports whether Kivraid can set a new password for the
// user without the current one. Local accounts always can; directory users
// only when their source's password_reset flag is on (the service account
// performs the write).
func (s *Server) canResetPassword(ctx context.Context, user sqlcgen.User) bool {
	switch user.Source {
	case "local":
		return true
	case "ldap":
		if s.ldap == nil || user.LdapSourceID == nil {
			return false
		}
		src, err := s.store.GetLdapSource(ctx, *user.LdapSourceID)
		return err == nil && src.PasswordReset
	}
	return false
}

// resetPassword sets a new password, routing to the local store or a
// directory service-account reset.
func (s *Server) resetPassword(ctx context.Context, user sqlcgen.User, newPassword string) error {
	if user.Source == "ldap" {
		return s.ldap.ResetPassword(ctx, user, newPassword)
	}
	return s.local.SetPassword(ctx, user.ID, newPassword)
}

type forgotData struct {
	CSRF  string
	Error string
	Sent  bool
}

type resetData struct {
	CSRF    string
	Token   string
	Error   string
	Invalid bool
	// Forced marks the "change your password before continuing" variant
	// shown after signing in with an administrator-chosen password.
	Forced bool
	Next   string
}

func (s *Server) handleForgotPage(w http.ResponseWriter, r *http.Request) {
	if !s.smtpEnabled.Load() {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.render(w, r, "forgot.html", forgotData{CSRF: s.csrfToken(r.Context())})
}

// handleForgotSubmit always reports the same neutral outcome, so it never
// reveals whether an account exists. A link is sent only for accounts that
// can actually be reset (local, or a directory with password reset enabled)
// and that have an email address.
func (s *Server) handleForgotSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.smtpEnabled.Load() {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	neutral := func() {
		s.render(w, r, "forgot.html", forgotData{CSRF: s.csrfToken(r.Context()), Sent: true})
	}
	identifier := strings.ToLower(strings.TrimSpace(r.PostFormValue("identifier")))
	if identifier == "" {
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.render(w, r, "forgot.html", forgotData{CSRF: s.csrfToken(r.Context()), Error: "Enter your username or email."})
		return
	}
	ip := s.clientIP(r)
	// Rate-limit by IP; a throttled request still shows the neutral page.
	if !s.ipLimiter.Allow(ip) {
		neutral()
		return
	}

	user, err := s.store.GetUserByUsername(r.Context(), identifier)
	if errors.Is(err, sql.ErrNoRows) && strings.Contains(identifier, "@") {
		user, err = s.store.GetUserByEmail(r.Context(), identifier)
	}
	if err == nil && user.Active && user.Email != "" && s.canResetPassword(r.Context(), user) {
		raw, terr := s.issueEmailToken(r.Context(), purposePasswordReset, user.ID, user.Email, resetTokenTTL)
		if terr != nil {
			s.serverError(w, r, terr)
			return
		}
		if serr := s.sendPasswordResetEmail(r.Context(), user, raw); serr != nil {
			// Don't leak delivery failures to the caller, but do record them.
			s.log.Warn("send password reset email", "user", user.Username, "err", serr)
		} else {
			s.audit.Record(r.Context(), user.Username, audit.ActionPasswordReset, "", "requested", ip)
		}
	}
	neutral()
}

func (s *Server) handleResetPage(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if _, ok := s.lookupEmailToken(r.Context(), purposePasswordReset, token); !ok {
		s.render(w, r, "reset.html", resetData{CSRF: s.csrfToken(r.Context()), Invalid: true})
		return
	}
	s.render(w, r, "reset.html", resetData{CSRF: s.csrfToken(r.Context()), Token: token})
}

func (s *Server) handleResetSubmit(w http.ResponseWriter, r *http.Request) {
	token := r.PostFormValue("token")
	fail := func(msg string) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.render(w, r, "reset.html", resetData{CSRF: s.csrfToken(r.Context()), Token: token, Error: msg})
	}

	if _, ok := s.lookupEmailToken(r.Context(), purposePasswordReset, token); !ok {
		s.render(w, r, "reset.html", resetData{CSRF: s.csrfToken(r.Context()), Invalid: true})
		return
	}
	password := r.PostFormValue("password")
	if len(password) < 8 {
		fail("The new password must be at least 8 characters.")
		return
	}
	if password != r.PostFormValue("confirm_password") {
		fail("The passwords do not match.")
		return
	}

	// Consume the token now that the input is valid.
	row, ok := s.consumeEmailToken(r.Context(), purposePasswordReset, token)
	if !ok {
		s.render(w, r, "reset.html", resetData{CSRF: s.csrfToken(r.Context()), Invalid: true})
		return
	}
	user, err := s.store.GetUserByID(r.Context(), row.UserID)
	if err != nil || !s.canResetPassword(r.Context(), user) {
		s.render(w, r, "reset.html", resetData{CSRF: s.csrfToken(r.Context()), Invalid: true})
		return
	}
	if err := s.resetPassword(r.Context(), user, password); err != nil {
		s.serverError(w, r, err)
		return
	}
	// Resetting via an emailed link proves control of the mailbox: mark local
	// addresses verified (directory addresses are trusted already). Existing
	// sessions and tokens are dropped as a precaution against a lingering
	// attacker.
	if user.Source == "local" {
		s.markEmailVerified(r.Context(), user.ID)
	}
	s.revokeUserAccess(r.Context(), user.ID)
	s.audit.Record(r.Context(), user.Username, audit.ActionPasswordChange, "", "reset via email", s.clientIP(r))
	s.log.Info("password reset via email", "user", user.Username)
	http.Redirect(w, r, "/login?reset=1", http.StatusSeeOther)
}

// handlePasswordChangeRequired asks a signed-in user whose password was set
// by an administrator to choose their own before going anywhere else.
func (s *Server) handlePasswordChangeRequired(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	next := s.safeNext(r.FormValue("next"), "/")
	if !user.MustChangePassword {
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}
	render := func(status int, msg string) {
		w.WriteHeader(status)
		s.render(w, r, "reset.html", resetData{CSRF: s.csrfToken(r.Context()), Forced: true, Next: next, Error: msg})
	}
	if r.Method != http.MethodPost {
		render(http.StatusOK, "")
		return
	}
	password := r.PostFormValue("password")
	if len(password) < 8 {
		render(http.StatusUnprocessableEntity, "The new password must be at least 8 characters.")
		return
	}
	if password != r.PostFormValue("confirm_password") {
		render(http.StatusUnprocessableEntity, "The passwords do not match.")
		return
	}
	if _, err := s.local.Authenticate(r.Context(), user.Username, password); err == nil {
		render(http.StatusUnprocessableEntity, "Choose a password different from the one you were given.")
		return
	}
	if err := s.resetPassword(r.Context(), user, password); err != nil {
		s.serverError(w, r, err)
		return
	}
	if err := s.store.SetUserMustChangePassword(r.Context(), sqlcgen.SetUserMustChangePasswordParams{
		MustChangePassword: false, ID: user.ID,
	}); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit.Record(r.Context(), user.Username, audit.ActionPasswordChange, "", "required at sign-in", s.clientIP(r))
	http.Redirect(w, r, next, http.StatusSeeOther)
}
