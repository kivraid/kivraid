package web

import (
	"context"
	"net/http"
	"time"

	"github.com/kivraid/kivraid/internal/audit"
	"github.com/kivraid/kivraid/internal/session"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
)

// markEmailVerified flags a user's address as confirmed. Best-effort logging;
// callers treat a failure as a server error where it matters.
func (s *Server) markEmailVerified(ctx context.Context, userID string) error {
	return s.store.SetEmailVerified(ctx, sqlcgen.SetEmailVerifiedParams{
		EmailVerified: true, UpdatedAt: time.Now().UTC(), ID: userID,
	})
}

// handleVerifyEmail consumes a verification link. It is public: the user may
// click it from a mail client with no Kivraid session.
func (s *Server) handleVerifyEmail(w http.ResponseWriter, r *http.Request) {
	row, ok := s.consumeEmailToken(r.Context(), purposeEmailVerify, r.URL.Query().Get("token"))
	if !ok {
		s.renderError(w, r, http.StatusBadRequest, "Link expired",
			"This verification link is invalid or has expired. Request a new one from your profile.")
		return
	}
	user, err := s.store.GetUserByID(r.Context(), row.UserID)
	if err != nil {
		s.renderError(w, r, http.StatusBadRequest, "Link expired",
			"This verification link is no longer valid.")
		return
	}
	// If the address changed after the link was sent, the token no longer
	// attests the current email.
	if row.Email != user.Email {
		s.renderError(w, r, http.StatusBadRequest, "Address changed",
			"This link was sent to a different email address than the one on the account now.")
		return
	}
	if err := s.markEmailVerified(r.Context(), user.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit.Record(r.Context(), user.Username, audit.ActionEmailVerify, "", "", s.clientIP(r))

	if s.sessions.GetString(r.Context(), session.KeyUserID) == user.ID {
		http.Redirect(w, r, "/profile?verified=1", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/login?verified=1", http.StatusSeeOther)
}

// handleProfileSendVerification lets a signed-in local user send themselves a
// verification link.
func (s *Server) handleProfileSendVerification(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	if user.Source != "local" {
		s.renderError(w, r, http.StatusBadRequest, "Directory-managed email",
			"Your email comes from the directory and is trusted as-is.")
		return
	}
	if user.EmailVerified {
		http.Redirect(w, r, "/profile", http.StatusSeeOther)
		return
	}
	if !s.smtpEnabled.Load() {
		s.renderError(w, r, http.StatusServiceUnavailable, "Email not configured",
			"This instance cannot send email yet. Ask an administrator to set up SMTP.")
		return
	}
	if err := s.sendVerificationEmail(r.Context(), user); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit.Record(r.Context(), user.Username, audit.ActionEmailVerifySnt, user.Username, "self", s.clientIP(r))
	http.Redirect(w, r, "/profile?vsent=1", http.StatusSeeOther)
}

// handleAdminUserSendVerification sends a verification link to a local user
// on an admin's behalf.
func (s *Server) handleAdminUserSendVerification(w http.ResponseWriter, r *http.Request) {
	target, ok := s.loadTargetUser(w, r)
	if !ok {
		return
	}
	if target.Source != "local" {
		s.renderError(w, r, http.StatusBadRequest, "Directory-managed email",
			"Directory users get their email from the directory; it is trusted as-is.")
		return
	}
	if !s.smtpEnabled.Load() {
		s.renderError(w, r, http.StatusServiceUnavailable, "Email not configured",
			"Configure SMTP under Admin → Settings → Email before sending verification links.")
		return
	}
	if err := s.sendVerificationEmail(r.Context(), target); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionEmailVerifySnt, target.Username, "", s.clientIP(r))
	http.Redirect(w, r, "/admin/users/"+target.ID+"?vsent=1", http.StatusSeeOther)
}
