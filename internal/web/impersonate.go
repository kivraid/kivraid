package web

import (
	"net/http"

	"github.com/kivraid/kivraid/internal/audit"
	"github.com/kivraid/kivraid/internal/session"
)

// handleAdminUserImpersonate lets an administrator view the instance as
// another user, to reproduce what that user sees. The admin's own identity
// is stashed in the session so a banner can restore it; the switch renews
// the session token to avoid fixation.
func (s *Server) handleAdminUserImpersonate(w http.ResponseWriter, r *http.Request) {
	target, ok := s.loadTargetUser(w, r)
	if !ok {
		return
	}
	actor := currentUser(r)
	if target.ID == actor.ID {
		s.renderError(w, r, http.StatusBadRequest, s.t(r, "Cannot impersonate yourself"),
			s.t(r, "You are already signed in as this account."))
		return
	}
	if !target.Active {
		s.renderError(w, r, http.StatusBadRequest, s.t(r, "Account deactivated"),
			s.t(r, "Reactivate the account before impersonating it."))
		return
	}
	// No nesting: an impersonation must be ended before starting another.
	if s.sessions.GetString(r.Context(), session.KeyImpersonator) != "" {
		s.renderError(w, r, http.StatusBadRequest, s.t(r, "Already impersonating"),
			s.t(r, "Return to your own account before impersonating another user."))
		return
	}

	if err := s.sessions.RenewToken(r.Context()); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.sessions.Put(r.Context(), session.KeyImpersonator, actor.ID)
	s.sessions.Put(r.Context(), session.KeyImpersonatorName, actor.Username)
	s.sessions.Put(r.Context(), session.KeyUserID, target.ID)
	s.audit.Record(r.Context(), actor.Username, audit.ActionImpersonate, target.Username, "", s.clientIP(r))
	s.log.Info("impersonation started", "admin", actor.Username, "target", target.Username)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// handleImpersonateStop restores the impersonating admin's own session. It
// is reachable by the impersonated (possibly non-admin) session, so it is
// gated on the presence of the stashed admin identity, not on admin rights.
func (s *Server) handleImpersonateStop(w http.ResponseWriter, r *http.Request) {
	adminID := s.sessions.GetString(r.Context(), session.KeyImpersonator)
	if adminID == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	adminName := s.sessions.GetString(r.Context(), session.KeyImpersonatorName)
	impersonated := currentUser(r)

	if err := s.sessions.RenewToken(r.Context()); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.sessions.Put(r.Context(), session.KeyUserID, adminID)
	s.sessions.Remove(r.Context(), session.KeyImpersonator)
	s.sessions.Remove(r.Context(), session.KeyImpersonatorName)
	s.audit.Record(r.Context(), adminName, audit.ActionImpersonateEnd, impersonated.Username, "", s.clientIP(r))
	s.log.Info("impersonation ended", "admin", adminName, "target", impersonated.Username)
	http.Redirect(w, r, "/admin/users/"+impersonated.ID, http.StatusSeeOther)
}
