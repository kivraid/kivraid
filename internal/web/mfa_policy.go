package web

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/kivraid/kivraid/internal/audit"
	"github.com/kivraid/kivraid/internal/session"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
)

// How a session was authenticated, recorded at sign-in. Every method but a
// bare password counts as two-factor: TOTP adds a second factor, a passkey
// is phishing-resistant possession plus user verification, and federated
// sign-ins delegate authentication to the upstream provider.
const (
	loginPassword     = "password"
	loginPasswordTOTP = "password+totp"
	loginPasskey      = "passkey"
	loginFederated    = "federated"
)

// Instance-wide two-factor policies.
const (
	mfaPolicyOff    = "off"
	mfaPolicyAdmins = "admins"
	mfaPolicyAll    = "all"
)

var mfaPolicies = []string{mfaPolicyOff, mfaPolicyAdmins, mfaPolicyAll}

// mfaRequiredPath is where a session lacking a required second factor is
// sent to set one up.
const mfaRequiredPath = "/mfa/required"

// mfaSetupPaths stay reachable while a second factor is required, so the
// user can actually enroll one (or deal with a pending password change).
var mfaSetupPaths = []string{
	mfaRequiredPath, passwordChangePath,
	"/profile/mfa/begin", "/profile/mfa/qr", "/profile/mfa/enable",
	"/profile/passkeys/begin", "/profile/passkeys/finish",
}

func (s *Server) loadMFAPolicy(ctx context.Context) {
	row, err := s.store.GetInstanceSettings(ctx)
	if err != nil {
		if s.log != nil {
			s.log.Warn("load two-factor policy", "err", err)
		}
		return
	}
	policy := row.MfaPolicy
	if !slices.Contains(mfaPolicies, policy) {
		policy = mfaPolicyOff
	}
	s.mfaPolicy.Store(policy)
}

func (s *Server) currentMFAPolicy() string {
	if p, ok := s.mfaPolicy.Load().(string); ok {
		return p
	}
	return mfaPolicyOff
}

// mfaRequiredFor reports whether the instance policy demands a second factor
// from this user (whose IsAdmin is the effective role).
func (s *Server) mfaRequiredFor(user sqlcgen.User) bool {
	switch s.currentMFAPolicy() {
	case mfaPolicyAll:
		return true
	case mfaPolicyAdmins:
		return user.IsAdmin
	}
	return false
}

// sessionHasSecondFactor reports whether the current session was
// authenticated with more than a bare password. Sessions that predate the
// recorded method count as password-only.
func (s *Server) sessionHasSecondFactor(ctx context.Context) bool {
	switch s.sessions.GetString(ctx, session.KeyLoginMethod) {
	case loginPasswordTOTP, loginPasskey, loginFederated:
		return true
	}
	return false
}

// redirectToMFASetup sends the browser to set up a second factor, then back.
func (s *Server) redirectToMFASetup(w http.ResponseWriter, r *http.Request, next string) {
	http.Redirect(w, r, mfaRequiredPath+"?next="+url.QueryEscape(next), http.StatusSeeOther)
}

type mfaRequiredData struct {
	Next        string
	HasTOTP     bool // enrolled, but this session skipped it: sign in again
	HasPasskeys bool
	ForApp      bool // required by an application rather than the instance
}

// handleMFARequired explains why a second factor is needed and offers to
// set one up. A user who already has one but signed in without it (e.g. a
// session older than the policy) is asked to sign in again.
func (s *Server) handleMFARequired(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	next := s.safeNext(r.URL.Query().Get("next"), "/")
	if s.sessionHasSecondFactor(r.Context()) {
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}
	s.sessions.Put(r.Context(), session.KeyMFANext, next)
	data := mfaRequiredData{Next: next, HasTOTP: user.TotpEnabled, ForApp: !s.mfaRequiredFor(user)}
	if s.webauthn != nil {
		if n, err := s.webauthn.Count(r.Context(), user.ID); err == nil {
			data.HasPasskeys = n > 0
		}
	}
	s.render(w, r, "mfa_required.html", pageData{
		Title: "Two-factor required", CSRF: s.csrfToken(r.Context()), User: user, Data: data,
	})
}

// markSecondFactor upgrades the current session once the user has just
// proven a second factor while signed in (TOTP enrollment).
func (s *Server) markSecondFactor(ctx context.Context, method string) {
	if !s.sessionHasSecondFactor(ctx) {
		s.sessions.Put(ctx, session.KeyLoginMethod, method)
	}
}

// --- Settings → Security ---------------------------------------------------

type adminSecurityData struct {
	MFAPolicy string
	Saved     bool
	Error     string
}

func (s *Server) renderSecurity(w http.ResponseWriter, r *http.Request, errMsg string) {
	s.render(w, r, "admin_security.html", pageData{
		Title: "Security", Active: "security", CSRF: s.csrfToken(r.Context()), User: currentUser(r),
		Data: adminSecurityData{
			MFAPolicy: s.currentMFAPolicy(), Saved: r.URL.Query().Get("saved") == "1", Error: errMsg,
		},
	})
}

func (s *Server) handleAdminSecurity(w http.ResponseWriter, r *http.Request) {
	s.renderSecurity(w, r, "")
}

func (s *Server) handleAdminSecuritySave(w http.ResponseWriter, r *http.Request) {
	policy := r.PostFormValue("mfa_policy")
	if !slices.Contains(mfaPolicies, policy) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.renderSecurity(w, r, "Choose who must use two-factor authentication.")
		return
	}
	if err := s.store.SetMFAPolicy(r.Context(), sqlcgen.SetMFAPolicyParams{
		MfaPolicy: policy, UpdatedAt: time.Now().UTC(),
	}); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.loadMFAPolicy(r.Context())
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionSecurityUpdate, "", "mfa_policy="+policy, s.clientIP(r))
	http.Redirect(w, r, "/admin/settings/security?saved=1", http.StatusSeeOther)
}
