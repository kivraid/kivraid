package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/kivraid/kivraid/internal/session"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
)

type ctxKey int

const (
	ctxKeyUser ctxKey = iota
	// ctxKeyImpersonator carries the impersonating admin's display name when
	// the current session is an impersonation; empty otherwise.
	ctxKeyImpersonator
)

func (s *Server) secureHeaders(next http.Handler) http.Handler {
	// HSTS only makes sense (and is only safe to assert) when the
	// instance is actually served over TLS.
	hsts := strings.HasPrefix(s.cfg.BaseURL, "https://")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		if hsts {
			h.Set("Strict-Transport-Security", "max-age=63072000")
		}
		next.ServeHTTP(w, r)
	})
}

// requireAuth redirects anonymous requests to the login page and loads
// the current user into the request context.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := s.sessions.GetString(r.Context(), session.KeyUserID)
		if userID == "" {
			redirectToLogin(w, r)
			return
		}
		user, err := s.store.GetUserByID(r.Context(), userID)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && !user.Active) {
			// Account deleted or deactivated: the session is worthless.
			s.sessions.Destroy(r.Context())
			redirectToLogin(w, r)
			return
		}
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		// The administrator role is effective, not just stored: membership
		// in a granting group confers it for the duration of the request.
		if !user.IsAdmin {
			n, err := s.store.CountAdminGroupMemberships(r.Context(), user.ID)
			if err != nil {
				s.serverError(w, r, err)
				return
			}
			user.IsAdmin = n > 0
		}
		ctx := context.WithValue(r.Context(), ctxKeyUser, user)
		// Surface an active impersonation so every rendered page can show
		// the return-to-your-account banner.
		if name := s.sessions.GetString(r.Context(), session.KeyImpersonatorName); name != "" {
			ctx = context.WithValue(ctx, ctxKeyImpersonator, name)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// impersonator returns the display name of the admin impersonating the
// current user, or "" when the session is not an impersonation.
func impersonator(r *http.Request) string {
	name, _ := r.Context().Value(ctxKeyImpersonator).(string)
	return name
}

func redirectToLogin(w http.ResponseWriter, r *http.Request) {
	target := "/login"
	if r.URL.Path != "/" {
		target += "?next=" + url.QueryEscape(r.URL.RequestURI())
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func currentUser(r *http.Request) sqlcgen.User {
	user, _ := r.Context().Value(ctxKeyUser).(sqlcgen.User)
	return user
}

// csrfProtect enforces a session-bound token on every state-changing
// request. Templates embed the token via csrfToken as a hidden _csrf field.
func (s *Server) csrfProtect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		want := s.sessions.GetString(r.Context(), session.KeyCSRF)
		// Form posts carry the token in a hidden field; fetch-based callers
		// (WebAuthn ceremonies, which send a JSON body) use the header so the
		// request body is left intact for the handler to parse.
		got := r.Header.Get("X-CSRF-Token")
		if got == "" {
			got = r.PostFormValue("_csrf")
		}
		if want == "" || subtle.ConstantTimeCompare([]byte(want), []byte(got)) != 1 {
			// Fetch-based callers expect a plain error body, not a page.
			if r.Header.Get("X-CSRF-Token") != "" {
				http.Error(w, "invalid CSRF token", http.StatusForbidden)
				return
			}
			if want == "" {
				// No token in the session: it expired (or was revoked)
				// while a form sat open in a tab — by far the most common
				// way to land here, and not the user's fault.
				s.renderErrorAction(w, r, http.StatusForbidden, "Session expired",
					"Your session ended while this page was open, so the form could not be submitted. Sign in again to continue.",
					"Sign in again", "/login")
				return
			}
			s.renderErrorAction(w, r, http.StatusForbidden, "Form expired",
				"This form is no longer valid. Go back, reload the page, and try again.",
				"", "")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// csrfToken returns the session's CSRF token, creating it on first use.
func (s *Server) csrfToken(ctx context.Context) string {
	if tok := s.sessions.GetString(ctx, session.KeyCSRF); tok != "" {
		return tok
	}
	buf := make([]byte, 32)
	rand.Read(buf)
	tok := hex.EncodeToString(buf)
	s.sessions.Put(ctx, session.KeyCSRF, tok)
	return tok
}

// isLocalPath reports whether next is a same-site path (no scheme, no
// protocol-relative tricks).
func isLocalPath(next string) bool {
	return len(next) > 1 && next[0] == '/' && next[1] != '/' && next[1] != '\\'
}
