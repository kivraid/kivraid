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

	"github.com/lporcheron/kivraid/internal/session"
	"github.com/lporcheron/kivraid/internal/store/sqlcgen"
)

type ctxKey int

const ctxKeyUser ctxKey = iota

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
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
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKeyUser, user)))
	})
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
		got := r.PostFormValue("_csrf")
		if want == "" || subtle.ConstantTimeCompare([]byte(want), []byte(got)) != 1 {
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
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
