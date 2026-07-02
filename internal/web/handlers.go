package web

import (
	"errors"
	"net/http"

	"github.com/lporcheron/kivraid/internal/oidcserver"
	"github.com/lporcheron/kivraid/internal/session"
	"github.com/lporcheron/kivraid/internal/sources/local"
	"github.com/lporcheron/kivraid/internal/store/sqlcgen"
)

type loginData struct {
	CSRF     string
	Error    string
	Username string
	Next     string
}

type pageData struct {
	Title  string
	Active string
	CSRF   string
	User   sqlcgen.User
	Groups []sqlcgen.Group
	Data   any
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if s.sessions.GetString(r.Context(), session.KeyUserID) != "" {
		// Already authenticated: honor the next target (e.g. an OIDC flow
		// resume) instead of bouncing to the portal.
		http.Redirect(w, r, safeNext(r.URL.Query().Get("next"), "/"), http.StatusSeeOther)
		return
	}
	s.render(w, r, "login.html", loginData{
		CSRF: s.csrfToken(r.Context()),
		Next: safeNext(r.URL.Query().Get("next"), ""),
	})
}

func (s *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	username := r.PostFormValue("username")
	password := r.PostFormValue("password")
	next := safeNext(r.PostFormValue("next"), "/")

	user, err := s.local.Authenticate(r.Context(), username, password)
	if errors.Is(err, local.ErrBadCredentials) {
		w.WriteHeader(http.StatusUnauthorized)
		s.render(w, r, "login.html", loginData{
			CSRF:     s.csrfToken(r.Context()),
			Error:    "Invalid username or password.",
			Username: username,
			Next:     next,
		})
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}

	// A fresh token on privilege change prevents session fixation.
	if err := s.sessions.RenewToken(r.Context()); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.sessions.Put(r.Context(), session.KeyUserID, user.ID)
	s.log.Info("user logged in", "user", user.Username)
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if err := s.sessions.Destroy(r.Context()); err != nil {
		s.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	// The portal home becomes the application launcher in M3; until then
	// the profile is the only page.
	http.Redirect(w, r, "/profile", http.StatusSeeOther)
}

func (s *Server) handleProfile(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	groups, err := s.store.ListUserGroups(r.Context(), user.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, "profile.html", pageData{
		Title:  "Profile",
		Active: "profile",
		CSRF:   s.csrfToken(r.Context()),
		User:   user,
		Groups: groups,
	})
}

func (s *Server) handleOIDCResume(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" || s.oidcStore == nil {
		http.Error(w, "missing authorization request id", http.StatusBadRequest)
		return
	}
	user := currentUser(r)
	if err := s.oidcStore.CompleteAuthRequest(r.Context(), id, user.ID); err != nil {
		s.log.Warn("resume authorization request", "id", id, "err", err)
		http.Error(w, "authorization request not found or expired", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, oidcserver.CallbackPath(id), http.StatusSeeOther)
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, page string, data any) {
	t, ok := s.pages[page]
	if !ok {
		s.serverError(w, r, errors.New("unknown template "+page))
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.Execute(w, data); err != nil {
		s.log.Error("render template", "page", page, "err", err)
	}
}

func (s *Server) serverError(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Error("internal error", "method", r.Method, "path", r.URL.Path, "err", err)
	http.Error(w, "internal server error", http.StatusInternalServerError)
}
