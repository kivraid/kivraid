package web

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/lporcheron/kivraid/internal/oidcserver"
	"github.com/lporcheron/kivraid/internal/session"
	"github.com/lporcheron/kivraid/internal/sources/ldap"
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

	// Sources are tried in order: local accounts first, then the enabled
	// LDAP directories.
	user, err := s.local.Authenticate(r.Context(), username, password)
	if errors.Is(err, local.ErrBadCredentials) && s.ldap != nil {
		user, err = s.ldap.Authenticate(r.Context(), username, password)
		if errors.Is(err, ldap.ErrBadCredentials) {
			err = local.ErrBadCredentials
		}
	}
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
	s.sessions.Put(r.Context(), session.KeyIP, clientIP(r))
	s.sessions.Put(r.Context(), session.KeyUserAgent, r.UserAgent())
	s.sessions.Put(r.Context(), session.KeyLoginAt, time.Now().Unix())
	s.log.Info("user logged in", "user", user.Username, "source", user.Source)
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if err := s.sessions.Destroy(r.Context()); err != nil {
		s.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

type profileData struct {
	Groups      []sqlcgen.Group
	CanChangePW bool
	PWError     string
	PWSuccess   bool
}

func (s *Server) handleProfile(w http.ResponseWriter, r *http.Request) {
	s.renderProfile(w, r, currentUser(r), "", r.URL.Query().Get("pw") == "1")
}

func (s *Server) renderProfile(w http.ResponseWriter, r *http.Request, user sqlcgen.User, pwError string, pwSuccess bool) {
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
		Data: profileData{
			Groups:      groups,
			CanChangePW: s.canChangePassword(r, user),
			PWError:     pwError,
			PWSuccess:   pwSuccess,
		},
	})
}

func (s *Server) handleOIDCResume(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" || s.oidcStore == nil {
		http.Error(w, "missing authorization request id", http.StatusBadRequest)
		return
	}
	user := currentUser(r)

	clientID, err := s.oidcStore.ClientIDForAuthRequest(r.Context(), id)
	if err != nil {
		s.log.Warn("resume authorization request", "id", id, "err", err)
		http.Error(w, "authorization request not found or expired", http.StatusBadRequest)
		return
	}
	provider, err := s.store.GetProviderByClientID(r.Context(), clientID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	app, err := s.store.GetApplication(r.Context(), provider.ApplicationID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	allowed, err := s.userCanAccessApp(r.Context(), app.ID, user.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if !allowed {
		s.log.Info("application access denied", "app", app.Slug, "user", user.Username)
		w.WriteHeader(http.StatusForbidden)
		s.render(w, r, "denied.html", pageData{
			Title: "Access denied", CSRF: s.csrfToken(r.Context()),
			User: user, Data: app,
		})
		return
	}

	if err := s.oidcStore.CompleteAuthRequest(r.Context(), id, user.ID); err != nil {
		s.log.Warn("resume authorization request", "id", id, "err", err)
		http.Error(w, "authorization request not found or expired", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, oidcserver.CallbackPath(id), http.StatusSeeOther)
}

// userCanAccessApp evaluates the group policy: no bound groups means the
// application is open to every authenticated user.
func (s *Server) userCanAccessApp(ctx context.Context, appID, userID string) (bool, error) {
	total, err := s.store.CountAppPolicies(ctx, appID)
	if err != nil {
		return false, err
	}
	if total == 0 {
		return true, nil
	}
	matching, err := s.store.CountMatchingAppPolicies(ctx, sqlcgen.CountMatchingAppPoliciesParams{
		ApplicationID: appID, UserID: userID,
	})
	if err != nil {
		return false, err
	}
	return matching > 0, nil
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
