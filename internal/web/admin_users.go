package web

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/lporcheron/kivraid/internal/audit"
	"github.com/lporcheron/kivraid/internal/session"
	"github.com/lporcheron/kivraid/internal/store/sqlcgen"
)

type adminUsersData struct {
	Users       []sqlcgen.User
	SourceNames map[string]string // ldap_source_id → source name
	AdminVia    map[string]bool   // user IDs that are admins via a granting group
}

type adminUserDetailData struct {
	Target      sqlcgen.User
	IsLDAP      bool
	SourceName  string
	Groups      []sqlcgen.Group
	AdminGroups []sqlcgen.Group // granting groups the user belongs to
	Error       string
	Saved       bool
	PWSaved     bool
	Self        bool
}

type adminUserNewData struct {
	Form  userForm
	Error string
}

type userForm struct {
	Username string
	Email    string
	Name     string
	IsAdmin  bool
}

// ldapSourceNames maps source IDs to display names for the users list.
func (s *Server) ldapSourceNames(ctx context.Context) (map[string]string, error) {
	sources, err := s.store.ListLdapSources(ctx)
	if err != nil {
		return nil, err
	}
	names := make(map[string]string, len(sources))
	for _, src := range sources {
		names[src.ID] = src.Name
	}
	return names, nil
}

func (s *Server) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	names, err := s.ldapSourceNames(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	viaIDs, err := s.store.ListAdminGroupMemberIDs(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	adminVia := make(map[string]bool, len(viaIDs))
	for _, id := range viaIDs {
		adminVia[id] = true
	}
	s.render(w, r, "admin_users.html", pageData{
		Title: "Users", Active: "users", CSRF: s.csrfToken(r.Context()),
		User: currentUser(r), Data: adminUsersData{Users: users, SourceNames: names, AdminVia: adminVia},
	})
}

func (s *Server) handleAdminUserNew(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "admin_user_new.html", pageData{
		Title: "New user", Active: "users", CSRF: s.csrfToken(r.Context()),
		User: currentUser(r), Data: adminUserNewData{},
	})
}

func (s *Server) handleAdminUserCreate(w http.ResponseWriter, r *http.Request) {
	form := userForm{
		Username: strings.ToLower(strings.TrimSpace(r.PostFormValue("username"))),
		Email:    strings.ToLower(strings.TrimSpace(r.PostFormValue("email"))),
		Name:     strings.TrimSpace(r.PostFormValue("name")),
		IsAdmin:  r.PostFormValue("is_admin") == "on",
	}
	password := r.PostFormValue("password")

	fail := func(msg string) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.render(w, r, "admin_user_new.html", pageData{
			Title: "New user", Active: "users", CSRF: s.csrfToken(r.Context()),
			User: currentUser(r), Data: adminUserNewData{Form: form, Error: msg},
		})
	}
	if form.Username == "" || form.Email == "" {
		fail("Username and email are required.")
		return
	}
	if form.Name == "" {
		form.Name = form.Username
	}
	if len(password) < 8 {
		fail("The password must be at least 8 characters.")
		return
	}

	user, err := s.local.CreateUser(r.Context(), form.Username, form.Email, form.Name, password, form.IsAdmin)
	if err != nil {
		if isUniqueViolation(err) {
			fail("A user with this username or email already exists.")
			return
		}
		s.serverError(w, r, err)
		return
	}
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionUserCreate, user.Username, "", clientIP(r))
	http.Redirect(w, r, "/admin/users/"+user.ID, http.StatusSeeOther)
}

func (s *Server) loadTargetUser(w http.ResponseWriter, r *http.Request) (sqlcgen.User, bool) {
	target, err := s.store.GetUserByID(r.Context(), r.PathValue("id"))
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return target, false
	}
	if err != nil {
		s.serverError(w, r, err)
		return target, false
	}
	return target, true
}

func (s *Server) renderUserDetail(w http.ResponseWriter, r *http.Request, target sqlcgen.User, errMsg string, saved, pwSaved bool) {
	groups, err := s.store.ListUserGroups(r.Context(), target.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	adminGroups, err := s.store.ListUserAdminGroups(r.Context(), target.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	sourceName := ""
	if target.LdapSourceID != nil {
		if names, err := s.ldapSourceNames(r.Context()); err == nil {
			sourceName = names[*target.LdapSourceID]
		}
	}
	s.render(w, r, "admin_user_detail.html", pageData{
		Title: target.Name, Active: "users", CSRF: s.csrfToken(r.Context()),
		User: currentUser(r),
		Data: adminUserDetailData{
			Target: target, IsLDAP: target.Source == "ldap", SourceName: sourceName,
			Groups: groups, AdminGroups: adminGroups,
			Error: errMsg, Saved: saved, PWSaved: pwSaved,
			Self: target.ID == currentUser(r).ID,
		},
	})
}

func (s *Server) handleAdminUserDetail(w http.ResponseWriter, r *http.Request) {
	target, ok := s.loadTargetUser(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	s.renderUserDetail(w, r, target, "", q.Get("saved") == "1", q.Get("pw") == "1")
}

func (s *Server) handleAdminUserUpdate(w http.ResponseWriter, r *http.Request) {
	target, ok := s.loadTargetUser(w, r)
	if !ok {
		return
	}
	actor := currentUser(r)
	isAdmin := r.PostFormValue("is_admin") == "on"
	active := r.PostFormValue("active") == "on"

	fail := func(msg string) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.renderUserDetail(w, r, target, msg, false, false)
	}

	// Footgun guards: you cannot lock yourself out, and the instance
	// always keeps one active administrator.
	if target.ID == actor.ID && (!isAdmin || !active) {
		fail("You cannot deactivate your own account or remove your own administrator role.")
		return
	}
	if target.IsAdmin && target.Active && (!isAdmin || !active) {
		admins, err := s.store.CountActiveAdmins(r.Context())
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		if admins <= 1 {
			fail("This is the last active administrator.")
			return
		}
	}

	now := time.Now().UTC()
	// Identity fields are directory-owned for LDAP users.
	if target.Source == "local" {
		name := strings.TrimSpace(r.PostFormValue("name"))
		email := strings.ToLower(strings.TrimSpace(r.PostFormValue("email")))
		if name == "" || email == "" {
			fail("Name and email are required.")
			return
		}
		if err := s.store.UpdateUserIdentity(r.Context(), sqlcgen.UpdateUserIdentityParams{
			Name: name, Email: email, UpdatedAt: now, ID: target.ID,
		}); err != nil {
			if isUniqueViolation(err) {
				fail("Another user already has this email.")
				return
			}
			s.serverError(w, r, err)
			return
		}
	}
	if err := s.store.UpdateUserFlags(r.Context(), sqlcgen.UpdateUserFlagsParams{
		IsAdmin: isAdmin, Active: active, UpdatedAt: now, ID: target.ID,
	}); err != nil {
		s.serverError(w, r, err)
		return
	}
	if !active {
		s.revokeUserAccess(r.Context(), target.ID)
	}
	s.audit.Record(r.Context(), actor.Username, audit.ActionUserUpdate, target.Username, "", clientIP(r))
	http.Redirect(w, r, "/admin/users/"+target.ID+"?saved=1", http.StatusSeeOther)
}

func (s *Server) handleAdminUserPassword(w http.ResponseWriter, r *http.Request) {
	target, ok := s.loadTargetUser(w, r)
	if !ok {
		return
	}
	if target.Source != "local" {
		http.Error(w, "directory users change their password in the directory", http.StatusBadRequest)
		return
	}
	password := r.PostFormValue("password")
	if len(password) < 8 {
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.renderUserDetail(w, r, target, "The new password must be at least 8 characters.", false, false)
		return
	}
	if err := s.local.SetPassword(r.Context(), target.ID, password); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionUserPWReset, target.Username, "", clientIP(r))
	http.Redirect(w, r, "/admin/users/"+target.ID+"?pw=1", http.StatusSeeOther)
}

func (s *Server) handleAdminUserDelete(w http.ResponseWriter, r *http.Request) {
	target, ok := s.loadTargetUser(w, r)
	if !ok {
		return
	}
	actor := currentUser(r)
	if target.ID == actor.ID {
		http.Error(w, "you cannot delete your own account", http.StatusBadRequest)
		return
	}
	s.revokeUserAccess(r.Context(), target.ID)
	if err := s.store.DeleteUser(r.Context(), target.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit.Record(r.Context(), actor.Username, audit.ActionUserDelete, target.Username, "", clientIP(r))
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

// revokeUserAccess kills the user's sessions and OAuth tokens; used when
// an account is deactivated or deleted.
func (s *Server) revokeUserAccess(ctx context.Context, userID string) {
	if err := s.sessions.Iterate(ctx, func(sctx context.Context) error {
		if s.sessions.GetString(sctx, session.KeyUserID) == userID {
			return s.sessions.Store.Delete(s.sessions.Token(sctx))
		}
		return nil
	}); err != nil {
		s.log.Warn("revoke sessions", "user", userID, "err", err)
	}
	if err := s.store.DeleteAccessTokensByUser(ctx, userID); err != nil {
		s.log.Warn("revoke access tokens", "user", userID, "err", err)
	}
	if err := s.store.DeleteRefreshTokensByUser(ctx, userID); err != nil {
		s.log.Warn("revoke refresh tokens", "user", userID, "err", err)
	}
}
