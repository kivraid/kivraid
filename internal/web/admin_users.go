package web

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kivraid/kivraid/internal/audit"
	"github.com/kivraid/kivraid/internal/session"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
)

const usersPageSize = 50

type adminUsersData struct {
	Users       []sqlcgen.User
	SourceNames map[string]string // ldap_source_id → source name
	AdminVia    map[string]bool   // user IDs that are admins via a granting group
	Deleted     bool
	Query       string
	Page        int
	Pages       int
	Total       int64
	RangeStart  int64
	RangeEnd    int64
	PrevPage    int
	NextPage    int
}

type adminUserDetailData struct {
	Target      sqlcgen.User
	IsLDAP      bool
	SourceName  string
	Groups      []sqlcgen.Group
	AdminGroups []sqlcgen.Group // granting groups the user belongs to
	Sessions    []sessionInfo
	Error       string
	Saved       bool
	PWSaved     bool
	Revoked     bool
	Self        bool
	// Email verification (local users only).
	EmailVerified  bool
	CanVerifyEmail bool
	VerifySent     bool
	// CanResetPassword: local, or a directory that allows service-account reset.
	CanResetPassword bool
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

// likePattern turns a free-text search into a case-insensitive LIKE
// pattern, escaping the LIKE wildcards in the user's input. An empty
// search matches everything.
func likePattern(q string) string {
	if q == "" {
		return "%"
	}
	esc := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(strings.ToLower(q))
	return "%" + esc + "%"
}

func (s *Server) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	pattern := likePattern(query)

	total, err := s.store.CountUsersSearch(r.Context(), pattern)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	pages := int((total + usersPageSize - 1) / usersPageSize)
	if pages < 1 {
		pages = 1
	}
	page := 1
	if p, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && p > 1 {
		page = p
	}
	if page > pages {
		page = pages
	}

	users, err := s.store.ListUsersPage(r.Context(), sqlcgen.ListUsersPageParams{
		Pattern: pattern, PageLimit: usersPageSize, PageOffset: int32(page-1) * usersPageSize,
	})
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

	data := adminUsersData{
		Users: users, SourceNames: names, AdminVia: adminVia,
		Deleted: r.URL.Query().Get("deleted") == "1",
		Query:   query, Page: page, Pages: pages, Total: total,
		RangeStart: int64(page-1)*usersPageSize + 1,
		RangeEnd:   int64(page-1)*usersPageSize + int64(len(users)),
	}
	if total == 0 {
		data.RangeStart = 0
	}
	if page > 1 {
		data.PrevPage = page - 1
	}
	if page < pages {
		data.NextPage = page + 1
	}

	s.render(w, r, "admin_users.html", pageData{
		Title: "Users", Active: "users", CSRF: s.csrfToken(r.Context()),
		User: currentUser(r), Data: data,
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
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionUserCreate, user.Username, "", s.clientIP(r))
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

func (s *Server) renderUserDetail(w http.ResponseWriter, r *http.Request, target sqlcgen.User, errMsg string, saved, pwSaved, revoked bool) {
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
	// The user's active sessions. listUserSessions marks "Current" against
	// the admin's own token, which is only ever true when an admin views
	// their own account — correct in that case, false for everyone else.
	sessions, err := s.listUserSessions(r, target.ID)
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
			Groups: groups, AdminGroups: adminGroups, Sessions: sessions,
			Error: errMsg, Saved: saved, PWSaved: pwSaved, Revoked: revoked,
			Self:             target.ID == currentUser(r).ID,
			EmailVerified:    target.EmailVerified,
			CanVerifyEmail:   target.Source == "local" && !target.EmailVerified && s.smtpEnabled.Load(),
			VerifySent:       r.URL.Query().Get("vsent") == "1",
			CanResetPassword: s.canResetPassword(r.Context(), target),
		},
	})
}

func (s *Server) handleAdminUserDetail(w http.ResponseWriter, r *http.Request) {
	target, ok := s.loadTargetUser(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	s.renderUserDetail(w, r, target, "", q.Get("saved") == "1", q.Get("pw") == "1", q.Get("revoked") == "1")
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
		s.renderUserDetail(w, r, target, msg, false, false, false)
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
		emailChanged := email != target.Email
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
		// A new address is unverified until the user confirms it.
		if emailChanged {
			if err := s.store.SetEmailVerified(r.Context(), sqlcgen.SetEmailVerifiedParams{
				EmailVerified: false, UpdatedAt: now, ID: target.ID,
			}); err != nil {
				s.serverError(w, r, err)
				return
			}
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
	s.audit.Record(r.Context(), actor.Username, audit.ActionUserUpdate, target.Username, "", s.clientIP(r))
	http.Redirect(w, r, "/admin/users/"+target.ID+"?saved=1", http.StatusSeeOther)
}

func (s *Server) handleAdminUserPassword(w http.ResponseWriter, r *http.Request) {
	target, ok := s.loadTargetUser(w, r)
	if !ok {
		return
	}
	if !s.canResetPassword(r.Context(), target) {
		s.renderError(w, r, http.StatusBadRequest, "Directory-managed password",
			"This directory does not allow Kivraid to reset passwords. Enable it on the directory (Admin → Directories), or reset the password in the directory itself.")
		return
	}
	password := r.PostFormValue("password")
	if len(password) < 8 {
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.renderUserDetail(w, r, target, "The new password must be at least 8 characters.", false, false, false)
		return
	}
	if err := s.resetPassword(r.Context(), target, password); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionUserPWReset, target.Username, "", s.clientIP(r))
	http.Redirect(w, r, "/admin/users/"+target.ID+"?pw=1", http.StatusSeeOther)
}

func (s *Server) handleAdminUserDelete(w http.ResponseWriter, r *http.Request) {
	target, ok := s.loadTargetUser(w, r)
	if !ok {
		return
	}
	actor := currentUser(r)
	if target.ID == actor.ID {
		s.renderError(w, r, http.StatusBadRequest, "You cannot delete your own account",
			"Sign in as another administrator to delete this account.")
		return
	}
	s.revokeUserAccess(r.Context(), target.ID)
	if err := s.store.DeleteUser(r.Context(), target.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit.Record(r.Context(), actor.Username, audit.ActionUserDelete, target.Username, "", s.clientIP(r))
	http.Redirect(w, r, "/admin/users?deleted=1", http.StatusSeeOther)
}

// handleAdminUserSessionsRevoke signs a user out everywhere: all their
// sessions and OAuth tokens are dropped, forcing a fresh login.
func (s *Server) handleAdminUserSessionsRevoke(w http.ResponseWriter, r *http.Request) {
	target, ok := s.loadTargetUser(w, r)
	if !ok {
		return
	}
	s.revokeUserAccess(r.Context(), target.ID)
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionSessionRevoke, target.Username, "admin revoked all sessions", s.clientIP(r))
	http.Redirect(w, r, "/admin/users/"+target.ID+"?revoked=1", http.StatusSeeOther)
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
