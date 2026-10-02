package web

import (
	"context"
	"database/sql"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kivraid/kivraid/internal/audit"
	"github.com/kivraid/kivraid/internal/session"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
)

const usersPageSize = 50

type adminUsersData struct {
	Users         []sqlcgen.User
	SourceNames   map[string]string // ldap_source_id → source name
	UpstreamNames map[string]string // upstream_source_id → provider name
	// Filters, echoed back into the form and the pagination links.
	Source     string
	Status     string
	AdminsOnly bool
	Filtered   bool
	FilterQS   template.URL    // encoded filters for pagination links (already escaped)
	AdminVia   map[string]bool // user IDs that are admins via a granting group
	Deleted    bool
	Query      string
	Page       int
	Pages      int
	Total      int64
	RangeStart int64
	RangeEnd   int64
	PrevPage   int
	NextPage   int
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
	// CanSendReset: a reset link can be emailed (SMTP on, address known).
	CanSendReset bool
	// Groups the user can still be added to (local groups only).
	AddableGroups []sqlcgen.Group
	Passkeys      []sqlcgen.WebauthnCredential
	Flash         string
	FlashError    string
}

type adminUserNewData struct {
	Form        userForm
	Error       string
	LocalGroups []sqlcgen.Group
	CanInvite   bool
}

// localGroups lists the groups an administrator can add members to.
func (s *Server) localGroups(ctx context.Context) ([]sqlcgen.Group, error) {
	all, err := s.store.ListGroups(ctx)
	if err != nil {
		return nil, err
	}
	var out []sqlcgen.Group
	for _, g := range all {
		if g.Source == "local" {
			out = append(out, g)
		}
	}
	return out, nil
}

func (s *Server) renderUserNew(w http.ResponseWriter, r *http.Request, form userForm, errMsg string) {
	groups, err := s.localGroups(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if errMsg != "" {
		w.WriteHeader(http.StatusUnprocessableEntity)
	}
	s.render(w, r, "admin_user_new.html", pageData{
		Title: "New user", Active: "users", CSRF: s.csrfToken(r.Context()),
		User: currentUser(r), Data: adminUserNewData{
			Form: form, Error: errMsg, LocalGroups: groups, CanInvite: s.smtpEnabled.Load(),
		},
	})
}

type userForm struct {
	Username string
	Email    string
	Name     string
	IsAdmin  bool
	// Invite emails a set-your-password link instead of taking a password.
	Invite bool
	// MustChange makes the user replace the given password at first sign-in.
	MustChange bool
	Groups     map[string]bool
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
	qv := r.URL.Query()
	query := strings.TrimSpace(qv.Get("q"))
	pattern := likePattern(query)
	source := qv.Get("source")
	if source != "local" && source != "ldap" && source != "upstream" {
		source = ""
	}
	status := qv.Get("status")
	if status != "active" && status != "inactive" {
		status = ""
	}
	adminsOnly := qv.Get("role") == "admin"

	total, err := s.store.CountUsersSearch(r.Context(), sqlcgen.CountUsersSearchParams{
		Pattern: pattern, Source: source, Status: status, AdminsOnly: adminsOnly,
	})
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
		Pattern: pattern, Source: source, Status: status, AdminsOnly: adminsOnly,
		PageLimit: usersPageSize, PageOffset: int32(page-1) * usersPageSize,
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

	upstreamNames := map[string]string{}
	if ups, err := s.store.ListUpstreamProviders(r.Context()); err == nil {
		for _, p := range ups {
			upstreamNames[p.ID] = p.Name
		}
	}
	filters := url.Values{}
	for k, v := range map[string]string{"q": query, "source": source, "status": status} {
		if v != "" {
			filters.Set(k, v)
		}
	}
	if adminsOnly {
		filters.Set("role", "admin")
	}

	data := adminUsersData{
		Users: users, SourceNames: names, UpstreamNames: upstreamNames, AdminVia: adminVia,
		Source: source, Status: status, AdminsOnly: adminsOnly,
		Filtered: source != "" || status != "" || adminsOnly, FilterQS: template.URL(filters.Encode()),
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
	s.renderUserNew(w, r, userForm{MustChange: true}, "")
}

func (s *Server) handleAdminUserCreate(w http.ResponseWriter, r *http.Request) {
	form := userForm{
		Username:   strings.ToLower(strings.TrimSpace(r.PostFormValue("username"))),
		Email:      strings.ToLower(strings.TrimSpace(r.PostFormValue("email"))),
		Name:       strings.TrimSpace(r.PostFormValue("name")),
		IsAdmin:    r.PostFormValue("is_admin") == "on",
		Invite:     r.PostFormValue("password_mode") == "invite" && s.smtpEnabled.Load(),
		MustChange: r.PostFormValue("must_change") == "on",
		Groups:     map[string]bool{},
	}
	for _, id := range r.PostForm["groups"] {
		form.Groups[id] = true
	}
	password := r.PostFormValue("password")

	fail := func(msg string) { s.renderUserNew(w, r, form, msg) }
	if form.Username == "" || form.Email == "" {
		fail(s.t(r, "Username and email are required."))
		return
	}
	if form.Name == "" {
		form.Name = form.Username
	}
	if form.Invite {
		// The user chooses their password from the invitation; until then
		// the account holds a random one nobody knows.
		password, form.MustChange = randomHex(32), false
	} else if len(password) < 8 {
		fail(s.t(r, "The password must be at least 8 characters."))
		return
	}
	groups, err := s.localGroups(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}

	user, err := s.local.CreateUser(r.Context(), form.Username, form.Email, form.Name, password, form.IsAdmin)
	if err != nil {
		if isUniqueViolation(err) {
			fail(s.t(r, "A user with this username or email already exists."))
			return
		}
		s.serverError(w, r, err)
		return
	}
	actor := currentUser(r).Username
	s.audit.Record(r.Context(), actor, audit.ActionUserCreate, user.Username, "", s.clientIP(r))
	for _, g := range groups {
		if !form.Groups[g.ID] {
			continue
		}
		if err := s.store.AddUserGroup(r.Context(), sqlcgen.AddUserGroupParams{UserID: user.ID, GroupID: g.ID}); err != nil {
			s.serverError(w, r, err)
			return
		}
		s.audit.Record(r.Context(), actor, audit.ActionGroupUpdate, g.Name, "member added: "+user.Username, s.clientIP(r))
	}
	if form.MustChange {
		if err := s.store.SetUserMustChangePassword(r.Context(), sqlcgen.SetUserMustChangePasswordParams{
			MustChangePassword: true, ID: user.ID,
		}); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	dest := "/admin/users/" + user.ID
	if form.Invite {
		if err := s.sendInvitationEmail(r.Context(), userLang(user, r), user); err != nil {
			s.log.Warn("send invitation", "user", user.Username, "err", err)
			dest += "?notice=invite-failed"
		} else {
			dest += "?notice=invite-sent"
		}
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
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
	local, err := s.localGroups(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	member := make(map[string]bool, len(groups))
	for _, g := range groups {
		member[g.ID] = true
	}
	var addable []sqlcgen.Group
	for _, g := range local {
		if !member[g.ID] {
			addable = append(addable, g)
		}
	}
	var passkeys []sqlcgen.WebauthnCredential
	if s.webauthn != nil {
		if passkeys, err = s.webauthn.List(r.Context(), target.ID); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	flash, flashErr := "", ""
	switch r.URL.Query().Get("notice") {
	case "invite-sent":
		flash = s.t(r, "Invitation sent to %s.", target.Email)
	case "invite-failed":
		flashErr = s.t(r, "The account was created, but the invitation email could not be sent. Check Settings → Email, then send a reset link below.")
	case "reset-sent":
		flash = s.t(r, "Password reset link sent to %s.", target.Email)
	case "reset-failed":
		flashErr = s.t(r, "The reset link could not be sent. Check Settings → Email.")
	case "group-added":
		flash = s.t(r, "Added to the group.")
	case "group-removed":
		flash = s.t(r, "Removed from the group.")
	case "passkey-removed":
		flash = s.t(r, "Passkey removed.")
	}
	canReset := s.canResetPassword(r.Context(), target)
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
			CanResetPassword: canReset,
			CanSendReset:     canReset && target.Email != "" && s.smtpEnabled.Load(),
			AddableGroups:    addable, Passkeys: passkeys,
			Flash: flash, FlashError: flashErr,
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
		fail(s.t(r, "You cannot deactivate your own account or remove your own administrator role."))
		return
	}
	if target.IsAdmin && target.Active && (!isAdmin || !active) {
		admins, err := s.store.CountActiveAdmins(r.Context())
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		if admins <= 1 {
			fail(s.t(r, "This is the last active administrator."))
			return
		}
	}

	now := time.Now().UTC()
	// Identity fields are directory-owned for LDAP users.
	if target.Source == "local" {
		name := strings.TrimSpace(r.PostFormValue("name"))
		email := strings.ToLower(strings.TrimSpace(r.PostFormValue("email")))
		if name == "" || email == "" {
			fail(s.t(r, "Name and email are required."))
			return
		}
		emailChanged := email != target.Email
		if err := s.store.UpdateUserIdentity(r.Context(), sqlcgen.UpdateUserIdentityParams{
			Name: name, Email: email, UpdatedAt: now, ID: target.ID,
		}); err != nil {
			if isUniqueViolation(err) {
				fail(s.t(r, "Another user already has this email."))
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
		s.renderError(w, r, http.StatusBadRequest, s.t(r, "Directory-managed password"),
			s.t(r, "This directory does not allow Kivraid to reset passwords. Enable it on the directory (Admin → Directories), or reset the password in the directory itself."))
		return
	}
	password := r.PostFormValue("password")
	if len(password) < 8 {
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.renderUserDetail(w, r, target, s.t(r, "The new password must be at least 8 characters."), false, false, false)
		return
	}
	if err := s.resetPassword(r.Context(), target, password); err != nil {
		s.serverError(w, r, err)
		return
	}
	if target.Source == "local" && r.PostFormValue("must_change") == "on" {
		if err := s.store.SetUserMustChangePassword(r.Context(), sqlcgen.SetUserMustChangePasswordParams{
			MustChangePassword: true, ID: target.ID,
		}); err != nil {
			s.serverError(w, r, err)
			return
		}
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
		s.renderError(w, r, http.StatusBadRequest, s.t(r, "You cannot delete your own account"),
			s.t(r, "Sign in as another administrator to delete this account."))
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

// handleAdminUserSendReset emails the user a password reset link, so the
// administrator never has to know or transmit the new password.
func (s *Server) handleAdminUserSendReset(w http.ResponseWriter, r *http.Request) {
	target, ok := s.loadTargetUser(w, r)
	if !ok {
		return
	}
	if !s.canResetPassword(r.Context(), target) || target.Email == "" || !s.smtpEnabled.Load() {
		s.renderError(w, r, http.StatusBadRequest, s.t(r, "Cannot send a reset link"),
			s.t(r, "A reset link needs email delivery (Settings → Email), an address on the account, and a source that lets Kivraid set passwords."))
		return
	}
	notice := "reset-sent"
	raw, err := s.issueEmailToken(r.Context(), purposePasswordReset, target.ID, target.Email, resetTokenTTL)
	if err == nil {
		err = s.sendPasswordResetEmail(r.Context(), userLang(target, r), target, raw)
	}
	if err != nil {
		s.log.Warn("send reset link", "user", target.Username, "err", err)
		notice = "reset-failed"
	} else {
		s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionPasswordReset, target.Username, "link sent by admin", s.clientIP(r))
	}
	http.Redirect(w, r, "/admin/users/"+target.ID+"?notice="+notice, http.StatusSeeOther)
}

// handleAdminUserGroupAdd and handleAdminUserGroupRemove manage a user's
// local group memberships from their page (directory and federated groups
// are mirrored, not edited).
func (s *Server) handleAdminUserGroupAdd(w http.ResponseWriter, r *http.Request) {
	s.changeUserGroup(w, r, true)
}

func (s *Server) handleAdminUserGroupRemove(w http.ResponseWriter, r *http.Request) {
	s.changeUserGroup(w, r, false)
}

func (s *Server) changeUserGroup(w http.ResponseWriter, r *http.Request, add bool) {
	target, ok := s.loadTargetUser(w, r)
	if !ok {
		return
	}
	group, err := s.store.GetGroup(r.Context(), r.PostFormValue("group_id"))
	if errors.Is(err, sql.ErrNoRows) || (err == nil && group.Source != "local") {
		s.renderError(w, r, http.StatusBadRequest, s.t(r, "Group not editable"),
			s.t(r, "Only local groups can be edited here; directory and federated groups mirror their source."))
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	params := sqlcgen.AddUserGroupParams{UserID: target.ID, GroupID: group.ID}
	notice, detail := "group-added", "member added: "
	if add {
		err = s.store.AddUserGroup(r.Context(), params)
	} else {
		err = s.store.RemoveUserGroup(r.Context(), sqlcgen.RemoveUserGroupParams(params))
		notice, detail = "group-removed", "member removed: "
	}
	if err != nil && !isUniqueViolation(err) {
		s.serverError(w, r, err)
		return
	}
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionGroupUpdate, group.Name, detail+target.Username, s.clientIP(r))
	http.Redirect(w, r, "/admin/users/"+target.ID+"?notice="+notice, http.StatusSeeOther)
}

// handleAdminUserPasskeyDelete removes one of the user's passkeys, e.g. for
// a lost device.
func (s *Server) handleAdminUserPasskeyDelete(w http.ResponseWriter, r *http.Request) {
	target, ok := s.loadTargetUser(w, r)
	if !ok {
		return
	}
	if s.webauthn == nil {
		http.NotFound(w, r)
		return
	}
	if err := s.webauthn.Delete(r.Context(), target.ID, r.PathValue("pk")); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionPasskeyRemove, target.Username, "by admin", s.clientIP(r))
	http.Redirect(w, r, "/admin/users/"+target.ID+"?notice=passkey-removed", http.StatusSeeOther)
}
