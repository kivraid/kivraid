package web

import (
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kivraid/kivraid/internal/audit"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
)

type adminGroupsData struct {
	Groups      []sqlcgen.ListGroupsWithCountsRow
	SourceNames map[string]string
	Error       string
	Deleted     bool
}

type adminGroupDetailData struct {
	Group      sqlcgen.Group
	IsLDAP     bool
	SourceName string
	Members    []sqlcgen.User
	NonMembers []sqlcgen.User
	// Apps are the applications restricted to this group; LockedApps names
	// those for which it is the only group, which deleting it would lock.
	Apps       []sqlcgen.ListApplicationsByPolicyGroupRow
	LockedApps string
	Error      string
}

func (s *Server) renderGroups(w http.ResponseWriter, r *http.Request, errMsg string) {
	groups, err := s.store.ListGroupsWithCounts(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	names, err := s.ldapSourceNames(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, "admin_groups.html", pageData{
		Title: "Groups", Active: "groups", CSRF: s.csrfToken(r.Context()),
		User: currentUser(r), Data: adminGroupsData{
			Groups: groups, SourceNames: names, Error: errMsg,
			Deleted: r.URL.Query().Get("deleted") == "1",
		},
	})
}

func (s *Server) handleAdminGroups(w http.ResponseWriter, r *http.Request) {
	s.renderGroups(w, r, "")
}

func (s *Server) handleAdminGroupCreate(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" {
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.renderGroups(w, r, "Group name is required.")
		return
	}
	group, err := s.store.CreateGroup(r.Context(), sqlcgen.CreateGroupParams{
		ID: uuid.NewString(), Name: name, Source: "local", LdapSourceID: nil,
		CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		if isUniqueViolation(err) {
			w.WriteHeader(http.StatusUnprocessableEntity)
			s.renderGroups(w, r, "A group with this name already exists.")
			return
		}
		s.serverError(w, r, err)
		return
	}
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionGroupCreate, group.Name, "", s.clientIP(r))
	http.Redirect(w, r, "/admin/groups/"+group.ID, http.StatusSeeOther)
}

func (s *Server) loadGroup(w http.ResponseWriter, r *http.Request) (sqlcgen.Group, bool) {
	group, err := s.store.GetGroup(r.Context(), r.PathValue("id"))
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return group, false
	}
	if err != nil {
		s.serverError(w, r, err)
		return group, false
	}
	return group, true
}

func (s *Server) renderGroupDetail(w http.ResponseWriter, r *http.Request, group sqlcgen.Group, errMsg string) {
	members, err := s.store.ListGroupMembers(r.Context(), group.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	// Candidates for the "add member" select: everyone not yet a member.
	var nonMembers []sqlcgen.User
	if group.Source == "local" {
		all, err := s.store.ListUsers(r.Context())
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		isMember := make(map[string]bool, len(members))
		for _, m := range members {
			isMember[m.ID] = true
		}
		for _, u := range all {
			if !isMember[u.ID] {
				nonMembers = append(nonMembers, u)
			}
		}
	}
	sourceName := ""
	if group.LdapSourceID != nil {
		if names, err := s.ldapSourceNames(r.Context()); err == nil {
			sourceName = names[*group.LdapSourceID]
		}
	}
	apps, err := s.store.ListApplicationsByPolicyGroup(r.Context(), group.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	var locked []string
	for _, a := range apps {
		if a.GroupCount == 1 {
			locked = append(locked, a.Name)
		}
	}
	s.render(w, r, "admin_group_detail.html", pageData{
		Title: group.Name, Active: "groups", CSRF: s.csrfToken(r.Context()),
		User: currentUser(r),
		Data: adminGroupDetailData{
			Group: group, IsLDAP: group.Source == "ldap", SourceName: sourceName,
			Members: members, NonMembers: nonMembers, Apps: apps,
			LockedApps: strings.Join(locked, ", "), Error: errMsg,
		},
	})
}

func (s *Server) handleAdminGroupDetail(w http.ResponseWriter, r *http.Request) {
	group, ok := s.loadGroup(w, r)
	if !ok {
		return
	}
	s.renderGroupDetail(w, r, group, "")
}

func (s *Server) handleAdminGroupRename(w http.ResponseWriter, r *http.Request) {
	group, ok := s.loadGroup(w, r)
	if !ok {
		return
	}
	if group.Source != "local" {
		s.renderError(w, r, http.StatusBadRequest, "Directory-managed group",
			"This group is synced from a directory and is managed there.")
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" {
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.renderGroupDetail(w, r, group, "Group name is required.")
		return
	}
	if err := s.store.RenameGroup(r.Context(), sqlcgen.RenameGroupParams{Name: name, ID: group.ID}); err != nil {
		if isUniqueViolation(err) {
			w.WriteHeader(http.StatusUnprocessableEntity)
			s.renderGroupDetail(w, r, group, "A group with this name already exists.")
			return
		}
		s.serverError(w, r, err)
		return
	}
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionGroupUpdate, name, "renamed from "+group.Name, s.clientIP(r))
	http.Redirect(w, r, "/admin/groups/"+group.ID, http.StatusSeeOther)
}

func (s *Server) handleAdminGroupAddMember(w http.ResponseWriter, r *http.Request) {
	group, ok := s.loadGroup(w, r)
	if !ok {
		return
	}
	if group.Source != "local" {
		s.renderError(w, r, http.StatusBadRequest, "Directory-managed group",
			"Members of a directory group are managed in the directory.")
		return
	}
	userID := r.PostFormValue("user_id")
	if _, err := s.store.GetUserByID(r.Context(), userID); err != nil {
		s.renderError(w, r, http.StatusBadRequest, "Unknown user",
			"That user does not exist (it may have just been deleted).")
		return
	}
	if err := s.store.AddUserGroup(r.Context(), sqlcgen.AddUserGroupParams{UserID: userID, GroupID: group.ID}); err != nil && !isUniqueViolation(err) {
		s.serverError(w, r, err)
		return
	}
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionGroupUpdate, group.Name, "member added", s.clientIP(r))
	http.Redirect(w, r, "/admin/groups/"+group.ID, http.StatusSeeOther)
}

func (s *Server) handleAdminGroupRemoveMember(w http.ResponseWriter, r *http.Request) {
	group, ok := s.loadGroup(w, r)
	if !ok {
		return
	}
	if group.Source != "local" {
		s.renderError(w, r, http.StatusBadRequest, "Directory-managed group",
			"Members of a directory group are managed in the directory.")
		return
	}
	if err := s.store.RemoveUserGroup(r.Context(), sqlcgen.RemoveUserGroupParams{
		UserID: r.PostFormValue("user_id"), GroupID: group.ID,
	}); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionGroupUpdate, group.Name, "member removed", s.clientIP(r))
	http.Redirect(w, r, "/admin/groups/"+group.ID, http.StatusSeeOther)
}

// handleAdminGroupRole toggles whether the group grants the administrator
// role to its members. Allowed on directory groups too: the flag is
// Kivraid-side metadata, like the per-user flags.
func (s *Server) handleAdminGroupRole(w http.ResponseWriter, r *http.Request) {
	group, ok := s.loadGroup(w, r)
	if !ok {
		return
	}
	grants := r.PostFormValue("grants_admin") == "on"
	if err := s.store.UpdateGroupGrantsAdmin(r.Context(), sqlcgen.UpdateGroupGrantsAdminParams{
		GrantsAdmin: grants, ID: group.ID,
	}); err != nil {
		s.serverError(w, r, err)
		return
	}
	detail := "no longer grants the administrator role"
	if grants {
		detail = "now grants the administrator role"
	}
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionGroupUpdate, group.Name, detail, s.clientIP(r))
	http.Redirect(w, r, "/admin/groups/"+group.ID, http.StatusSeeOther)
}

func (s *Server) handleAdminGroupDelete(w http.ResponseWriter, r *http.Request) {
	group, ok := s.loadGroup(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteGroup(r.Context(), group.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionGroupDelete, group.Name, "", s.clientIP(r))
	http.Redirect(w, r, "/admin/groups?deleted=1", http.StatusSeeOther)
}
