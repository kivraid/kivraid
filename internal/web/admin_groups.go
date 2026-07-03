package web

import (
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/lporcheron/kivraid/internal/audit"
	"github.com/lporcheron/kivraid/internal/store/sqlcgen"
)

type adminGroupsData struct {
	Groups      []sqlcgen.ListGroupsWithCountsRow
	SourceNames map[string]string
	Error       string
}

type adminGroupDetailData struct {
	Group      sqlcgen.Group
	IsLDAP     bool
	SourceName string
	Members    []sqlcgen.User
	NonMembers []sqlcgen.User
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
		User: currentUser(r), Data: adminGroupsData{Groups: groups, SourceNames: names, Error: errMsg},
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
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionGroupCreate, group.Name, "", clientIP(r))
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
	s.render(w, r, "admin_group_detail.html", pageData{
		Title: group.Name, Active: "groups", CSRF: s.csrfToken(r.Context()),
		User: currentUser(r),
		Data: adminGroupDetailData{
			Group: group, IsLDAP: group.Source == "ldap", SourceName: sourceName,
			Members: members, NonMembers: nonMembers, Error: errMsg,
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
		http.Error(w, "directory groups are managed in the directory", http.StatusBadRequest)
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
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionGroupUpdate, name, "renamed from "+group.Name, clientIP(r))
	http.Redirect(w, r, "/admin/groups/"+group.ID, http.StatusSeeOther)
}

func (s *Server) handleAdminGroupAddMember(w http.ResponseWriter, r *http.Request) {
	group, ok := s.loadGroup(w, r)
	if !ok {
		return
	}
	if group.Source != "local" {
		http.Error(w, "directory group memberships are managed in the directory", http.StatusBadRequest)
		return
	}
	userID := r.PostFormValue("user_id")
	if _, err := s.store.GetUserByID(r.Context(), userID); err != nil {
		http.Error(w, "unknown user", http.StatusBadRequest)
		return
	}
	if err := s.store.AddUserGroup(r.Context(), sqlcgen.AddUserGroupParams{UserID: userID, GroupID: group.ID}); err != nil && !isUniqueViolation(err) {
		s.serverError(w, r, err)
		return
	}
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionGroupUpdate, group.Name, "member added", clientIP(r))
	http.Redirect(w, r, "/admin/groups/"+group.ID, http.StatusSeeOther)
}

func (s *Server) handleAdminGroupRemoveMember(w http.ResponseWriter, r *http.Request) {
	group, ok := s.loadGroup(w, r)
	if !ok {
		return
	}
	if group.Source != "local" {
		http.Error(w, "directory group memberships are managed in the directory", http.StatusBadRequest)
		return
	}
	if err := s.store.RemoveUserGroup(r.Context(), sqlcgen.RemoveUserGroupParams{
		UserID: r.PostFormValue("user_id"), GroupID: group.ID,
	}); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionGroupUpdate, group.Name, "member removed", clientIP(r))
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
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionGroupDelete, group.Name, "", clientIP(r))
	http.Redirect(w, r, "/admin/groups", http.StatusSeeOther)
}
