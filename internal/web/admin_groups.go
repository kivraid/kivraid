package web

import (
	"database/sql"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kivraid/kivraid/internal/audit"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
)

const (
	groupsPageSize  = 50
	membersPageSize = 50
	// candidateLimit caps the add-member type-ahead suggestions.
	candidateLimit = 20
)

type adminGroupsData struct {
	Groups      []sqlcgen.ListGroupsPageRow
	SourceNames map[string]string
	Error       string
	Deleted     bool
	Query       string
	Source      string
	Filtered    bool
	Pager       pager
}

type adminGroupDetailData struct {
	Group       sqlcgen.Group
	IsLDAP      bool
	Editable    bool // local group: name and members are managed here
	SourceName  string
	Members     []sqlcgen.User
	MemberCount int64
	Pager       pager
	// Apps are the applications restricted to this group; LockedApps names
	// those for which it is the only group, which deleting it would lock.
	Apps       []sqlcgen.ListApplicationsByPolicyGroupRow
	LockedApps string
	Error      string
	Saved      bool
}

func (s *Server) renderGroups(w http.ResponseWriter, r *http.Request, errMsg string) {
	qv := r.URL.Query()
	query := strings.TrimSpace(qv.Get("q"))
	source := qv.Get("source")
	if source != "local" && source != "ldap" && source != "upstream" {
		source = ""
	}
	pattern := likePattern(query)
	total, err := s.store.CountGroupsSearch(r.Context(), sqlcgen.CountGroupsSearchParams{Pattern: pattern, Source: source})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	page, pages, limit, offset := pageWindow(r, "page", total, groupsPageSize)
	groups, err := s.store.ListGroupsPage(r.Context(), sqlcgen.ListGroupsPageParams{
		Pattern: pattern, Source: source, PageLimit: limit, PageOffset: offset,
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
	filters := url.Values{}
	if query != "" {
		filters.Set("q", query)
	}
	if source != "" {
		filters.Set("source", source)
	}
	s.render(w, r, "admin_groups.html", pageData{
		Title: "Groups", Active: "groups", CSRF: s.csrfToken(r.Context()),
		User: currentUser(r), Data: adminGroupsData{
			Groups: groups, SourceNames: names, Error: errMsg,
			Deleted: qv.Get("deleted") == "1",
			Query:   query, Source: source, Filtered: query != "" || source != "",
			Pager: newPager("page", template.URL(filters.Encode()), page, pages, total, groupsPageSize, len(groups)),
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
	total, err := s.store.CountGroupMembers(r.Context(), group.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	page, pages, limit, offset := pageWindow(r, "page", total, membersPageSize)
	members, err := s.store.ListGroupMembersPage(r.Context(), sqlcgen.ListGroupMembersPageParams{
		GroupID: group.ID, PageLimit: limit, PageOffset: offset,
	})
	if err != nil {
		s.serverError(w, r, err)
		return
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
			Group: group, IsLDAP: group.Source == "ldap", Editable: group.Source == "local", SourceName: sourceName,
			Members: members, MemberCount: total, Apps: apps,
			Pager: newPager("page", "", page, pages, total, membersPageSize, len(members)), Saved: r.URL.Query().Get("saved") == "1",
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

// handleAdminGroupUpdate saves the group settings: its name (local groups
// only — directory and federated names mirror their source) and whether it
// grants the administrator role, which is Kivraid-side metadata allowed on
// every group.
func (s *Server) handleAdminGroupUpdate(w http.ResponseWriter, r *http.Request) {
	group, ok := s.loadGroup(w, r)
	if !ok {
		return
	}
	actor := currentUser(r).Username
	if group.Source == "local" {
		name := strings.TrimSpace(r.PostFormValue("name"))
		if name == "" {
			w.WriteHeader(http.StatusUnprocessableEntity)
			s.renderGroupDetail(w, r, group, "Group name is required.")
			return
		}
		if name != group.Name {
			if err := s.store.RenameGroup(r.Context(), sqlcgen.RenameGroupParams{Name: name, ID: group.ID}); err != nil {
				if isUniqueViolation(err) {
					w.WriteHeader(http.StatusUnprocessableEntity)
					s.renderGroupDetail(w, r, group, "A group with this name already exists.")
					return
				}
				s.serverError(w, r, err)
				return
			}
			s.audit.Record(r.Context(), actor, audit.ActionGroupUpdate, name, "renamed from "+group.Name, s.clientIP(r))
			group.Name = name
		}
	}
	if grants := r.PostFormValue("grants_admin") == "on"; grants != group.GrantsAdmin {
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
		s.audit.Record(r.Context(), actor, audit.ActionGroupUpdate, group.Name, detail, s.clientIP(r))
	}
	http.Redirect(w, r, "/admin/groups/"+group.ID+"?saved=1", http.StatusSeeOther)
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
	// The member field is a type-ahead on usernames; user_id is accepted too.
	user, err := s.store.GetUserByID(r.Context(), r.PostFormValue("user_id"))
	if username := strings.ToLower(strings.TrimSpace(r.PostFormValue("username"))); username != "" {
		user, err = s.store.GetUserByUsername(r.Context(), username)
	}
	if err != nil {
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.renderGroupDetail(w, r, group, "No user with that username. Pick one from the suggestions.")
		return
	}
	userID := user.ID
	if err := s.store.AddUserGroup(r.Context(), sqlcgen.AddUserGroupParams{UserID: userID, GroupID: group.ID}); err != nil && !isUniqueViolation(err) {
		s.serverError(w, r, err)
		return
	}
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionGroupUpdate, group.Name, "member added: "+user.Username, s.clientIP(r))
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

// handleAdminGroupCandidates answers the add-member type-ahead: up to
// candidateLimit users matching the typed text who are not members yet.
func (s *Server) handleAdminGroupCandidates(w http.ResponseWriter, r *http.Request) {
	group, ok := s.loadGroup(w, r)
	if !ok {
		return
	}
	type candidate struct {
		Username string `json:"username"`
		Name     string `json:"name"`
	}
	out := []candidate{}
	if q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q"))); q != "" && group.Source == "local" {
		rows, err := s.store.SearchGroupCandidates(r.Context(), sqlcgen.SearchGroupCandidatesParams{
			Pattern: likePattern(q), GroupID: group.ID, MaxResults: candidateLimit,
		})
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		for _, u := range rows {
			out = append(out, candidate{Username: u.Username, Name: u.Name})
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(out)
}
