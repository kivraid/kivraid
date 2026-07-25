package web

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kivraid/kivraid/internal/audit"
	"github.com/kivraid/kivraid/internal/secrets"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
)

type ldapForm struct {
	Name          string
	URL           string
	StartTLS      bool
	SkipTLSVerify bool
	BindDN        string
	BindPassword  string // write-only; empty on edit keeps the stored value
	BaseDN        string
	UserFilter    string
	UsernameAttr  string
	EmailAttr     string
	NameAttr      string
	PhotoAttr     string
	GroupFilter   string
	GroupNameAttr string
	Writeback     bool
	Reset         bool
	Enabled       bool
}

type ldapTestResult struct {
	OK      bool
	Message string
	DN      string
	Email   string
	Groups  []string
}

type adminLdapListData struct {
	Sources []sqlcgen.LdapSource
	Deleted bool
}

type adminLdapFormData struct {
	IsNew      bool
	ID         string
	Form       ldapForm
	Error      string
	Saved      bool
	TestResult *ldapTestResult
	SyncResult *ldapTestResult
}

func formFromSource(src sqlcgen.LdapSource) ldapForm {
	return ldapForm{
		Name: src.Name, URL: src.Url, StartTLS: src.StartTls, SkipTLSVerify: src.SkipTlsVerify,
		BindDN: src.BindDn, BaseDN: src.BaseDn, UserFilter: src.UserFilter,
		UsernameAttr: src.UsernameAttr, EmailAttr: src.EmailAttr, NameAttr: src.NameAttr,
		PhotoAttr:   src.PhotoAttr,
		GroupFilter: src.GroupFilter, GroupNameAttr: src.GroupNameAttr,
		Writeback: src.PasswordWriteback, Reset: src.PasswordReset, Enabled: src.Enabled,
	}
}

func parseLdapForm(r *http.Request) ldapForm {
	str := func(name string) string { return strings.TrimSpace(r.PostFormValue(name)) }
	f := ldapForm{
		Name:          str("name"),
		URL:           str("url"),
		StartTLS:      r.PostFormValue("start_tls") == "on",
		SkipTLSVerify: r.PostFormValue("skip_tls_verify") == "on",
		BindDN:        str("bind_dn"),
		BindPassword:  r.PostFormValue("bind_password"),
		BaseDN:        str("base_dn"),
		UserFilter:    str("user_filter"),
		UsernameAttr:  str("username_attr"),
		EmailAttr:     str("email_attr"),
		NameAttr:      str("name_attr"),
		PhotoAttr:     str("photo_attr"),
		GroupFilter:   str("group_filter"),
		GroupNameAttr: str("group_name_attr"),
		Writeback:     r.PostFormValue("password_writeback") == "on",
		Reset:         r.PostFormValue("password_reset") == "on",
		Enabled:       r.PostFormValue("enabled") == "on",
	}
	if f.UsernameAttr == "" {
		f.UsernameAttr = "uid"
	}
	if f.EmailAttr == "" {
		f.EmailAttr = "mail"
	}
	if f.NameAttr == "" {
		f.NameAttr = "cn"
	}
	if f.GroupNameAttr == "" {
		f.GroupNameAttr = "cn"
	}
	return f
}

func (f *ldapForm) validate() error {
	if f.Name == "" {
		return errors.New("Name is required.")
	}
	u, err := url.Parse(f.URL)
	if err != nil || (u.Scheme != "ldap" && u.Scheme != "ldaps") || u.Host == "" {
		return errors.New("URL must look like ldap://host:389 or ldaps://host:636.")
	}
	if f.BaseDN == "" {
		return errors.New("Base DN is required.")
	}
	if !strings.Contains(f.UserFilter, "{username}") {
		return errors.New("User filter must contain the {username} placeholder.")
	}
	if f.GroupFilter != "" && !strings.Contains(f.GroupFilter, "{dn}") && !strings.Contains(f.GroupFilter, "{username}") {
		return errors.New("Group filter must contain a {dn} or {username} placeholder (or be empty to disable group sync).")
	}
	return nil
}

func (s *Server) handleAdminLdapList(w http.ResponseWriter, r *http.Request) {
	sources, err := s.store.ListLdapSources(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, "admin_ldap.html", pageData{
		Title: "Directories", Active: "ldap", CSRF: s.csrfToken(r.Context()),
		User: currentUser(r), Data: adminLdapListData{Sources: sources, Deleted: r.URL.Query().Get("deleted") == "1"},
	})
}

func (s *Server) renderLdapForm(w http.ResponseWriter, r *http.Request, data adminLdapFormData) {
	title := "Edit directory"
	if data.IsNew {
		title = "New directory"
	}
	// A freshly-typed bind password can be echoed back into the form (see
	// the template) so it survives a test round-trip; keep that out of the
	// browser cache.
	w.Header().Set("Cache-Control", "no-store")
	s.render(w, r, "admin_ldap_form.html", pageData{
		Title: title, Active: "ldap", CSRF: s.csrfToken(r.Context()),
		User: currentUser(r), Data: data,
	})
}

func (s *Server) handleAdminLdapNew(w http.ResponseWriter, r *http.Request) {
	s.renderLdapForm(w, r, adminLdapFormData{IsNew: true, Form: ldapForm{
		UsernameAttr: "uid", EmailAttr: "mail", NameAttr: "cn", PhotoAttr: "jpegPhoto",
		GroupNameAttr: "cn",
		Writeback:     true, Enabled: true,
	}})
}

func (s *Server) handleAdminLdapCreate(w http.ResponseWriter, r *http.Request) {
	form := parseLdapForm(r)
	fail := func(msg string) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.renderLdapForm(w, r, adminLdapFormData{IsNew: true, Form: form, Error: msg})
	}
	if err := form.validate(); err != nil {
		fail(err.Error())
		return
	}
	if form.BindDN != "" && form.BindPassword == "" {
		fail("Bind password is required (leave the bind DN empty for anonymous binds).")
		return
	}
	sealed, err := secrets.Seal(s.ldap.SealKey(), []byte(form.BindPassword))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	now := time.Now().UTC()
	src, err := s.store.CreateLdapSource(r.Context(), sqlcgen.CreateLdapSourceParams{
		ID: uuid.NewString(), Name: form.Name, Url: form.URL,
		StartTls: form.StartTLS, SkipTlsVerify: form.SkipTLSVerify,
		BindDn: form.BindDN, BindPasswordEnc: sealed, BaseDn: form.BaseDN,
		UserFilter: form.UserFilter, UsernameAttr: form.UsernameAttr,
		EmailAttr: form.EmailAttr, NameAttr: form.NameAttr, PhotoAttr: form.PhotoAttr,
		GroupFilter: form.GroupFilter, GroupNameAttr: form.GroupNameAttr,
		PasswordWriteback: form.Writeback, PasswordReset: form.Reset,
		Enabled: form.Enabled, Position: 0, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		if isUniqueViolation(err) {
			fail("A directory with this name already exists.")
			return
		}
		s.serverError(w, r, err)
		return
	}
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionLdapCreate, src.Name, "", s.clientIP(r))
	s.log.Info("ldap source created", "source", src.Name, "by", currentUser(r).Username)
	if r.PostFormValue("sync") == "1" {
		result := s.syncSource(r, src)
		s.renderLdapForm(w, r, adminLdapFormData{ID: src.ID, Form: formFromSource(src), Saved: true, SyncResult: result})
		return
	}
	http.Redirect(w, r, "/admin/ldap/"+src.ID+"?saved=1", http.StatusSeeOther)
}

func (s *Server) loadLdapSource(w http.ResponseWriter, r *http.Request) (sqlcgen.LdapSource, bool) {
	src, err := s.store.GetLdapSource(r.Context(), r.PathValue("id"))
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return src, false
	}
	if err != nil {
		s.serverError(w, r, err)
		return src, false
	}
	return src, true
}

func (s *Server) handleAdminLdapEdit(w http.ResponseWriter, r *http.Request) {
	src, ok := s.loadLdapSource(w, r)
	if !ok {
		return
	}
	s.renderLdapForm(w, r, adminLdapFormData{
		ID: src.ID, Form: formFromSource(src), Saved: r.URL.Query().Get("saved") == "1",
	})
}

func (s *Server) handleAdminLdapUpdate(w http.ResponseWriter, r *http.Request) {
	src, ok := s.loadLdapSource(w, r)
	if !ok {
		return
	}
	form := parseLdapForm(r)
	fail := func(msg string) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.renderLdapForm(w, r, adminLdapFormData{ID: src.ID, Form: form, Error: msg})
	}
	if err := form.validate(); err != nil {
		fail(err.Error())
		return
	}
	now := time.Now().UTC()
	if err := s.store.UpdateLdapSource(r.Context(), sqlcgen.UpdateLdapSourceParams{
		Name: form.Name, Url: form.URL, StartTls: form.StartTLS, SkipTlsVerify: form.SkipTLSVerify,
		BindDn: form.BindDN, BaseDn: form.BaseDN, UserFilter: form.UserFilter,
		UsernameAttr: form.UsernameAttr, EmailAttr: form.EmailAttr, NameAttr: form.NameAttr,
		PhotoAttr:   form.PhotoAttr,
		GroupFilter: form.GroupFilter, GroupNameAttr: form.GroupNameAttr,
		PasswordWriteback: form.Writeback, PasswordReset: form.Reset,
		Enabled: form.Enabled, UpdatedAt: now, ID: src.ID,
	}); err != nil {
		if isUniqueViolation(err) {
			fail("A directory with this name already exists.")
			return
		}
		s.serverError(w, r, err)
		return
	}
	if form.BindPassword != "" {
		sealed, err := secrets.Seal(s.ldap.SealKey(), []byte(form.BindPassword))
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		if err := s.store.UpdateLdapSourceBindPassword(r.Context(), sqlcgen.UpdateLdapSourceBindPasswordParams{
			BindPasswordEnc: sealed, UpdatedAt: now, ID: src.ID,
		}); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionLdapUpdate, src.Name, "", s.clientIP(r))
	if r.PostFormValue("sync") == "1" {
		// Re-load so the sync runs against exactly what was persisted
		// (including any just-changed bind password).
		updated, ok := s.loadLdapSource(w, r)
		if !ok {
			return
		}
		result := s.syncSource(r, updated)
		s.renderLdapForm(w, r, adminLdapFormData{ID: updated.ID, Form: formFromSource(updated), Saved: true, SyncResult: result})
		return
	}
	http.Redirect(w, r, "/admin/ldap/"+src.ID+"?saved=1", http.StatusSeeOther)
}

func (s *Server) handleAdminLdapDelete(w http.ResponseWriter, r *http.Request) {
	src, ok := s.loadLdapSource(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteLdapSource(r.Context(), src.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionLdapDelete, src.Name, "", s.clientIP(r))
	s.log.Info("ldap source deleted", "source", src.Name, "by", currentUser(r).Username)
	http.Redirect(w, r, "/admin/ldap?deleted=1", http.StatusSeeOther)
}

// draftSource builds an unsaved LdapSource from the submitted form so a
// configuration can be tested before it exists in the database.
// storedPassword carries the persisted encrypted bind password to fall
// back on when the (write-only) password field is left empty on edit.
func (s *Server) draftSource(form ldapForm, storedPassword []byte) (sqlcgen.LdapSource, error) {
	enc := storedPassword
	if form.BindPassword != "" || storedPassword == nil {
		sealed, err := secrets.Seal(s.ldap.SealKey(), []byte(form.BindPassword))
		if err != nil {
			return sqlcgen.LdapSource{}, err
		}
		enc = sealed
	}
	return sqlcgen.LdapSource{
		Name: form.Name, Url: form.URL,
		StartTls: form.StartTLS, SkipTlsVerify: form.SkipTLSVerify,
		BindDn: form.BindDN, BindPasswordEnc: enc, BaseDn: form.BaseDN,
		UserFilter: form.UserFilter, UsernameAttr: form.UsernameAttr,
		EmailAttr: form.EmailAttr, NameAttr: form.NameAttr, PhotoAttr: form.PhotoAttr,
		GroupFilter: form.GroupFilter, GroupNameAttr: form.GroupNameAttr,
	}, nil
}

// runLdapTest verifies connectivity and the service bind, and optionally
// resolves a test username through the configured filters.
func (s *Server) runLdapTest(src sqlcgen.LdapSource, testUser string) *ldapTestResult {
	result := &ldapTestResult{}
	if u, err := url.Parse(src.Url); err != nil || (u.Scheme != "ldap" && u.Scheme != "ldaps") || u.Host == "" {
		result.Message = "Fill in a valid LDAP URL first (ldap://host:389 or ldaps://host:636)."
		return result
	}
	if testUser == "" {
		conn, err := s.ldap.Connect(src)
		if err != nil {
			result.Message = err.Error()
			return result
		}
		conn.Close()
		result.OK = true
		if src.BindDn == "" {
			result.Message = "Connection succeeded (anonymous bind)."
		} else {
			result.Message = "Connection and service bind succeeded."
		}
		return result
	}
	if src.BaseDn == "" || !strings.Contains(src.UserFilter, "{username}") {
		result.Message = "Fill in the base DN and a user filter containing {username} to test a user lookup."
		return result
	}
	entry, err := s.ldap.FindUser(src, testUser)
	if err != nil {
		result.Message = err.Error()
		return result
	}
	result.OK = true
	result.Message = "User found."
	result.DN = entry.DN
	result.Email = entry.Email
	result.Groups = entry.Groups
	return result
}

// handleAdminLdapTest tests the configuration as currently filled in on
// the edit form, without saving it.
func (s *Server) handleAdminLdapTest(w http.ResponseWriter, r *http.Request) {
	src, ok := s.loadLdapSource(w, r)
	if !ok {
		return
	}
	form := parseLdapForm(r)
	draft, err := s.draftSource(form, src.BindPasswordEnc)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	result := s.runLdapTest(draft, strings.TrimSpace(r.PostFormValue("test_username")))
	s.renderLdapForm(w, r, adminLdapFormData{ID: src.ID, Form: form, TestResult: result})
}

// syncSource runs a full synchronization of a directory and returns the
// outcome as a result banner, recording an audit entry on success.
func (s *Server) syncSource(r *http.Request, src sqlcgen.LdapSource) *ldapTestResult {
	result := &ldapTestResult{}
	sync, err := s.ldap.SyncAll(r.Context(), src)
	if err != nil {
		result.Message = err.Error()
		return result
	}
	result.OK = true
	result.Message = fmt.Sprintf("Synchronized: %d user(s) created, %d updated, %d skipped.",
		sync.Created, sync.Updated, sync.Skipped)
	if sync.Missing > 0 {
		result.Message += fmt.Sprintf(" %d shadow user(s) no longer match the directory — review them under Admin → Users.", sync.Missing)
	}
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionLdapSync, src.Name, result.Message, s.clientIP(r))
	return result
}

// handleAdminLdapSync imports or refreshes every directory user and their
// groups without waiting for individual sign-ins.
func (s *Server) handleAdminLdapSync(w http.ResponseWriter, r *http.Request) {
	src, ok := s.loadLdapSource(w, r)
	if !ok {
		return
	}
	result := s.syncSource(r, src)
	s.renderLdapForm(w, r, adminLdapFormData{ID: src.ID, Form: formFromSource(src), SyncResult: result})
}

// handleAdminLdapTestDraft is the same for the creation form: the source
// does not exist yet.
func (s *Server) handleAdminLdapTestDraft(w http.ResponseWriter, r *http.Request) {
	form := parseLdapForm(r)
	draft, err := s.draftSource(form, nil)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	result := s.runLdapTest(draft, strings.TrimSpace(r.PostFormValue("test_username")))
	s.renderLdapForm(w, r, adminLdapFormData{IsNew: true, Form: form, TestResult: result})
}
