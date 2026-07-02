package web

import (
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/lporcheron/kivraid/internal/secrets"
	"github.com/lporcheron/kivraid/internal/store/sqlcgen"
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
	GroupFilter   string
	GroupNameAttr string
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
}

type adminLdapFormData struct {
	IsNew      bool
	ID         string
	Form       ldapForm
	Error      string
	Saved      bool
	TestResult *ldapTestResult
}

func formFromSource(src sqlcgen.LdapSource) ldapForm {
	return ldapForm{
		Name: src.Name, URL: src.Url, StartTLS: src.StartTls, SkipTLSVerify: src.SkipTlsVerify,
		BindDN: src.BindDn, BaseDN: src.BaseDn, UserFilter: src.UserFilter,
		UsernameAttr: src.UsernameAttr, EmailAttr: src.EmailAttr, NameAttr: src.NameAttr,
		GroupFilter: src.GroupFilter, GroupNameAttr: src.GroupNameAttr, Enabled: src.Enabled,
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
		GroupFilter:   str("group_filter"),
		GroupNameAttr: str("group_name_attr"),
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
	if f.BindDN == "" {
		return errors.New("Bind DN is required (a read-only service account).")
	}
	if f.BaseDN == "" {
		return errors.New("Base DN is required.")
	}
	if !strings.Contains(f.UserFilter, "{username}") {
		return errors.New("User filter must contain the {username} placeholder.")
	}
	if f.GroupFilter != "" && !strings.Contains(f.GroupFilter, "{dn}") {
		return errors.New("Group filter must contain the {dn} placeholder (or be empty to disable group sync).")
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
		User: currentUser(r), Data: adminLdapListData{Sources: sources},
	})
}

func (s *Server) renderLdapForm(w http.ResponseWriter, r *http.Request, data adminLdapFormData) {
	title := "Edit directory"
	if data.IsNew {
		title = "New directory"
	}
	s.render(w, r, "admin_ldap_form.html", pageData{
		Title: title, Active: "ldap", CSRF: s.csrfToken(r.Context()),
		User: currentUser(r), Data: data,
	})
}

func (s *Server) handleAdminLdapNew(w http.ResponseWriter, r *http.Request) {
	s.renderLdapForm(w, r, adminLdapFormData{IsNew: true, Form: ldapForm{
		UsernameAttr: "uid", EmailAttr: "mail", NameAttr: "cn", GroupNameAttr: "cn", Enabled: true,
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
	if form.BindPassword == "" {
		fail("Bind password is required.")
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
		EmailAttr: form.EmailAttr, NameAttr: form.NameAttr,
		GroupFilter: form.GroupFilter, GroupNameAttr: form.GroupNameAttr,
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
	s.log.Info("ldap source created", "source", src.Name, "by", currentUser(r).Username)
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
		GroupFilter: form.GroupFilter, GroupNameAttr: form.GroupNameAttr,
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
	s.log.Info("ldap source deleted", "source", src.Name, "by", currentUser(r).Username)
	http.Redirect(w, r, "/admin/ldap", http.StatusSeeOther)
}

// handleAdminLdapTest verifies connectivity and the service bind, and
// optionally resolves a test username through the configured filters.
func (s *Server) handleAdminLdapTest(w http.ResponseWriter, r *http.Request) {
	src, ok := s.loadLdapSource(w, r)
	if !ok {
		return
	}
	result := &ldapTestResult{}
	testUser := strings.TrimSpace(r.PostFormValue("test_username"))

	if testUser == "" {
		conn, err := s.ldap.Connect(src)
		if err != nil {
			result.Message = err.Error()
		} else {
			conn.Close()
			result.OK = true
			result.Message = "Connection and service bind succeeded."
		}
	} else {
		entry, err := s.ldap.FindUser(src, testUser)
		if err != nil {
			result.Message = err.Error()
		} else {
			result.OK = true
			result.Message = "User found."
			result.DN = entry.DN
			result.Email = entry.Email
			result.Groups = entry.Groups
		}
	}
	s.renderLdapForm(w, r, adminLdapFormData{ID: src.ID, Form: formFromSource(src), TestResult: result})
}
