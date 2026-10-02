package web

import (
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kivraid/kivraid/internal/audit"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
)

type providerForm struct {
	Name         string
	Issuer       string
	ClientID     string
	ClientSecret string // write-only; empty on edit keeps the stored value
	Scopes       string
	ClaimEmail   string
	ClaimName    string
	ClaimGroups  string
	AllowSignup  bool
	Enabled      bool
}

type providerTestResult struct {
	OK       bool
	Message  string
	Issuer   string
	Auth     string
	Token    string
	Userinfo string
}

type adminProvidersListData struct {
	Providers []sqlcgen.UpstreamProvider
	Deleted   bool
}

type adminProviderFormData struct {
	IsNew         bool
	ID            string
	Form          providerForm
	RedirectURI   string
	PostLogoutURI string
	HasSecret     bool
	Error         string
	Saved         bool
	TestResult    *providerTestResult
}

func formFromProvider(p sqlcgen.UpstreamProvider) providerForm {
	return providerForm{
		Name: p.Name, Issuer: p.Issuer, ClientID: p.ClientID, Scopes: p.Scopes,
		ClaimEmail: p.ClaimEmail, ClaimName: p.ClaimName, ClaimGroups: p.ClaimGroups,
		AllowSignup: p.AllowSignup, Enabled: p.Enabled,
	}
}

func parseProviderForm(r *http.Request) providerForm {
	str := func(n string) string { return strings.TrimSpace(r.PostFormValue(n)) }
	f := providerForm{
		Name: str("name"), Issuer: str("issuer"), ClientID: str("client_id"),
		ClientSecret: r.PostFormValue("client_secret"),
		Scopes:       str("scopes"),
		ClaimEmail:   str("claim_email"), ClaimName: str("claim_name"), ClaimGroups: str("claim_groups"),
		AllowSignup: r.PostFormValue("allow_signup") == "on",
		Enabled:     r.PostFormValue("enabled") == "on",
	}
	if f.Scopes == "" {
		f.Scopes = "openid profile email"
	}
	if f.ClaimEmail == "" {
		f.ClaimEmail = "email"
	}
	if f.ClaimName == "" {
		f.ClaimName = "name"
	}
	if f.ClaimGroups == "" {
		f.ClaimGroups = "groups"
	}
	return f
}

func (f *providerForm) validate() error {
	if f.Name == "" {
		return errorf("Name is required.")
	}
	u, err := url.Parse(f.Issuer)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errorf("Issuer must be an absolute URL, e.g. https://idp.example.com.")
	}
	if f.ClientID == "" {
		return errorf("Client ID is required.")
	}
	if !strings.Contains(f.Scopes, "openid") {
		return errorf(`Scopes must include "openid".`)
	}
	return nil
}

func (s *Server) handleAdminProviders(w http.ResponseWriter, r *http.Request) {
	providers, err := s.store.ListUpstreamProviders(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, "admin_providers.html", pageData{
		Title: "Providers", Active: "providers", CSRF: s.csrfToken(r.Context()),
		User: currentUser(r),
		Data: adminProvidersListData{Providers: providers, Deleted: r.URL.Query().Get("deleted") == "1"},
	})
}

func (s *Server) renderProviderForm(w http.ResponseWriter, r *http.Request, data adminProviderFormData) {
	title := msgid("Edit provider")
	if data.IsNew {
		title = msgid("New provider")
	}
	// A freshly-typed client secret can round-trip through a test; keep it
	// out of the browser cache.
	w.Header().Set("Cache-Control", "no-store")
	s.render(w, r, "admin_providers_form.html", pageData{
		Title: title, Active: "providers", CSRF: s.csrfToken(r.Context()),
		User: currentUser(r), Data: data,
	})
}

func (s *Server) handleAdminProviderNew(w http.ResponseWriter, r *http.Request) {
	s.renderProviderForm(w, r, adminProviderFormData{IsNew: true, Form: providerForm{
		Scopes: "openid profile email", ClaimEmail: "email", ClaimName: "name", ClaimGroups: "groups",
		AllowSignup: true, Enabled: true,
	}})
}

func (s *Server) handleAdminProviderCreate(w http.ResponseWriter, r *http.Request) {
	form := parseProviderForm(r)
	fail := func(msg string) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.renderProviderForm(w, r, adminProviderFormData{IsNew: true, Form: form, Error: msg})
	}
	if err := form.validate(); err != nil {
		fail(s.tErr(r, err))
		return
	}
	var enc []byte
	if form.ClientSecret != "" {
		sealed, err := s.broker.SealSecret(form.ClientSecret)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		enc = sealed
	}
	now := time.Now().UTC()
	p, err := s.store.CreateUpstreamProvider(r.Context(), sqlcgen.CreateUpstreamProviderParams{
		ID: uuid.NewString(), Name: form.Name, Issuer: strings.TrimSuffix(form.Issuer, "/"),
		ClientID: form.ClientID, ClientSecretEnc: enc, Scopes: form.Scopes,
		ClaimEmail: form.ClaimEmail, ClaimName: form.ClaimName, ClaimGroups: form.ClaimGroups,
		AllowSignup: form.AllowSignup, Enabled: form.Enabled, Position: 0,
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		if isUniqueViolation(err) {
			fail(s.t(r, "A provider with this name already exists."))
			return
		}
		s.serverError(w, r, err)
		return
	}
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionProviderCreate, p.Name, "", s.clientIP(r))
	s.log.Info("upstream provider created", "provider", p.Name, "by", currentUser(r).Username)
	http.Redirect(w, r, "/admin/providers/"+p.ID+"?saved=1", http.StatusSeeOther)
}

func (s *Server) loadProvider(w http.ResponseWriter, r *http.Request) (sqlcgen.UpstreamProvider, bool) {
	p, err := s.store.GetUpstreamProvider(r.Context(), r.PathValue("id"))
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return p, false
	}
	if err != nil {
		s.serverError(w, r, err)
		return p, false
	}
	return p, true
}

func (s *Server) handleAdminProviderEdit(w http.ResponseWriter, r *http.Request) {
	p, ok := s.loadProvider(w, r)
	if !ok {
		return
	}
	s.renderProviderForm(w, r, adminProviderFormData{
		ID: p.ID, Form: formFromProvider(p), RedirectURI: s.broker.RedirectURI(p.ID), PostLogoutURI: s.issuer() + "/login",
		HasSecret: len(p.ClientSecretEnc) > 0, Saved: r.URL.Query().Get("saved") == "1",
	})
}

func (s *Server) handleAdminProviderUpdate(w http.ResponseWriter, r *http.Request) {
	p, ok := s.loadProvider(w, r)
	if !ok {
		return
	}
	form := parseProviderForm(r)
	fail := func(msg string) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.renderProviderForm(w, r, adminProviderFormData{
			ID: p.ID, Form: form, RedirectURI: s.broker.RedirectURI(p.ID), PostLogoutURI: s.issuer() + "/login",
			HasSecret: len(p.ClientSecretEnc) > 0, Error: msg,
		})
	}
	if err := form.validate(); err != nil {
		fail(s.tErr(r, err))
		return
	}
	now := time.Now().UTC()
	if err := s.store.UpdateUpstreamProvider(r.Context(), sqlcgen.UpdateUpstreamProviderParams{
		Name: form.Name, Issuer: strings.TrimSuffix(form.Issuer, "/"), ClientID: form.ClientID,
		Scopes: form.Scopes, ClaimEmail: form.ClaimEmail, ClaimName: form.ClaimName,
		ClaimGroups: form.ClaimGroups, AllowSignup: form.AllowSignup, Enabled: form.Enabled,
		UpdatedAt: now, ID: p.ID,
	}); err != nil {
		if isUniqueViolation(err) {
			fail(s.t(r, "A provider with this name already exists."))
			return
		}
		s.serverError(w, r, err)
		return
	}
	if form.ClientSecret != "" {
		sealed, err := s.broker.SealSecret(form.ClientSecret)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		if err := s.store.UpdateUpstreamProviderSecret(r.Context(), sqlcgen.UpdateUpstreamProviderSecretParams{
			ClientSecretEnc: sealed, UpdatedAt: now, ID: p.ID,
		}); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionProviderUpdate, form.Name, "", s.clientIP(r))
	http.Redirect(w, r, "/admin/providers/"+p.ID+"?saved=1", http.StatusSeeOther)
}

func (s *Server) handleAdminProviderDelete(w http.ResponseWriter, r *http.Request) {
	p, ok := s.loadProvider(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteUpstreamProvider(r.Context(), p.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionProviderDelete, p.Name, "", s.clientIP(r))
	s.log.Info("upstream provider deleted", "provider", p.Name, "by", currentUser(r).Username)
	http.Redirect(w, r, "/admin/providers?deleted=1", http.StatusSeeOther)
}

// runProviderTest fetches the issuer's discovery document to confirm the URL
// is reachable and valid. It needs no client credentials.
func (s *Server) runProviderTest(r *http.Request, issuer string) *providerTestResult {
	res := &providerTestResult{}
	if strings.TrimSpace(issuer) == "" {
		res.Message = s.t(r, "Enter an issuer URL first.")
		return res
	}
	d, err := s.broker.Discover(r.Context(), issuer)
	if err != nil {
		res.Message = s.t(r, "Discovery failed: %s", err.Error())
		return res
	}
	res.OK = true
	res.Message = s.t(r, "Discovery succeeded.")
	res.Issuer, res.Auth, res.Token, res.Userinfo = d.Issuer, d.AuthorizationEndpoint, d.TokenEndpoint, d.UserinfoEndpoint
	return res
}

func (s *Server) handleAdminProviderTestDraft(w http.ResponseWriter, r *http.Request) {
	form := parseProviderForm(r)
	s.renderProviderForm(w, r, adminProviderFormData{
		IsNew: true, Form: form, TestResult: s.runProviderTest(r, form.Issuer),
	})
}

func (s *Server) handleAdminProviderTest(w http.ResponseWriter, r *http.Request) {
	p, ok := s.loadProvider(w, r)
	if !ok {
		return
	}
	form := parseProviderForm(r)
	s.renderProviderForm(w, r, adminProviderFormData{
		ID: p.ID, Form: form, RedirectURI: s.broker.RedirectURI(p.ID), PostLogoutURI: s.issuer() + "/login",
		HasSecret: len(p.ClientSecretEnc) > 0, TestResult: s.runProviderTest(r, form.Issuer),
	})
}
