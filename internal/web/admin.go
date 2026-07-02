package web

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/lporcheron/kivraid/internal/audit"
	"github.com/lporcheron/kivraid/internal/oidcserver"

	"github.com/lporcheron/kivraid/internal/store/sqlcgen"
)

func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !currentUser(r).IsAdmin {
			s.renderError(w, r, http.StatusForbidden, "Administrator access required",
				"This page is reserved for administrators of this Kivraid instance.")
			return
		}
		next.ServeHTTP(w, r)
	}))
}

// appForm carries the create/edit form state, including re-display of the
// user's input after a validation error.
type appForm struct {
	Name           string
	Slug           string
	LaunchURL      string
	RedirectURIs   string
	PostLogoutURIs string
	Public         bool
}

type adminAppsData struct {
	Apps []sqlcgen.ListApplicationsWithProvidersRow
}

type adminAppFormData struct {
	Form  appForm
	Error string
}

type adminAppSecretData struct {
	App          sqlcgen.Application
	ClientID     string
	ClientSecret string
	Issuer       string
	Rotated      bool
}

type adminAppDetailData struct {
	App      sqlcgen.Application
	Provider sqlcgen.Provider
	Form     appForm
	Issuer   string
	Error    string
	Saved    bool
	Groups   []sqlcgen.Group
	Bound    map[string]bool
}

func (s *Server) handleAdminApps(w http.ResponseWriter, r *http.Request) {
	apps, err := s.store.ListApplicationsWithProviders(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, "admin_apps.html", pageData{
		Title: "Applications", Active: "apps", CSRF: s.csrfToken(r.Context()),
		User: currentUser(r), Data: adminAppsData{Apps: apps},
	})
}

func (s *Server) handleAdminAppNew(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "admin_app_new.html", pageData{
		Title: "New application", Active: "apps", CSRF: s.csrfToken(r.Context()),
		User: currentUser(r), Data: adminAppFormData{},
	})
}

func parseAppForm(r *http.Request) appForm {
	return appForm{
		Name:           strings.TrimSpace(r.PostFormValue("name")),
		Slug:           strings.TrimSpace(r.PostFormValue("slug")),
		LaunchURL:      strings.TrimSpace(r.PostFormValue("launch_url")),
		RedirectURIs:   r.PostFormValue("redirect_uris"),
		PostLogoutURIs: r.PostFormValue("post_logout_uris"),
		Public:         r.PostFormValue("client_type") == "public",
	}
}

func (f *appForm) validate() (redirects, postLogout []string, err error) {
	if f.Name == "" {
		return nil, nil, errors.New("Name is required.")
	}
	if f.Slug == "" {
		f.Slug = slugify(f.Name)
	} else {
		f.Slug = slugify(f.Slug)
	}
	if f.Slug == "" {
		return nil, nil, errors.New("Slug must contain at least one letter or digit.")
	}
	if f.LaunchURL != "" {
		if _, perr := url.ParseRequestURI(f.LaunchURL); perr != nil {
			return nil, nil, errors.New("Launch URL must be a valid absolute URL.")
		}
	}
	redirects, err = parseURIList(f.RedirectURIs)
	if err != nil {
		return nil, nil, fmt.Errorf("Redirect URIs: %s", err)
	}
	if len(redirects) == 0 {
		return nil, nil, errors.New("At least one redirect URI is required.")
	}
	postLogout, err = parseURIList(f.PostLogoutURIs)
	if err != nil {
		return nil, nil, fmt.Errorf("Post-logout redirect URIs: %s", err)
	}
	return redirects, postLogout, nil
}

func parseURIList(raw string) ([]string, error) {
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		u, err := url.Parse(line)
		if err != nil || u.Scheme == "" {
			return nil, fmt.Errorf("%q is not an absolute URI", line)
		}
		out = append(out, line)
	}
	return out, nil
}

func slugify(s string) string {
	var b strings.Builder
	prevDash := true // avoid a leading dash
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
			b.WriteRune(r)
			prevDash = false
		case !prevDash:
			b.WriteByte('-')
			prevDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

func randomHex(bytes int) string {
	raw := make([]byte, bytes)
	rand.Read(raw)
	return hex.EncodeToString(raw)
}

func jsonList(items []string) string {
	if items == nil {
		items = []string{}
	}
	raw, _ := json.Marshal(items)
	return string(raw)
}

func (s *Server) handleAdminAppCreate(w http.ResponseWriter, r *http.Request) {
	form := parseAppForm(r)
	renderErr := func(msg string) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.render(w, r, "admin_app_new.html", pageData{
			Title: "New application", Active: "apps", CSRF: s.csrfToken(r.Context()),
			User: currentUser(r), Data: adminAppFormData{Form: form, Error: msg},
		})
	}

	redirects, postLogout, err := form.validate()
	if err != nil {
		renderErr(err.Error())
		return
	}

	clientID := randomHex(20)
	var secret string
	var secretHash *string
	if !form.Public {
		secret = randomHex(32)
		h := oidcserver.HashToken(secret)
		secretHash = &h
	}

	now := time.Now().UTC()
	tx, err := s.store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	defer tx.Rollback()
	q := s.store.Queries.WithTx(tx)

	app, err := q.CreateApplication(r.Context(), sqlcgen.CreateApplicationParams{
		ID: uuid.NewString(), Name: form.Name, Slug: form.Slug,
		LaunchUrl: form.LaunchURL, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		if isUniqueViolation(err) {
			renderErr("An application with this slug already exists.")
			return
		}
		s.serverError(w, r, err)
		return
	}
	_, err = q.CreateProvider(r.Context(), sqlcgen.CreateProviderParams{
		ID: uuid.NewString(), ApplicationID: app.ID, ClientID: clientID,
		ClientSecretHash: secretHash,
		RedirectUris:     jsonList(redirects), PostLogoutRedirectUris: jsonList(postLogout),
		Public:                form.Public,
		AccessTokenTtlSeconds: 300, RefreshTokenTtlSeconds: 30 * 24 * 3600, IDTokenTtlSeconds: 3600,
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if err := tx.Commit(); err != nil {
		s.serverError(w, r, err)
		return
	}

	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionAppCreate, app.Slug, "", clientIP(r))
	s.log.Info("application created", "app", app.Slug, "by", currentUser(r).Username)
	s.render(w, r, "admin_app_secret.html", pageData{
		Title: "Application created", Active: "apps", CSRF: s.csrfToken(r.Context()),
		User: currentUser(r),
		Data: adminAppSecretData{App: app, ClientID: clientID, ClientSecret: secret, Issuer: s.issuer()},
	})
}

func (s *Server) loadAppAndProvider(w http.ResponseWriter, r *http.Request) (sqlcgen.Application, sqlcgen.Provider, bool) {
	app, err := s.store.GetApplication(r.Context(), r.PathValue("id"))
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return app, sqlcgen.Provider{}, false
	}
	if err != nil {
		s.serverError(w, r, err)
		return app, sqlcgen.Provider{}, false
	}
	provider, err := s.store.GetProviderByApplication(r.Context(), app.ID)
	if err != nil {
		s.serverError(w, r, err)
		return app, provider, false
	}
	return app, provider, true
}

func (s *Server) renderAppDetail(w http.ResponseWriter, r *http.Request, app sqlcgen.Application, provider sqlcgen.Provider, errMsg string, saved bool) {
	form := appForm{
		Name: app.Name, Slug: app.Slug, LaunchURL: app.LaunchUrl,
		RedirectURIs:   strings.Join(decodeList(provider.RedirectUris), "\n"),
		PostLogoutURIs: strings.Join(decodeList(provider.PostLogoutRedirectUris), "\n"),
		Public:         provider.Public,
	}
	groups, err := s.store.ListGroups(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	boundIDs, err := s.store.ListAppPolicyGroupIDs(r.Context(), app.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	bound := make(map[string]bool, len(boundIDs))
	for _, id := range boundIDs {
		bound[id] = true
	}
	s.render(w, r, "admin_app_detail.html", pageData{
		Title: app.Name, Active: "apps", CSRF: s.csrfToken(r.Context()),
		User: currentUser(r),
		Data: adminAppDetailData{
			App: app, Provider: provider, Form: form, Issuer: s.issuer(),
			Error: errMsg, Saved: saved, Groups: groups, Bound: bound,
		},
	})
}

func (s *Server) handleAdminAppDetail(w http.ResponseWriter, r *http.Request) {
	app, provider, ok := s.loadAppAndProvider(w, r)
	if !ok {
		return
	}
	s.renderAppDetail(w, r, app, provider, "", r.URL.Query().Get("saved") == "1")
}

func (s *Server) handleAdminAppUpdate(w http.ResponseWriter, r *http.Request) {
	app, provider, ok := s.loadAppAndProvider(w, r)
	if !ok {
		return
	}
	form := parseAppForm(r)
	form.Public = provider.Public // client type is immutable after creation

	redirects, postLogout, err := form.validate()
	if err != nil {
		app.Name, app.Slug, app.LaunchUrl = form.Name, form.Slug, form.LaunchURL
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.renderAppDetail(w, r, app, provider, err.Error(), false)
		return
	}

	now := time.Now().UTC()
	if err := s.store.UpdateApplication(r.Context(), sqlcgen.UpdateApplicationParams{
		Name: form.Name, Slug: form.Slug, LaunchUrl: form.LaunchURL, UpdatedAt: now, ID: app.ID,
	}); err != nil {
		if isUniqueViolation(err) {
			s.renderAppDetail(w, r, app, provider, "An application with this slug already exists.", false)
			return
		}
		s.serverError(w, r, err)
		return
	}
	if err := s.store.UpdateProviderRedirects(r.Context(), sqlcgen.UpdateProviderRedirectsParams{
		RedirectUris: jsonList(redirects), PostLogoutRedirectUris: jsonList(postLogout),
		UpdatedAt: now, ID: provider.ID,
	}); err != nil {
		s.serverError(w, r, err)
		return
	}

	// Replace the group access policy (no boxes checked = everyone).
	tx, err := s.store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	defer tx.Rollback()
	q := s.store.Queries.WithTx(tx)
	if err := q.DeleteAppPolicies(r.Context(), app.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	for _, groupID := range r.PostForm["policy_groups"] {
		if err := q.AddAppPolicy(r.Context(), sqlcgen.AddAppPolicyParams{
			ApplicationID: app.ID, GroupID: groupID,
		}); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	if err := tx.Commit(); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionAppUpdate, app.Slug, "", clientIP(r))
	http.Redirect(w, r, "/admin/applications/"+app.ID+"?saved=1", http.StatusSeeOther)
}

func (s *Server) handleAdminAppRotateSecret(w http.ResponseWriter, r *http.Request) {
	app, provider, ok := s.loadAppAndProvider(w, r)
	if !ok {
		return
	}
	if provider.Public {
		http.Error(w, "public clients have no secret", http.StatusBadRequest)
		return
	}
	secret := randomHex(32)
	h := oidcserver.HashToken(secret)
	if err := s.store.UpdateProviderSecret(r.Context(), sqlcgen.UpdateProviderSecretParams{
		ClientSecretHash: &h, UpdatedAt: time.Now().UTC(), ID: provider.ID,
	}); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionSecretRotate, app.Slug, "", clientIP(r))
	s.log.Info("client secret rotated", "app", app.Slug, "by", currentUser(r).Username)
	s.render(w, r, "admin_app_secret.html", pageData{
		Title: "Secret rotated", Active: "apps", CSRF: s.csrfToken(r.Context()),
		User: currentUser(r),
		Data: adminAppSecretData{App: app, ClientID: provider.ClientID, ClientSecret: secret, Issuer: s.issuer(), Rotated: true},
	})
}

func (s *Server) handleAdminAppDelete(w http.ResponseWriter, r *http.Request) {
	app, _, ok := s.loadAppAndProvider(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteApplication(r.Context(), app.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionAppDelete, app.Slug, "", clientIP(r))
	s.log.Info("application deleted", "app", app.Slug, "by", currentUser(r).Username)
	http.Redirect(w, r, "/admin/applications", http.StatusSeeOther)
}

func (s *Server) issuer() string {
	return strings.TrimSuffix(s.cfg.BaseURL, "/")
}

func decodeList(raw string) []string {
	var out []string
	json.Unmarshal([]byte(raw), &out)
	return out
}

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}
