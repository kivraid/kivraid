package web

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
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
	Kind           string // "oidc" or "proxy"
	Description    string
	LaunchURL      string
	RedirectURIs   string
	PostLogoutURIs string
	ProxyHosts     string
	Public         bool
	AccessTTL      int64
	RefreshTTL     int64
	IDTTL          int64
}

type adminAppsData struct {
	Apps []sqlcgen.ListApplicationsAdminRow
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
	App          sqlcgen.Application
	Provider     sqlcgen.Provider
	Form         appForm
	Issuer       string
	Error        string
	Saved        bool
	Groups       []sqlcgen.Group
	Bound        map[string]bool
	ClientSecret string // decrypted; empty for legacy hashed-only rows
}

func (s *Server) handleAdminApps(w http.ResponseWriter, r *http.Request) {
	apps, err := s.store.ListApplicationsAdmin(r.Context())
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
	f := appForm{
		Name:           strings.TrimSpace(r.PostFormValue("name")),
		Slug:           strings.TrimSpace(r.PostFormValue("slug")),
		Kind:           r.PostFormValue("kind"),
		Description:    strings.TrimSpace(r.PostFormValue("description")),
		LaunchURL:      strings.TrimSpace(r.PostFormValue("launch_url")),
		RedirectURIs:   r.PostFormValue("redirect_uris"),
		PostLogoutURIs: r.PostFormValue("post_logout_uris"),
		ProxyHosts:     r.PostFormValue("proxy_hosts"),
		Public:         r.PostFormValue("client_type") == "public",
		AccessTTL:      parseTTL(r.PostFormValue("access_ttl"), 300),
		RefreshTTL:     parseTTL(r.PostFormValue("refresh_ttl"), 30*24*3600),
		IDTTL:          parseTTL(r.PostFormValue("id_ttl"), 3600),
	}
	if f.Kind != "proxy" {
		f.Kind = "oidc"
	}
	return f
}

// parseTTL reads a positive seconds value, falling back to def.
func parseTTL(raw string, def int64) int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

// parseHostList reads one host[:port] per line.
func parseHostList(raw string) []string {
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, strings.ToLower(line))
		}
	}
	return out
}

// validate checks common fields and, for OIDC apps, the redirect URIs.
// Proxy apps validate their hosts via validateProxy.
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
	if f.Kind == "proxy" {
		if len(parseHostList(f.ProxyHosts)) == 0 {
			return nil, nil, errors.New("At least one protected host is required.")
		}
		return nil, nil, nil
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

	now := time.Now().UTC()
	tx, err := s.store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	defer tx.Rollback()
	q := s.store.Queries.WithTx(tx)

	hosts := ""
	if form.Kind == "proxy" {
		hosts = jsonList(parseHostList(form.ProxyHosts))
	}
	app, err := q.CreateApplication(r.Context(), sqlcgen.CreateApplicationParams{
		ID: uuid.NewString(), Name: form.Name, Slug: form.Slug, Kind: form.Kind,
		Description: form.Description, LaunchUrl: form.LaunchURL, ProxyHosts: hosts,
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		if isUniqueViolation(err) {
			renderErr("An application with this slug already exists.")
			return
		}
		s.serverError(w, r, err)
		return
	}

	// Proxy apps have no OIDC provider; nothing more to create.
	if form.Kind == "proxy" {
		if err := tx.Commit(); err != nil {
			s.serverError(w, r, err)
			return
		}
		s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionAppCreate, app.Slug, "proxy", clientIP(r))
		http.Redirect(w, r, "/admin/applications/"+app.ID, http.StatusSeeOther)
		return
	}

	clientID := randomHex(20)
	var secret string
	var secretHash *string
	var secretEnc []byte
	if !form.Public {
		secret = randomHex(32)
		h := oidcserver.HashToken(secret)
		secretHash = &h
		if secretEnc, err = s.oidcStore.SealClientSecret(secret); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	_, err = q.CreateProvider(r.Context(), sqlcgen.CreateProviderParams{
		ID: uuid.NewString(), ApplicationID: app.ID, ClientID: clientID,
		ClientSecretHash: secretHash, ClientSecretEnc: secretEnc,
		RedirectUris: jsonList(redirects), PostLogoutRedirectUris: jsonList(postLogout),
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

func (s *Server) loadApp(w http.ResponseWriter, r *http.Request) (sqlcgen.Application, bool) {
	app, err := s.store.GetApplication(r.Context(), r.PathValue("id"))
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return app, false
	}
	if err != nil {
		s.serverError(w, r, err)
		return app, false
	}
	return app, true
}

func (s *Server) renderAppDetail(w http.ResponseWriter, r *http.Request, app sqlcgen.Application, provider sqlcgen.Provider, errMsg string, saved bool) {
	form := appForm{
		Name: app.Name, Slug: app.Slug, Kind: app.Kind, Description: app.Description, LaunchURL: app.LaunchUrl,
		RedirectURIs:   strings.Join(decodeList(provider.RedirectUris), "\n"),
		PostLogoutURIs: strings.Join(decodeList(provider.PostLogoutRedirectUris), "\n"),
		Public:         provider.Public,
		AccessTTL:      provider.AccessTokenTtlSeconds,
		RefreshTTL:     provider.RefreshTokenTtlSeconds,
		IDTTL:          provider.IDTokenTtlSeconds,
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
			ClientSecret: s.oidcStore.OpenClientSecret(provider.ClientSecretEnc),
		},
	})
}

func (s *Server) handleAdminAppDetail(w http.ResponseWriter, r *http.Request) {
	app, ok := s.loadApp(w, r)
	if !ok {
		return
	}
	if app.Kind == "proxy" {
		s.renderProxyDetail(w, r, app, "", r.URL.Query().Get("saved") == "1")
		return
	}
	provider, err := s.store.GetProviderByApplication(r.Context(), app.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.renderAppDetail(w, r, app, provider, "", r.URL.Query().Get("saved") == "1")
}

func (s *Server) handleAdminAppUpdate(w http.ResponseWriter, r *http.Request) {
	app, ok := s.loadApp(w, r)
	if !ok {
		return
	}
	if app.Kind == "proxy" {
		s.handleAdminProxyUpdate(w, r, app)
		return
	}
	provider, err := s.store.GetProviderByApplication(r.Context(), app.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	form := parseAppForm(r)
	form.Kind = "oidc"

	redirects, postLogout, err := form.validate()
	if err != nil {
		app.Name, app.Slug, app.LaunchUrl = form.Name, form.Slug, form.LaunchURL
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.renderAppDetail(w, r, app, provider, err.Error(), false)
		return
	}

	now := time.Now().UTC()
	if err := s.store.UpdateApplication(r.Context(), sqlcgen.UpdateApplicationParams{
		Name: form.Name, Slug: form.Slug, Description: form.Description, LaunchUrl: form.LaunchURL,
		ProxyHosts: app.ProxyHosts, UpdatedAt: now, ID: app.ID,
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
		AccessTokenTtlSeconds: form.AccessTTL, RefreshTokenTtlSeconds: form.RefreshTTL,
		IDTokenTtlSeconds: form.IDTTL, UpdatedAt: now, ID: provider.ID,
	}); err != nil {
		s.serverError(w, r, err)
		return
	}

	// Client type change: switching to public drops the secret (PKCE is
	// enforced instead); switching to confidential mints a fresh one,
	// visible in the Credentials section.
	if form.Public != provider.Public {
		var secretHash *string
		var secretEnc []byte
		if !form.Public {
			secret := randomHex(32)
			h := oidcserver.HashToken(secret)
			secretHash = &h
			if secretEnc, err = s.oidcStore.SealClientSecret(secret); err != nil {
				s.serverError(w, r, err)
				return
			}
		}
		if err := s.store.UpdateProviderType(r.Context(), sqlcgen.UpdateProviderTypeParams{
			Public: form.Public, ClientSecretHash: secretHash, ClientSecretEnc: secretEnc,
			UpdatedAt: now, ID: provider.ID,
		}); err != nil {
			s.serverError(w, r, err)
			return
		}
	}

	// Replace the group access policy (no boxes checked = everyone).
	if err := s.replacePolicy(r, app.ID); err != nil {
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
	enc, err := s.oidcStore.SealClientSecret(secret)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if err := s.store.UpdateProviderSecret(r.Context(), sqlcgen.UpdateProviderSecretParams{
		ClientSecretHash: &h, ClientSecretEnc: enc, UpdatedAt: time.Now().UTC(), ID: provider.ID,
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
	app, ok := s.loadApp(w, r)
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

// --- Proxy (forward-auth) applications -------------------------------------

type adminProxyDetailData struct {
	App    sqlcgen.Application
	Form   appForm
	Groups []sqlcgen.Group
	Bound  map[string]bool
	OutURL string
	Error  string
	Saved  bool
}

func (s *Server) renderProxyDetail(w http.ResponseWriter, r *http.Request, app sqlcgen.Application, errMsg string, saved bool) {
	form := appForm{
		Name: app.Name, Slug: app.Slug, Kind: "proxy", Description: app.Description,
		LaunchURL: app.LaunchUrl, ProxyHosts: strings.Join(decodeList(app.ProxyHosts), "\n"),
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
	s.render(w, r, "admin_proxy_detail.html", pageData{
		Title: app.Name, Active: "apps", CSRF: s.csrfToken(r.Context()),
		User: currentUser(r),
		Data: adminProxyDetailData{
			App: app, Form: form, Groups: groups, Bound: bound,
			OutURL: s.issuer() + "/outpost/auth", Error: errMsg, Saved: saved,
		},
	})
}

func (s *Server) handleAdminProxyUpdate(w http.ResponseWriter, r *http.Request, app sqlcgen.Application) {
	form := parseAppForm(r)
	form.Kind = "proxy"
	if _, _, err := form.validate(); err != nil {
		app.Name, app.Slug, app.Description = form.Name, form.Slug, form.Description
		app.LaunchUrl, app.ProxyHosts = form.LaunchURL, jsonList(parseHostList(form.ProxyHosts))
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.renderProxyDetail(w, r, app, err.Error(), false)
		return
	}

	now := time.Now().UTC()
	if err := s.store.UpdateApplication(r.Context(), sqlcgen.UpdateApplicationParams{
		Name: form.Name, Slug: form.Slug, Description: form.Description, LaunchUrl: form.LaunchURL,
		ProxyHosts: jsonList(parseHostList(form.ProxyHosts)), UpdatedAt: now, ID: app.ID,
	}); err != nil {
		if isUniqueViolation(err) {
			s.renderProxyDetail(w, r, app, "An application with this slug already exists.", false)
			return
		}
		s.serverError(w, r, err)
		return
	}
	if err := s.replacePolicy(r, app.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionAppUpdate, app.Slug, "proxy", clientIP(r))
	http.Redirect(w, r, "/admin/applications/"+app.ID+"?saved=1", http.StatusSeeOther)
}

// replacePolicy resets an application's group access policy from the
// submitted policy_groups values.
func (s *Server) replacePolicy(r *http.Request, appID string) error {
	tx, err := s.store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	q := s.store.Queries.WithTx(tx)
	if err := q.DeleteAppPolicies(r.Context(), appID); err != nil {
		return err
	}
	for _, groupID := range r.PostForm["policy_groups"] {
		if err := q.AddAppPolicy(r.Context(), sqlcgen.AddAppPolicyParams{
			ApplicationID: appID, GroupID: groupID,
		}); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// --- Icons -----------------------------------------------------------------

func (s *Server) handleAppIcon(w http.ResponseWriter, r *http.Request) {
	row, err := s.store.GetApplicationIcon(r.Context(), r.PathValue("id"))
	if err != nil || len(row.Icon) == 0 || row.IconMime == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", *row.IconMime)
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Write(row.Icon)
}

func (s *Server) handleAppIconUpload(w http.ResponseWriter, r *http.Request) {
	app, ok := s.loadApp(w, r)
	if !ok {
		return
	}
	back := "/admin/applications/" + app.ID
	if err := r.ParseMultipartForm(maxUploadPhotoSize); err != nil {
		http.Error(w, "the icon must be smaller than 1 MB", http.StatusRequestEntityTooLarge)
		return
	}
	file, _, err := r.FormFile("icon")
	if err != nil {
		http.Redirect(w, r, back, http.StatusSeeOther)
		return
	}
	defer file.Close()
	icon, err := io.ReadAll(io.LimitReader(file, maxUploadPhotoSize+1))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	mime := http.DetectContentType(icon)
	if len(icon) > maxUploadPhotoSize || !slices.Contains(allowedPhotoTypes, mime) {
		http.Error(w, "unsupported or oversized image (use JPEG, PNG, WebP or GIF up to 1 MB)", http.StatusBadRequest)
		return
	}
	if err := s.store.UpdateApplicationIcon(r.Context(), sqlcgen.UpdateApplicationIconParams{
		Icon: icon, IconMime: &mime, UpdatedAt: time.Now().UTC(), ID: app.ID,
	}); err != nil {
		s.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}

func (s *Server) handleAppIconDelete(w http.ResponseWriter, r *http.Request) {
	app, ok := s.loadApp(w, r)
	if !ok {
		return
	}
	if err := s.store.UpdateApplicationIcon(r.Context(), sqlcgen.UpdateApplicationIconParams{
		Icon: nil, IconMime: nil, UpdatedAt: time.Now().UTC(), ID: app.ID,
	}); err != nil {
		s.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, "/admin/applications/"+app.ID, http.StatusSeeOther)
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
	if err == nil {
		return false
	}
	msg := err.Error()
	// SQLite and PostgreSQL word this differently.
	return strings.Contains(msg, "UNIQUE constraint failed") ||
		strings.Contains(msg, "duplicate key value")
}
