// Package web serves the HTML interface (login, user portal, admin) and
// dispatches the OIDC protocol endpoints. Templates and static assets are
// embedded in the binary.
package web

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/alexedwards/scs/v2"
	"golang.org/x/time/rate"

	"github.com/lporcheron/kivraid/internal/audit"
	"github.com/lporcheron/kivraid/internal/config"
	"github.com/lporcheron/kivraid/internal/oidcserver"
	"github.com/lporcheron/kivraid/internal/ratelimit"
	"github.com/lporcheron/kivraid/internal/sources/ldap"
	"github.com/lporcheron/kivraid/internal/sources/local"
	"github.com/lporcheron/kivraid/internal/store"
)

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed static/app.css static/app.js static/fonts static/favicon.svg
var staticFS embed.FS

type Server struct {
	cfg       config.Config
	store     *store.Store
	local     *local.Source
	ldap      *ldap.Manager
	sessions  *scs.SessionManager
	oidc      http.Handler
	oidcStore *oidcserver.Storage
	audit     *audit.Recorder
	log       *slog.Logger

	// Login brute-force protection: per-IP on attempts, per-username on
	// failures.
	ipLimiter   *ratelimit.Limiter
	userLimiter *ratelimit.Limiter

	// pages maps a page name to its parsed template set (layout + page).
	pages map[string]*template.Template
}

// Deps bundles the server's collaborators.
type Deps struct {
	Config    config.Config
	Store     *store.Store
	Sessions  *scs.SessionManager
	OIDC      http.Handler
	OIDCStore *oidcserver.Storage
	LDAP      *ldap.Manager
	Audit     *audit.Recorder
	Log       *slog.Logger
}

func NewServer(d Deps) (*Server, error) {
	if d.Audit == nil {
		d.Audit = audit.NewRecorder(d.Store, d.Log)
	}
	s := &Server{
		cfg:       d.Config,
		store:     d.Store,
		local:     local.NewSource(d.Store),
		ldap:      d.LDAP,
		sessions:  d.Sessions,
		oidc:      d.OIDC,
		oidcStore: d.OIDCStore,
		audit:     d.Audit,
		log:       d.Log,
		// 10 attempts/minute per IP, 5 failures/minute per username.
		ipLimiter:   ratelimit.New(rate.Every(6*time.Second), 10),
		userLimiter: ratelimit.New(rate.Every(12*time.Second), 5),
		pages:       map[string]*template.Template{},
	}

	funcs := template.FuncMap{
		"initials": initials,
	}
	standalone := []string{"login.html", "error.html"}
	for _, page := range standalone {
		t, err := template.New(page).Funcs(funcs).ParseFS(templatesFS, "templates/"+page)
		if err != nil {
			return nil, fmt.Errorf("parse template %s: %w", page, err)
		}
		s.pages[page] = t
	}
	withLayout := []string{
		"home.html", "profile.html", "sessions.html", "denied.html",
		"admin_apps.html", "admin_app_new.html", "admin_app_secret.html", "admin_app_detail.html",
		"admin_ldap.html", "admin_ldap_form.html", "admin_audit.html",
	}
	for _, page := range withLayout {
		t, err := template.New("layout.html").Funcs(funcs).
			ParseFS(templatesFS, "templates/layout.html", "templates/"+page)
		if err != nil {
			return nil, fmt.Errorf("parse template %s: %w", page, err)
		}
		s.pages[page] = t
	}
	return s, nil
}

func (s *Server) Handler() http.Handler {
	web := http.NewServeMux()
	web.HandleFunc("GET /login", s.handleLoginPage)
	web.HandleFunc("POST /login", s.handleLoginSubmit)
	web.HandleFunc("POST /logout", s.handleLogout)
	web.Handle("GET /{$}", s.requireAuth(http.HandlerFunc(s.handleHome)))
	web.Handle("GET /profile", s.requireAuth(http.HandlerFunc(s.handleProfile)))
	web.Handle("POST /profile/password", s.requireAuth(http.HandlerFunc(s.handleProfilePassword)))
	web.Handle("GET /sessions", s.requireAuth(http.HandlerFunc(s.handleSessions)))
	web.Handle("POST /sessions/revoke", s.requireAuth(http.HandlerFunc(s.handleSessionRevoke)))
	web.Handle("POST /sessions/revoke-others", s.requireAuth(http.HandlerFunc(s.handleSessionsRevokeOthers)))
	web.Handle("GET "+oidcserver.ResumePath, s.requireAuth(http.HandlerFunc(s.handleOIDCResume)))
	web.HandleFunc("GET /outpost/auth", s.handleForwardAuth)

	web.Handle("GET /admin/applications", s.requireAdmin(http.HandlerFunc(s.handleAdminApps)))
	web.Handle("GET /admin/applications/new", s.requireAdmin(http.HandlerFunc(s.handleAdminAppNew)))
	web.Handle("POST /admin/applications", s.requireAdmin(http.HandlerFunc(s.handleAdminAppCreate)))
	web.Handle("GET /admin/applications/{id}", s.requireAdmin(http.HandlerFunc(s.handleAdminAppDetail)))
	web.Handle("POST /admin/applications/{id}", s.requireAdmin(http.HandlerFunc(s.handleAdminAppUpdate)))
	web.Handle("POST /admin/applications/{id}/rotate-secret", s.requireAdmin(http.HandlerFunc(s.handleAdminAppRotateSecret)))
	web.Handle("POST /admin/applications/{id}/delete", s.requireAdmin(http.HandlerFunc(s.handleAdminAppDelete)))

	web.Handle("GET /admin/ldap", s.requireAdmin(http.HandlerFunc(s.handleAdminLdapList)))
	web.Handle("GET /admin/ldap/new", s.requireAdmin(http.HandlerFunc(s.handleAdminLdapNew)))
	web.Handle("POST /admin/ldap", s.requireAdmin(http.HandlerFunc(s.handleAdminLdapCreate)))
	web.Handle("GET /admin/ldap/{id}", s.requireAdmin(http.HandlerFunc(s.handleAdminLdapEdit)))
	web.Handle("POST /admin/ldap/{id}", s.requireAdmin(http.HandlerFunc(s.handleAdminLdapUpdate)))
	web.Handle("POST /admin/ldap/{id}/test", s.requireAdmin(http.HandlerFunc(s.handleAdminLdapTest)))
	web.Handle("POST /admin/ldap/{id}/delete", s.requireAdmin(http.HandlerFunc(s.handleAdminLdapDelete)))

	web.Handle("GET /admin/audit", s.requireAdmin(http.HandlerFunc(s.handleAdminAudit)))

	// Anything else under the web surface gets the styled 404.
	web.HandleFunc("/", s.handleNotFound)

	webChain := secureHeaders(s.sessions.LoadAndSave(s.csrfProtect(web)))

	root := http.NewServeMux()
	static, _ := fs.Sub(staticFS, "static")
	root.Handle("GET /static/", http.StripPrefix("/static/", cacheStatic(http.FileServerFS(static))))
	root.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok"))
	})
	// Protocol endpoints are API surface: no session, no CSRF, no CSP.
	// end_session is the exception: it needs the session middleware so
	// RP-initiated logout also terminates the Kivraid session.
	if s.oidc != nil {
		for _, pattern := range oidcserver.Routes() {
			if pattern == "/end_session" {
				continue
			}
			root.Handle(pattern, s.oidc)
		}
		root.Handle("/end_session", s.sessions.LoadAndSave(http.HandlerFunc(s.handleEndSession)))
	}
	root.Handle("/", webChain)
	return root
}

// initials derives up-to-two uppercase initials for the avatar chip.
func initials(name string) string {
	fields := strings.Fields(name)
	switch {
	case len(fields) >= 2:
		return upperFirst(fields[0]) + upperFirst(fields[1])
	case len(fields) == 1:
		return upperFirst(fields[0])
	default:
		return "?"
	}
}

func upperFirst(s string) string {
	for _, r := range s {
		return strings.ToUpper(string(r))
	}
	return ""
}

func cacheStatic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		next.ServeHTTP(w, r)
	})
}
