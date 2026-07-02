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

	"github.com/alexedwards/scs/v2"

	"github.com/lporcheron/kivraid/internal/config"
	"github.com/lporcheron/kivraid/internal/oidcserver"
	"github.com/lporcheron/kivraid/internal/sources/local"
	"github.com/lporcheron/kivraid/internal/store"
)

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed static/app.css static/app.js static/fonts static/htmx.min.js static/favicon.svg
var staticFS embed.FS

type Server struct {
	cfg       config.Config
	store     *store.Store
	local     *local.Source
	sessions  *scs.SessionManager
	oidc      http.Handler
	oidcStore *oidcserver.Storage
	log       *slog.Logger

	// pages maps a page name to its parsed template set (layout + page).
	pages map[string]*template.Template
}

func NewServer(cfg config.Config, st *store.Store, sessions *scs.SessionManager,
	oidcHandler http.Handler, oidcStore *oidcserver.Storage, log *slog.Logger) (*Server, error) {
	s := &Server{
		cfg:       cfg,
		store:     st,
		local:     local.NewSource(st),
		sessions:  sessions,
		oidc:      oidcHandler,
		oidcStore: oidcStore,
		log:       log,
		pages:     map[string]*template.Template{},
	}

	funcs := template.FuncMap{
		"initials": initials,
	}
	standalone := []string{"login.html"}
	for _, page := range standalone {
		t, err := template.New(page).Funcs(funcs).ParseFS(templatesFS, "templates/"+page)
		if err != nil {
			return nil, fmt.Errorf("parse template %s: %w", page, err)
		}
		s.pages[page] = t
	}
	withLayout := []string{
		"profile.html",
		"admin_apps.html", "admin_app_new.html", "admin_app_secret.html", "admin_app_detail.html",
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
	web.Handle("GET "+oidcserver.ResumePath, s.requireAuth(http.HandlerFunc(s.handleOIDCResume)))

	web.Handle("GET /admin/applications", s.requireAdmin(http.HandlerFunc(s.handleAdminApps)))
	web.Handle("GET /admin/applications/new", s.requireAdmin(http.HandlerFunc(s.handleAdminAppNew)))
	web.Handle("POST /admin/applications", s.requireAdmin(http.HandlerFunc(s.handleAdminAppCreate)))
	web.Handle("GET /admin/applications/{id}", s.requireAdmin(http.HandlerFunc(s.handleAdminAppDetail)))
	web.Handle("POST /admin/applications/{id}", s.requireAdmin(http.HandlerFunc(s.handleAdminAppUpdate)))
	web.Handle("POST /admin/applications/{id}/rotate-secret", s.requireAdmin(http.HandlerFunc(s.handleAdminAppRotateSecret)))
	web.Handle("POST /admin/applications/{id}/delete", s.requireAdmin(http.HandlerFunc(s.handleAdminAppDelete)))

	webChain := secureHeaders(s.sessions.LoadAndSave(s.csrfProtect(web)))

	root := http.NewServeMux()
	static, _ := fs.Sub(staticFS, "static")
	root.Handle("GET /static/", http.StripPrefix("/static/", cacheStatic(http.FileServerFS(static))))
	root.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok"))
	})
	// Protocol endpoints are API surface: no session, no CSRF, no CSP.
	if s.oidc != nil {
		for _, pattern := range oidcserver.Routes() {
			root.Handle(pattern, s.oidc)
		}
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
