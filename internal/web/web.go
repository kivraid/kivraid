// Package web serves the HTML interface (login, user portal, admin) and
// dispatches the OIDC protocol endpoints. Templates and static assets are
// embedded in the binary.
package web

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/alexedwards/scs/v2"
	"golang.org/x/time/rate"

	"github.com/lporcheron/kivraid/internal/audit"
	"github.com/lporcheron/kivraid/internal/config"
	"github.com/lporcheron/kivraid/internal/mfa"
	"github.com/lporcheron/kivraid/internal/oidcserver"
	"github.com/lporcheron/kivraid/internal/ratelimit"
	"github.com/lporcheron/kivraid/internal/sources/ldap"
	"github.com/lporcheron/kivraid/internal/sources/local"
	"github.com/lporcheron/kivraid/internal/store"
	"github.com/lporcheron/kivraid/internal/webauthn"
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
	mfa       *mfa.Manager
	webauthn  *webauthn.Manager
	audit     *audit.Recorder
	log       *slog.Logger

	// Login brute-force protection: per-IP on attempts, per-username on
	// failures.
	ipLimiter   *ratelimit.Limiter
	userLimiter *ratelimit.Limiter

	// trustedProxies gates X-Forwarded-For handling in clientIP.
	trustedProxies []netip.Prefix

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
	MFA       *mfa.Manager
	WebAuthn  *webauthn.Manager
	Audit     *audit.Recorder
	Log       *slog.Logger
}

func NewServer(d Deps) (*Server, error) {
	if d.Audit == nil {
		d.Audit = audit.NewRecorder(d.Store, d.Log)
	}
	proxies, err := config.ParseTrustedProxies(d.Config.TrustedProxies)
	if err != nil {
		return nil, err
	}
	s := &Server{
		trustedProxies: proxies,
		cfg:            d.Config,
		store:          d.Store,
		local:          local.NewSource(d.Store),
		ldap:           d.LDAP,
		sessions:       d.Sessions,
		oidc:           d.OIDC,
		oidcStore:      d.OIDCStore,
		mfa:            d.MFA,
		webauthn:       d.WebAuthn,
		audit:          d.Audit,
		log:            d.Log,
		// 10 attempts/minute per IP, 5 failures/minute per username.
		ipLimiter:   ratelimit.New(rate.Every(6*time.Second), 10),
		userLimiter: ratelimit.New(rate.Every(12*time.Second), 5),
		pages:       map[string]*template.Template{},
	}

	// Asset URLs carry a content hash so browsers can cache aggressively
	// yet pick up new CSS/JS immediately after an upgrade.
	assetV := assetVersion()
	funcs := template.FuncMap{
		"initials": initials,
		"deref": func(p *string) string {
			if p == nil {
				return ""
			}
			return *p
		},
		"asset": func(name string) string {
			return "/static/" + name + "?v=" + assetV
		},
	}
	standalone := []string{"login.html", "login_mfa.html", "error.html", "setup.html"}
	for _, page := range standalone {
		t, err := template.New(page).Funcs(funcs).ParseFS(templatesFS, "templates/"+page)
		if err != nil {
			return nil, fmt.Errorf("parse template %s: %w", page, err)
		}
		s.pages[page] = t
	}
	withLayout := []string{
		"home.html", "profile.html", "sessions.html", "denied.html",
		"mfa_enroll.html", "mfa_recovery.html",
		"admin_apps.html", "admin_app_new.html", "admin_app_secret.html", "admin_app_detail.html",
		"admin_proxy_detail.html",
		"admin_ldap.html", "admin_ldap_form.html", "admin_audit.html",
		"admin_users.html", "admin_user_new.html", "admin_user_detail.html",
		"admin_groups.html", "admin_group_detail.html",
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
	web.HandleFunc("GET /login/mfa", s.handleMFAChallengePage)
	web.HandleFunc("POST /login/mfa", s.handleMFAChallengeSubmit)
	web.HandleFunc("POST /login/passkey/begin", s.handlePasskeyLoginBegin)
	web.HandleFunc("POST /login/passkey/finish", s.handlePasskeyLoginFinish)
	web.HandleFunc("POST /logout", s.handleLogout)
	web.HandleFunc("GET /setup", s.handleSetupPage)
	web.HandleFunc("POST /setup", s.handleSetupSubmit)
	web.Handle("GET /{$}", s.requireAuth(http.HandlerFunc(s.handleHome)))
	web.Handle("GET /avatar/{id}", s.requireAuth(http.HandlerFunc(s.handleAvatar)))
	web.Handle("GET /appicon/{id}", s.requireAuth(http.HandlerFunc(s.handleAppIcon)))
	web.Handle("GET /profile", s.requireAuth(http.HandlerFunc(s.handleProfile)))
	web.Handle("POST /profile/password", s.requireAuth(http.HandlerFunc(s.handleProfilePassword)))
	web.Handle("POST /profile/photo", s.requireAuth(http.HandlerFunc(s.handleProfilePhoto)))
	web.Handle("POST /profile/photo/delete", s.requireAuth(http.HandlerFunc(s.handleProfilePhotoDelete)))
	web.Handle("POST /profile/mfa/begin", s.requireAuth(http.HandlerFunc(s.handleMFABegin)))
	web.Handle("GET /profile/mfa/qr", s.requireAuth(http.HandlerFunc(s.handleMFAQR)))
	web.Handle("POST /profile/mfa/enable", s.requireAuth(http.HandlerFunc(s.handleMFAEnable)))
	web.Handle("POST /profile/mfa/disable", s.requireAuth(http.HandlerFunc(s.handleMFADisable)))
	web.Handle("POST /profile/mfa/recovery", s.requireAuth(http.HandlerFunc(s.handleMFARegenerateRecovery)))
	web.Handle("POST /profile/passkeys/begin", s.requireAuth(http.HandlerFunc(s.handlePasskeyRegisterBegin)))
	web.Handle("POST /profile/passkeys/finish", s.requireAuth(http.HandlerFunc(s.handlePasskeyRegisterFinish)))
	web.Handle("POST /profile/passkeys/{id}/delete", s.requireAuth(http.HandlerFunc(s.handlePasskeyDelete)))
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
	web.Handle("POST /admin/applications/{id}/icon", s.requireAdmin(http.HandlerFunc(s.handleAppIconUpload)))
	web.Handle("POST /admin/applications/{id}/icon/delete", s.requireAdmin(http.HandlerFunc(s.handleAppIconDelete)))
	web.Handle("POST /admin/applications/{id}/delete", s.requireAdmin(http.HandlerFunc(s.handleAdminAppDelete)))

	web.Handle("GET /admin/ldap", s.requireAdmin(http.HandlerFunc(s.handleAdminLdapList)))
	web.Handle("GET /admin/ldap/new", s.requireAdmin(http.HandlerFunc(s.handleAdminLdapNew)))
	web.Handle("POST /admin/ldap", s.requireAdmin(http.HandlerFunc(s.handleAdminLdapCreate)))
	web.Handle("POST /admin/ldap/test", s.requireAdmin(http.HandlerFunc(s.handleAdminLdapTestDraft)))
	web.Handle("GET /admin/ldap/{id}", s.requireAdmin(http.HandlerFunc(s.handleAdminLdapEdit)))
	web.Handle("POST /admin/ldap/{id}", s.requireAdmin(http.HandlerFunc(s.handleAdminLdapUpdate)))
	web.Handle("POST /admin/ldap/{id}/test", s.requireAdmin(http.HandlerFunc(s.handleAdminLdapTest)))
	web.Handle("POST /admin/ldap/{id}/sync", s.requireAdmin(http.HandlerFunc(s.handleAdminLdapSync)))
	web.Handle("POST /admin/ldap/{id}/delete", s.requireAdmin(http.HandlerFunc(s.handleAdminLdapDelete)))

	web.Handle("GET /admin/users", s.requireAdmin(http.HandlerFunc(s.handleAdminUsers)))
	web.Handle("GET /admin/users/new", s.requireAdmin(http.HandlerFunc(s.handleAdminUserNew)))
	web.Handle("POST /admin/users", s.requireAdmin(http.HandlerFunc(s.handleAdminUserCreate)))
	web.Handle("GET /admin/users/{id}", s.requireAdmin(http.HandlerFunc(s.handleAdminUserDetail)))
	web.Handle("POST /admin/users/{id}", s.requireAdmin(http.HandlerFunc(s.handleAdminUserUpdate)))
	web.Handle("POST /admin/users/{id}/password", s.requireAdmin(http.HandlerFunc(s.handleAdminUserPassword)))
	web.Handle("POST /admin/users/{id}/mfa/reset", s.requireAdmin(http.HandlerFunc(s.handleAdminUserMFAReset)))
	web.Handle("POST /admin/users/{id}/delete", s.requireAdmin(http.HandlerFunc(s.handleAdminUserDelete)))

	web.Handle("GET /admin/groups", s.requireAdmin(http.HandlerFunc(s.handleAdminGroups)))
	web.Handle("POST /admin/groups", s.requireAdmin(http.HandlerFunc(s.handleAdminGroupCreate)))
	web.Handle("GET /admin/groups/{id}", s.requireAdmin(http.HandlerFunc(s.handleAdminGroupDetail)))
	web.Handle("POST /admin/groups/{id}", s.requireAdmin(http.HandlerFunc(s.handleAdminGroupRename)))
	web.Handle("POST /admin/groups/{id}/role", s.requireAdmin(http.HandlerFunc(s.handleAdminGroupRole)))
	web.Handle("POST /admin/groups/{id}/members", s.requireAdmin(http.HandlerFunc(s.handleAdminGroupAddMember)))
	web.Handle("POST /admin/groups/{id}/members/remove", s.requireAdmin(http.HandlerFunc(s.handleAdminGroupRemoveMember)))
	web.Handle("POST /admin/groups/{id}/delete", s.requireAdmin(http.HandlerFunc(s.handleAdminGroupDelete)))

	web.Handle("GET /admin/audit", s.requireAdmin(http.HandlerFunc(s.handleAdminAudit)))

	// Anything else under the web surface gets the styled 404.
	web.HandleFunc("/", s.handleNotFound)

	webChain := s.secureHeaders(s.sessions.LoadAndSave(s.csrfProtect(web)))

	root := http.NewServeMux()
	static, _ := fs.Sub(staticFS, "static")
	root.Handle("GET /static/", http.StripPrefix("/static/", cacheStatic(http.FileServerFS(static))))
	root.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok"))
	})
	// Public avatar endpoint for the OIDC `picture` claim: served without a
	// session so relying parties can fetch it (see handlePublicAvatar).
	root.HandleFunc("GET /oidc/avatar/{id}", s.handlePublicAvatar)
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
		// Versioned URLs (?v=<content hash>) change whenever the asset
		// does, so those responses can be cached indefinitely. Anything
		// referenced without a version keeps a short lifetime.
		if r.URL.Query().Get("v") != "" {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "public, max-age=3600")
		}
		next.ServeHTTP(w, r)
	})
}

// assetVersion hashes the embedded CSS and JS into a short cache-busting
// token that changes with any asset change.
func assetVersion() string {
	h := sha256.New()
	for _, name := range []string{"static/app.css", "static/app.js"} {
		b, err := staticFS.ReadFile(name)
		if err != nil {
			// Embedded files cannot go missing at runtime; be defensive
			// anyway and fall back to an uncached-style token.
			return "dev"
		}
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}
