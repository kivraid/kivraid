// Package web serves the HTML interface (login, user portal, admin) and
// dispatches the OIDC protocol endpoints. Templates and static assets are
// embedded in the binary.
package web

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alexedwards/scs/v2"
	"golang.org/x/time/rate"

	"github.com/kivraid/kivraid/internal/audit"
	"github.com/kivraid/kivraid/internal/broker"
	"github.com/kivraid/kivraid/internal/config"
	"github.com/kivraid/kivraid/internal/mailer"
	"github.com/kivraid/kivraid/internal/mfa"
	"github.com/kivraid/kivraid/internal/oidcserver"
	"github.com/kivraid/kivraid/internal/ratelimit"
	"github.com/kivraid/kivraid/internal/sources/ldap"
	"github.com/kivraid/kivraid/internal/sources/local"
	"github.com/kivraid/kivraid/internal/store"
	"github.com/kivraid/kivraid/internal/webauthn"
)

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed static/app.css static/app.js static/fonts static/favicon.svg
var staticFS embed.FS

type Server struct {
	cfg       config.Config
	version   string
	store     *store.Store
	local     *local.Source
	ldap      *ldap.Manager
	sessions  *scs.SessionManager
	oidc      http.Handler
	oidcStore *oidcserver.Storage
	mfa       *mfa.Manager
	webauthn  *webauthn.Manager
	audit     *audit.Recorder
	mailer    *mailer.Mailer
	broker    *broker.Manager
	log       *slog.Logger

	// smtpEnabled caches whether email delivery is configured, so templates
	// can gate "forgot password" / "verify email" affordances without a DB
	// hit per render. Refreshed at startup and after an admin saves SMTP.
	smtpEnabled atomic.Bool

	// Login brute-force protection: per-IP on attempts, per-username on
	// failures.
	ipLimiter   *ratelimit.Limiter
	userLimiter *ratelimit.Limiter

	// trustedProxies gates X-Forwarded-For handling in clientIP.
	trustedProxies []netip.Prefix

	// pages maps a page name to its parsed template set (layout + page).
	pages map[string]*template.Template

	// Branding is admin-editable and cached in memory; brandMu guards it and
	// brandVer is a content token for cache-busting the logo URL.
	brandMu       sync.RWMutex
	brandName     string
	brandLogo     []byte
	brandLogoMime string
	brandVer      string
	// brandBg is the optional sign-in background image; brandBgVer
	// cache-busts its URL the same way.
	brandBg     []byte
	brandBgMime string
	brandBgVer  string
}

// Deps bundles the server's collaborators.
type Deps struct {
	Config    config.Config
	Version   string
	Store     *store.Store
	Sessions  *scs.SessionManager
	OIDC      http.Handler
	OIDCStore *oidcserver.Storage
	LDAP      *ldap.Manager
	MFA       *mfa.Manager
	WebAuthn  *webauthn.Manager
	Audit     *audit.Recorder
	Mailer    *mailer.Mailer
	Broker    *broker.Manager
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
		version:        d.Version,
		store:          d.Store,
		local:          local.NewSource(d.Store),
		ldap:           d.LDAP,
		sessions:       d.Sessions,
		oidc:           d.OIDC,
		oidcStore:      d.OIDCStore,
		mfa:            d.MFA,
		webauthn:       d.WebAuthn,
		audit:          d.Audit,
		mailer:         d.Mailer,
		broker:         d.Broker,
		log:            d.Log,
		// 10 attempts/minute per IP, 5 failures/minute per username.
		ipLimiter:   ratelimit.New(rate.Every(6*time.Second), 10),
		userLimiter: ratelimit.New(rate.Every(12*time.Second), 5),
		pages:       map[string]*template.Template{},
	}

	// Load the admin-editable branding before first render; defaults are
	// used if it cannot be read.
	s.loadBranding(context.Background())
	s.refreshSMTPCache(context.Background())

	// Asset URLs carry a content hash so browsers can cache aggressively
	// yet pick up new CSS/JS immediately after an upgrade.
	assetV := assetVersion()
	funcs := template.FuncMap{
		"initials":    initials,
		"tileClass":   tileClass,
		"since":       since,
		"actionLabel": audit.Label,
		"actionTone":  audit.Tone,
		"localTime":   localTime,
		"deref":       deref,
		"asset": func(name string) string {
			return "/static/" + name + "?v=" + assetV
		},
		// Branding helpers read the in-memory cache at render time, so a
		// save is reflected on the next page load.
		"brandName":          s.brandDisplayName,
		"brandHasLogo":       s.brandHasLogo,
		"brandLogoURL":       func() string { return "/brand/logo?v=" + s.brandVersion() },
		"brandHasBackground": s.brandHasBackground,
		"brandBackgroundURL": func() string { return "/brand/background?v=" + s.brandBackgroundVersion() },
		"mailEnabled":        s.smtpEnabled.Load,
	}
	standalone := []string{"login.html", "login_password.html", "login_mfa.html", "error.html", "setup.html",
		"forgot.html", "reset.html"}
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
		"admin_providers.html", "admin_providers_form.html", "admin_routing.html",
		"admin_users.html", "admin_user_new.html", "admin_user_detail.html",
		"admin_groups.html", "admin_group_detail.html", "admin_system.html",
		"admin_dashboard.html", "admin_branding.html", "admin_smtp.html",
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
	web.HandleFunc("POST /login", s.handleLoginIdentify)
	web.HandleFunc("POST /login/account", s.handleLoginAccount)
	web.HandleFunc("POST /login/account/forget", s.handleLoginAccountForget)
	web.HandleFunc("GET /login/password", s.handleLoginPasswordPage)
	web.HandleFunc("POST /login/password", s.handleLoginPasswordSubmit)
	web.HandleFunc("GET /login/mfa", s.handleMFAChallengePage)
	web.HandleFunc("POST /login/mfa", s.handleMFAChallengeSubmit)
	web.HandleFunc("POST /login/passkey/begin", s.handlePasskeyLoginBegin)
	web.HandleFunc("POST /login/passkey/finish", s.handlePasskeyLoginFinish)
	web.HandleFunc("POST /logout", s.handleLogout)
	web.HandleFunc("GET /setup", s.handleSetupPage)
	web.HandleFunc("POST /setup", s.handleSetupSubmit)
	web.HandleFunc("GET /forgot", s.handleForgotPage)
	web.HandleFunc("POST /forgot", s.handleForgotSubmit)
	web.HandleFunc("GET /reset", s.handleResetPage)
	web.HandleFunc("POST /reset", s.handleResetSubmit)
	web.HandleFunc("GET /verify-email", s.handleVerifyEmail)
	web.Handle("GET "+passwordChangePath, s.requireAuth(http.HandlerFunc(s.handlePasswordChangeRequired)))
	web.Handle("POST "+passwordChangePath, s.requireAuth(http.HandlerFunc(s.handlePasswordChangeRequired)))
	web.HandleFunc("GET /login/upstream/{id}/start", s.handleUpstreamLoginStart)
	web.HandleFunc("GET /login/upstream/{id}/callback", s.handleUpstreamLoginCallback)
	// Public custom logo and background (the login page, served before
	// auth, references them).
	web.HandleFunc("GET /brand/logo", s.handleBrandLogo)
	web.HandleFunc("GET /brand/background", s.handleBrandBackground)
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
	web.Handle("POST /profile/verify-email", s.requireAuth(http.HandlerFunc(s.handleProfileSendVerification)))
	web.Handle("GET /sessions", s.requireAuth(http.HandlerFunc(s.handleSessions)))
	web.Handle("POST /sessions/revoke", s.requireAuth(http.HandlerFunc(s.handleSessionRevoke)))
	web.Handle("POST /sessions/revoke-others", s.requireAuth(http.HandlerFunc(s.handleSessionsRevokeOthers)))
	web.Handle("GET "+oidcserver.ResumePath, s.requireAuth(http.HandlerFunc(s.handleOIDCResume)))
	web.Handle("POST /impersonate/stop", s.requireAuth(http.HandlerFunc(s.handleImpersonateStop)))
	web.HandleFunc("GET /outpost/auth", s.handleForwardAuth)

	web.Handle("GET /admin", s.requireAdmin(http.HandlerFunc(s.handleAdminDashboard)))

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

	web.Handle("GET /admin/providers", s.requireAdmin(http.HandlerFunc(s.handleAdminProviders)))
	web.Handle("GET /admin/providers/new", s.requireAdmin(http.HandlerFunc(s.handleAdminProviderNew)))
	web.Handle("POST /admin/providers", s.requireAdmin(http.HandlerFunc(s.handleAdminProviderCreate)))
	web.Handle("POST /admin/providers/test", s.requireAdmin(http.HandlerFunc(s.handleAdminProviderTestDraft)))
	web.Handle("GET /admin/providers/{id}", s.requireAdmin(http.HandlerFunc(s.handleAdminProviderEdit)))
	web.Handle("POST /admin/providers/{id}", s.requireAdmin(http.HandlerFunc(s.handleAdminProviderUpdate)))
	web.Handle("POST /admin/providers/{id}/test", s.requireAdmin(http.HandlerFunc(s.handleAdminProviderTest)))
	web.Handle("POST /admin/providers/{id}/delete", s.requireAdmin(http.HandlerFunc(s.handleAdminProviderDelete)))
	web.Handle("GET /admin/routing", s.requireAdmin(http.HandlerFunc(s.handleAdminRouting)))
	web.Handle("POST /admin/routing", s.requireAdmin(http.HandlerFunc(s.handleAdminRoutingAdd)))
	web.Handle("POST /admin/routing/default", s.requireAdmin(http.HandlerFunc(s.handleAdminRoutingDefault)))
	web.Handle("POST /admin/routing/{id}/delete", s.requireAdmin(http.HandlerFunc(s.handleAdminRoutingDelete)))

	web.Handle("GET /admin/users", s.requireAdmin(http.HandlerFunc(s.handleAdminUsers)))
	web.Handle("GET /admin/users/new", s.requireAdmin(http.HandlerFunc(s.handleAdminUserNew)))
	web.Handle("POST /admin/users", s.requireAdmin(http.HandlerFunc(s.handleAdminUserCreate)))
	web.Handle("GET /admin/users/{id}", s.requireAdmin(http.HandlerFunc(s.handleAdminUserDetail)))
	web.Handle("POST /admin/users/{id}", s.requireAdmin(http.HandlerFunc(s.handleAdminUserUpdate)))
	web.Handle("POST /admin/users/{id}/password", s.requireAdmin(http.HandlerFunc(s.handleAdminUserPassword)))
	web.Handle("POST /admin/users/{id}/password/send-reset", s.requireAdmin(http.HandlerFunc(s.handleAdminUserSendReset)))
	web.Handle("POST /admin/users/{id}/groups", s.requireAdmin(http.HandlerFunc(s.handleAdminUserGroupAdd)))
	web.Handle("POST /admin/users/{id}/groups/remove", s.requireAdmin(http.HandlerFunc(s.handleAdminUserGroupRemove)))
	web.Handle("POST /admin/users/{id}/passkeys/{pk}/delete", s.requireAdmin(http.HandlerFunc(s.handleAdminUserPasskeyDelete)))
	web.Handle("POST /admin/users/{id}/mfa/reset", s.requireAdmin(http.HandlerFunc(s.handleAdminUserMFAReset)))
	web.Handle("POST /admin/users/{id}/sessions/revoke", s.requireAdmin(http.HandlerFunc(s.handleAdminUserSessionsRevoke)))
	web.Handle("POST /admin/users/{id}/impersonate", s.requireAdmin(http.HandlerFunc(s.handleAdminUserImpersonate)))
	web.Handle("POST /admin/users/{id}/verify-email", s.requireAdmin(http.HandlerFunc(s.handleAdminUserSendVerification)))
	web.Handle("POST /admin/users/{id}/delete", s.requireAdmin(http.HandlerFunc(s.handleAdminUserDelete)))

	web.Handle("GET /admin/groups", s.requireAdmin(http.HandlerFunc(s.handleAdminGroups)))
	web.Handle("POST /admin/groups", s.requireAdmin(http.HandlerFunc(s.handleAdminGroupCreate)))
	web.Handle("GET /admin/groups/{id}", s.requireAdmin(http.HandlerFunc(s.handleAdminGroupDetail)))
	web.Handle("GET /admin/groups/{id}/candidates", s.requireAdmin(http.HandlerFunc(s.handleAdminGroupCandidates)))
	web.Handle("POST /admin/groups/{id}", s.requireAdmin(http.HandlerFunc(s.handleAdminGroupUpdate)))
	web.Handle("POST /admin/groups/{id}/members", s.requireAdmin(http.HandlerFunc(s.handleAdminGroupAddMember)))
	web.Handle("POST /admin/groups/{id}/members/remove", s.requireAdmin(http.HandlerFunc(s.handleAdminGroupRemoveMember)))
	web.Handle("POST /admin/groups/{id}/delete", s.requireAdmin(http.HandlerFunc(s.handleAdminGroupDelete)))

	web.Handle("GET /admin/audit", s.requireAdmin(http.HandlerFunc(s.handleAdminAudit)))
	web.Handle("GET /admin/audit/export.csv", s.requireAdmin(http.HandlerFunc(s.handleAdminAuditExport)))

	// Instance settings, grouped under one nav entry with server-rendered
	// tabs (one URL per tab).
	web.Handle("GET /admin/settings", s.requireAdmin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/settings/system", http.StatusSeeOther)
	})))
	web.Handle("GET /admin/settings/branding", s.requireAdmin(http.HandlerFunc(s.handleAdminBranding)))
	web.Handle("POST /admin/settings/branding", s.requireAdmin(http.HandlerFunc(s.handleAdminBrandingSave)))
	web.Handle("POST /admin/settings/branding/logo/delete", s.requireAdmin(http.HandlerFunc(s.handleAdminBrandingLogoDelete)))
	web.Handle("POST /admin/settings/branding/background/delete", s.requireAdmin(http.HandlerFunc(s.handleAdminBrandingBackgroundDelete)))
	web.Handle("GET /admin/settings/email", s.requireAdmin(http.HandlerFunc(s.handleAdminSMTP)))
	web.Handle("POST /admin/settings/email", s.requireAdmin(http.HandlerFunc(s.handleAdminSMTPSave)))
	web.Handle("POST /admin/settings/email/test", s.requireAdmin(http.HandlerFunc(s.handleAdminSMTPTest)))
	web.Handle("GET /admin/settings/system", s.requireAdmin(http.HandlerFunc(s.handleAdminSystem)))
	web.Handle("POST /admin/settings/system/rotate-key", s.requireAdmin(http.HandlerFunc(s.handleAdminSystemRotateKey)))

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
			switch pattern {
			case "/end_session":
				continue
			case "/authorize":
				// Turn op's bare 400 for an unknown client / unregistered
				// redirect_uri into a branded, actionable error page.
				root.Handle(pattern, s.guardAuthorize(s.oidc))
			default:
				root.Handle(pattern, s.oidc)
			}
		}
		root.Handle("/end_session", s.sessions.LoadAndSave(http.HandlerFunc(s.handleEndSession)))
	}
	root.Handle("/", webChain)
	return root
}

// localTime renders a timestamp as a <time> element: the server shows UTC,
// and app.js rewrites it in the viewer's timezone.
func localTime(t time.Time) template.HTML {
	u := t.UTC()
	return template.HTML(fmt.Sprintf(`<time datetime="%s" data-local>%s UTC</time>`,
		u.Format(time.RFC3339), template.HTMLEscapeString(u.Format("Jan 2, 2006 15:04"))))
}

// since renders how long ago t was, coarsely: "just now", "5 minutes ago",
// "3 days ago", then a date for anything older than a month.
func since(t time.Time) string {
	d := time.Since(t)
	plural := func(n int, unit string) string {
		if n == 1 {
			return "1 " + unit + " ago"
		}
		return fmt.Sprintf("%d %ss ago", n, unit)
	}
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return plural(int(d/time.Minute), "minute")
	case d < 24*time.Hour:
		return plural(int(d/time.Hour), "hour")
	case d < 30*24*time.Hour:
		return plural(int(d/(24*time.Hour)), "day")
	}
	return "on " + t.Format("Jan 2, 2006")
}

// tileClass picks one of the app-tile gradients from a name, stably, so an
// application keeps its color everywhere it appears.
func tileClass(name string) string {
	h := fnv.New32a()
	h.Write([]byte(strings.ToLower(name)))
	return "tile-" + strconv.Itoa(int(h.Sum32()%6))
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
