package web

import (
	"fmt"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"runtime/debug"
	"strings"
	"time"

	"github.com/kivraid/kivraid/internal/audit"
	"github.com/kivraid/kivraid/internal/i18n"
)

type systemRow struct {
	Label string // English message, translated in the template
	Value string
	// Mono renders the value in a monospace box (URLs, IPs, DSNs).
	Mono bool
}

type adminSystemData struct {
	Config  []systemRow
	Request []systemRow
	// Signing-key card.
	SigningAlg    string
	PublishedKeys int
	CanRotate     bool
	KeyCreated    time.Time
	RotationDays  int32 // automatic rotation period, 0 = manual
	NextRotation  time.Time
	KeyRotated    bool
}

var dsnPasswordRe = regexp.MustCompile(`(?i)password=[^ ]+`)

// redactDSN removes credentials from a database DSN before display. SQLite
// DSNs are file paths and shown as-is; Postgres DSNs (URL or keyword form)
// have their password stripped.
func redactDSN(driver, dsn string) string {
	if driver != "postgres" || dsn == "" {
		return dsn
	}
	if u, err := url.Parse(dsn); err == nil && u.User != nil {
		if _, hasPW := u.User.Password(); hasPW {
			u.User = url.User(u.User.Username())
			dsn = u.String()
		}
	}
	return dsnPasswordRe.ReplaceAllString(dsn, "password=***")
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.0f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func (s *Server) enabled(r *http.Request, b bool) string {
	if b {
		return s.t(r, "enabled")
	}
	return s.t(r, "disabled")
}

// handleAdminSystem renders a read-only view of the effective configuration
// (secrets redacted) plus live request diagnostics — most useful for
// working out client-IP resolution behind a reverse proxy.
func (s *Server) handleAdminSystem(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg
	https := strings.HasPrefix(cfg.BaseURL, "https://")

	secretKey := s.t(r, "not set")
	if n := len(cfg.SecretKey); n > 0 {
		secretKey = s.t(r, "set (%d characters)", n)
	}

	memLimit := s.t(r, "not set (no cgroup limit)")
	if lim := debug.SetMemoryLimit(-1); lim != math.MaxInt64 {
		memLimit = humanBytes(lim)
	}

	trusted := s.t(r, "none — X-Forwarded-For is ignored")
	if len(cfg.TrustedProxies) > 0 {
		trusted = strings.Join(cfg.TrustedProxies, ", ")
	}
	fwdDomains := s.t(r, "none")
	if len(cfg.ForwardAuth.Domains) > 0 {
		fwdDomains = strings.Join(cfg.ForwardAuth.Domains, ", ")
	}

	signing := cfg.OIDC.SigningAlgorithm
	if s.oidcStore != nil {
		signing = s.t(r, "%s (%d key(s) published)",
			s.oidcStore.ActiveSigningAlgorithm(), s.oidcStore.PublishedKeyCount())
	}

	config := []systemRow{
		{Label: msgid("Version"), Value: s.version, Mono: true},
		{Label: msgid("Listen address"), Value: cfg.Listen, Mono: true},
		{Label: msgid("Base URL (issuer)"), Value: cfg.BaseURL, Mono: true},
		{Label: msgid("Secret key"), Value: secretKey},
		{Label: msgid("Database"), Value: cfg.Database.Driver},
		{Label: msgid("Database DSN"), Value: redactDSN(cfg.Database.Driver, cfg.Database.DSN), Mono: true},
		{Label: msgid("OIDC signing"), Value: signing},
		{Label: msgid("Session lifetime"), Value: readableDurationIn(langOf(r), time.Duration(cfg.Session.Lifetime))},
		{Label: msgid("Session idle timeout"), Value: s.idleTimeout(r, time.Duration(cfg.Session.IdleTimeout))},
		{Label: msgid("Trusted proxies"), Value: trusted, Mono: len(cfg.TrustedProxies) > 0},
		{Label: msgid("Forward-auth domains"), Value: fwdDomains, Mono: len(cfg.ForwardAuth.Domains) > 0},
		{Label: msgid("Secure cookies"), Value: s.t(r, "%s (base URL is %s)", s.enabled(r, https), scheme(https))},
		{Label: msgid("HSTS header"), Value: s.enabled(r, https)},
		{Label: msgid("GOMEMLIMIT"), Value: memLimit},
		{Label: msgid("Log level"), Value: cfg.LogLevel},
	}

	// Request diagnostics: what this very request looks like to Kivraid.
	peer, ok := remoteAddr(r)
	peerStr := r.RemoteAddr
	verdict := s.t(r, "no trusted_proxies configured — header ignored, peer used as client IP")
	if ok {
		peerStr = peer.String()
		if len(s.trustedProxies) == 0 {
			// keep default verdict
		} else if proxyTrusted(s.trustedProxies, peer) {
			verdict = s.t(r, "trusted — X-Forwarded-For is honored")
		} else {
			verdict = s.t(r, "NOT trusted — add its range to trusted_proxies to honor X-Forwarded-For")
		}
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		xff = s.t(r, "(header absent)")
	}
	request := []systemRow{
		{Label: msgid("Direct peer (RemoteAddr)"), Value: peerStr, Mono: true},
		{Label: msgid("X-Forwarded-For (received)"), Value: xff, Mono: true},
		{Label: msgid("Peer trusted?"), Value: verdict},
		{Label: msgid("Resolved client IP"), Value: s.clientIP(r), Mono: true},
	}

	data := adminSystemData{Config: config, Request: request, KeyRotated: r.URL.Query().Get("rotated") == "1"}
	if s.oidcStore != nil {
		data.SigningAlg = s.oidcStore.ActiveSigningAlgorithm()
		data.PublishedKeys = s.oidcStore.PublishedKeyCount()
		data.CanRotate = true
		data.KeyCreated = s.oidcStore.SigningKeyCreated()
		if settings, err := s.store.GetInstanceSettings(r.Context()); err == nil && settings.KeyRotationDays > 0 {
			data.RotationDays = settings.KeyRotationDays
			data.NextRotation = data.KeyCreated.Add(time.Duration(settings.KeyRotationDays) * 24 * time.Hour)
		}
	}
	s.render(w, r, "admin_system.html", pageData{
		Title: "System", Active: "system", CSRF: s.csrfToken(r.Context()),
		User: currentUser(r), Data: data,
	})
}

// handleAdminSystemRotateKey generates a fresh signing key of the active
// algorithm and makes it the signer. The previous key stays published in the
// JWKS so tokens issued before the rotation keep verifying until they expire.
func (s *Server) handleAdminSystemRotateKey(w http.ResponseWriter, r *http.Request) {
	if s.oidcStore == nil {
		http.Redirect(w, r, "/admin/system", http.StatusSeeOther)
		return
	}
	if err := s.oidcStore.RotateSigningKey(r.Context()); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionKeyRotate, "",
		"alg="+s.oidcStore.ActiveSigningAlgorithm(), s.clientIP(r))
	s.log.Info("signing key rotated", "by", currentUser(r).Username)
	http.Redirect(w, r, "/admin/settings/system?rotated=1", http.StatusSeeOther)
}

func (s *Server) idleTimeout(r *http.Request, d time.Duration) string {
	if d == 0 {
		return s.t(r, "disabled")
	}
	return readableDurationIn(langOf(r), d)
}

// readableDuration renders a configured duration in English (see
// readableDurationIn).
func readableDuration(d time.Duration) string {
	return readableDurationIn(i18n.Default, d)
}

// readableDurationIn renders a configured duration as "7 days" or
// "30 minutes" in lang, falling back to Go's notation for sub-second
// precision.
func readableDurationIn(lang string, d time.Duration) string {
	if d <= 0 || d%time.Second != 0 {
		return d.String()
	}
	return humanDurationIn(lang, int64(d/time.Second))
}

func scheme(https bool) string {
	if https {
		return "https"
	}
	return "http"
}
