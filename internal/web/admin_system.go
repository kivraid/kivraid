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
)

type systemRow struct {
	Label string
	Value string
	// Mono renders the value in a monospace box (URLs, IPs, DSNs).
	Mono bool
}

type adminSystemData struct {
	Config  []systemRow
	Request []systemRow
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

func enabled(b bool) string {
	if b {
		return "enabled"
	}
	return "disabled"
}

// handleAdminSystem renders a read-only view of the effective configuration
// (secrets redacted) plus live request diagnostics — most useful for
// working out client-IP resolution behind a reverse proxy.
func (s *Server) handleAdminSystem(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg
	https := strings.HasPrefix(cfg.BaseURL, "https://")

	secretKey := "not set"
	if n := len(cfg.SecretKey); n > 0 {
		secretKey = fmt.Sprintf("set (%d characters)", n)
	}

	memLimit := "not set (no cgroup limit)"
	if lim := debug.SetMemoryLimit(-1); lim != math.MaxInt64 {
		memLimit = humanBytes(lim)
	}

	trusted := "none — X-Forwarded-For is ignored"
	if len(cfg.TrustedProxies) > 0 {
		trusted = strings.Join(cfg.TrustedProxies, ", ")
	}
	fwdDomains := "none"
	if len(cfg.ForwardAuth.Domains) > 0 {
		fwdDomains = strings.Join(cfg.ForwardAuth.Domains, ", ")
	}

	signing := cfg.OIDC.SigningAlgorithm
	if s.oidcStore != nil {
		signing = fmt.Sprintf("%s (%d key(s) published)",
			s.oidcStore.ActiveSigningAlgorithm(), s.oidcStore.PublishedKeyCount())
	}

	config := []systemRow{
		{Label: "Version", Value: s.version, Mono: true},
		{Label: "Listen address", Value: cfg.Listen, Mono: true},
		{Label: "Base URL (issuer)", Value: cfg.BaseURL, Mono: true},
		{Label: "Secret key", Value: secretKey},
		{Label: "Database", Value: cfg.Database.Driver},
		{Label: "Database DSN", Value: redactDSN(cfg.Database.Driver, cfg.Database.DSN), Mono: true},
		{Label: "OIDC signing", Value: signing},
		{Label: "Session lifetime", Value: time.Duration(cfg.Session.Lifetime).String()},
		{Label: "Session idle timeout", Value: idleTimeout(time.Duration(cfg.Session.IdleTimeout))},
		{Label: "Trusted proxies", Value: trusted, Mono: len(cfg.TrustedProxies) > 0},
		{Label: "Forward-auth domains", Value: fwdDomains, Mono: len(cfg.ForwardAuth.Domains) > 0},
		{Label: "Secure cookies", Value: enabled(https) + " (base URL is " + scheme(https) + ")"},
		{Label: "HSTS header", Value: enabled(https)},
		{Label: "GOMEMLIMIT", Value: memLimit},
		{Label: "Log level", Value: cfg.LogLevel},
	}

	// Request diagnostics: what this very request looks like to Kivraid.
	peer, ok := remoteAddr(r)
	peerStr := r.RemoteAddr
	verdict := "no trusted_proxies configured — header ignored, peer used as client IP"
	if ok {
		peerStr = peer.String()
		if len(s.trustedProxies) == 0 {
			// keep default verdict
		} else if proxyTrusted(s.trustedProxies, peer) {
			verdict = "trusted — X-Forwarded-For is honored"
		} else {
			verdict = "NOT trusted — add its range to trusted_proxies to honor X-Forwarded-For"
		}
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		xff = "(header absent)"
	}
	request := []systemRow{
		{Label: "Direct peer (RemoteAddr)", Value: peerStr, Mono: true},
		{Label: "X-Forwarded-For (received)", Value: xff, Mono: true},
		{Label: "Peer trusted?", Value: verdict},
		{Label: "Resolved client IP", Value: s.clientIP(r), Mono: true},
	}

	s.render(w, r, "admin_system.html", pageData{
		Title: "System", Active: "system", CSRF: s.csrfToken(r.Context()),
		User: currentUser(r), Data: adminSystemData{Config: config, Request: request},
	})
}

func idleTimeout(d time.Duration) string {
	if d == 0 {
		return "disabled"
	}
	return d.String()
}

func scheme(https bool) string {
	if https {
		return "https"
	}
	return "http"
}
