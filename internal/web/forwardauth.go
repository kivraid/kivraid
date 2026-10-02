package web

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/kivraid/kivraid/internal/audit"
	"github.com/kivraid/kivraid/internal/session"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
)

// handleForwardAuth is the auth_request-style endpoint for reverse
// proxies (Traefik forwardAuth, nginx auth_request, Caddy forward_auth).
// Authenticated requests get 200 plus identity headers the proxy can
// copy upstream; anonymous browser requests are redirected to the login
// page when the target host is allowlisted, 401 otherwise. When a proxy
// application is registered for the host, its group access policy is
// enforced (403 for members who fail it).
func (s *Server) handleForwardAuth(w http.ResponseWriter, r *http.Request) {
	userID := s.sessions.GetString(r.Context(), session.KeyUserID)
	if userID == "" {
		s.forwardAuthDeny(w, r)
		return
	}
	user, err := s.store.GetUserByID(r.Context(), userID)
	if err != nil || !user.Active {
		s.forwardAuthDeny(w, r)
		return
	}
	// A password set by an administrator must be replaced before reaching
	// protected applications too, not only Kivraid's own pages.
	if user.MustChangePassword && s.sessions.GetString(r.Context(), session.KeyImpersonatorName) == "" {
		s.forwardAuthRedirect(w, r, passwordChangePath)
		return
	}

	// If a proxy application is registered for the requested host, enforce
	// its group access policy (an unrestricted app admits any authenticated user).
	if app, matched, err := s.matchProxyApp(r.Context(), r.Header.Get("X-Forwarded-Host")); err != nil {
		s.serverError(w, r, err)
		return
	} else if matched {
		allowed, err := s.userCanAccessApp(r.Context(), app, user.ID)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		if !allowed {
			s.audit.Record(r.Context(), user.Username, audit.ActionOIDCDeny, app.Slug, "forward-auth", s.clientIP(r))
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if app.RequireMfa && !s.sessionHasSecondFactor(r.Context()) &&
			s.sessions.GetString(r.Context(), session.KeyImpersonatorName) == "" {
			s.forwardAuthRedirect(w, r, mfaRequiredPath)
			return
		}
	}

	groups, err := s.store.ListUserGroups(r.Context(), user.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	names := make([]string, len(groups))
	for i, g := range groups {
		names[i] = g.Name
	}
	h := w.Header()
	h.Set("Remote-User", user.Username)
	h.Set("Remote-Email", user.Email)
	h.Set("Remote-Name", user.Name)
	h.Set("Remote-Groups", strings.Join(names, ","))
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (s *Server) forwardAuthDeny(w http.ResponseWriter, r *http.Request) {
	s.forwardAuthRedirect(w, r, "/login")
}

// forwardAuthRedirect sends a browser request for an allowlisted host to a
// Kivraid page (login, password change) that returns it to the original URL
// afterwards; anything else gets a bare 401.
func (s *Server) forwardAuthRedirect(w http.ResponseWriter, r *http.Request, path string) {
	host := r.Header.Get("X-Forwarded-Host")
	if host != "" && s.forwardHostAllowed(host) {
		proto := r.Header.Get("X-Forwarded-Proto")
		if proto == "" {
			proto = "https"
		}
		original := proto + "://" + host + r.Header.Get("X-Forwarded-Uri")
		http.Redirect(w, r, s.issuer()+path+"?next="+url.QueryEscape(original), http.StatusFound)
		return
	}
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

// normalizeHost lowercases host and strips any port.
func normalizeHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(host)
}

// forwardHostAllowed reports whether host may be a post-login redirect
// target: it must match a configured forward-auth domain (".suffix"
// entries match subdomains and the bare domain; others match exactly) or
// a registered proxy application's host.
func (s *Server) forwardHostAllowed(host string) bool {
	hostname := normalizeHost(host)
	for _, d := range s.cfg.ForwardAuth.Domains {
		d = strings.ToLower(d)
		if strings.HasPrefix(d, ".") {
			if hostname == d[1:] || strings.HasSuffix(hostname, d) {
				return true
			}
		} else if hostname == d {
			return true
		}
	}
	if _, matched, err := s.matchProxyApp(context.Background(), host); err == nil && matched {
		return true
	}
	return false
}

// matchProxyApp returns the proxy application registered for host, if any.
func (s *Server) matchProxyApp(ctx context.Context, host string) (sqlcgen.Application, bool, error) {
	hostname := normalizeHost(host)
	if hostname == "" {
		return sqlcgen.Application{}, false, nil
	}
	apps, err := s.store.ListProxyApplications(ctx)
	if err != nil {
		return sqlcgen.Application{}, false, err
	}
	for _, app := range apps {
		for _, h := range decodeList(app.ProxyHosts) {
			if normalizeHost(h) == hostname {
				return app, true, nil
			}
		}
	}
	return sqlcgen.Application{}, false, nil
}

// safeNext returns next when it is a same-site path or an absolute URL
// on an allowlisted forward-auth domain, otherwise the fallback.
func (s *Server) safeNext(next, fallback string) string {
	if isLocalPath(next) {
		return next
	}
	if u, err := url.Parse(next); err == nil &&
		(u.Scheme == "http" || u.Scheme == "https") && u.Host != "" &&
		s.forwardHostAllowed(u.Host) {
		return next
	}
	return fallback
}
