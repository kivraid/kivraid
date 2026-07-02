package web

import (
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/lporcheron/kivraid/internal/session"
)

// handleForwardAuth is the auth_request-style endpoint for reverse
// proxies (Traefik forwardAuth, nginx auth_request, Caddy forward_auth).
// Authenticated requests get 200 plus identity headers the proxy can
// copy upstream; anonymous browser requests are redirected to the login
// page when the target host is allowlisted, 401 otherwise.
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
	host := r.Header.Get("X-Forwarded-Host")
	if host != "" && s.forwardHostAllowed(host) {
		proto := r.Header.Get("X-Forwarded-Proto")
		if proto == "" {
			proto = "https"
		}
		original := proto + "://" + host + r.Header.Get("X-Forwarded-Uri")
		http.Redirect(w, r, s.issuer()+"/login?next="+url.QueryEscape(original), http.StatusFound)
		return
	}
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

// forwardHostAllowed reports whether host matches the configured
// forward-auth domains (".suffix" entries match subdomains and the bare
// domain; others match exactly).
func (s *Server) forwardHostAllowed(host string) bool {
	hostname := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostname = h
	}
	hostname = strings.ToLower(hostname)
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
	return false
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
