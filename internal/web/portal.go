package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/kivraid/kivraid/internal/audit"
	"github.com/kivraid/kivraid/internal/i18n"
	"github.com/kivraid/kivraid/internal/session"
	"github.com/kivraid/kivraid/internal/sources/ldap"
	"github.com/kivraid/kivraid/internal/sources/local"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
)

type homeData struct {
	Apps []sqlcgen.Application
}

// handleHome renders the application launcher: applications the user may
// access that have a launch URL.
func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	apps, err := s.store.ListLaunchableApplications(r.Context(), user.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, "home.html", pageData{
		Title: "Home", Active: "home", CSRF: s.csrfToken(r.Context()),
		User: user, Data: homeData{Apps: apps},
	})
}

// --- Password change ------------------------------------------------------

func (s *Server) canChangePassword(r *http.Request, user sqlcgen.User) bool {
	switch user.Source {
	case "local":
		return true
	case "ldap":
		if user.LdapSourceID == nil {
			return false
		}
		src, err := s.store.GetLdapSource(r.Context(), *user.LdapSourceID)
		return err == nil && src.PasswordWriteback
	}
	return false
}

func (s *Server) handleProfilePassword(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	current := r.PostFormValue("current_password")
	newPW := r.PostFormValue("new_password")
	confirm := r.PostFormValue("confirm_password")

	fail := func(msg string) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.renderProfile(w, r, user, msg, false)
	}

	if !s.canChangePassword(r, user) {
		fail(s.t(r, "Password changes are not available for this account."))
		return
	}
	if len(newPW) < 8 {
		fail(s.t(r, "The new password must be at least 8 characters."))
		return
	}
	if newPW != confirm {
		fail(s.t(r, "The new passwords do not match."))
		return
	}

	var err error
	switch user.Source {
	case "local":
		err = s.local.ChangePassword(r.Context(), user, current, newPW)
	case "ldap":
		if s.ldap == nil {
			fail(s.t(r, "Password changes are not available for this account."))
			return
		}
		err = s.ldap.ChangePassword(r.Context(), user, current, newPW)
	}
	switch {
	case errors.Is(err, local.ErrBadCredentials) || errors.Is(err, ldap.ErrBadCredentials):
		fail(s.t(r, "The current password is incorrect."))
		return
	case errors.Is(err, ldap.ErrWritebackDisabled):
		fail(s.t(r, "Password changes are disabled for your directory."))
		return
	case err != nil:
		s.log.Error("password change", "user", user.Username, "err", err)
		fail(s.t(r, "The directory refused the password change. Contact your administrator."))
		return
	}
	s.audit.Record(r.Context(), user.Username, audit.ActionPasswordChange, "", "source="+user.Source, s.clientIP(r))
	s.log.Info("password changed", "user", user.Username, "source", user.Source)
	http.Redirect(w, r, "/profile?pw=1", http.StatusSeeOther)
}

// --- Sessions --------------------------------------------------------------

type sessionInfo struct {
	TokenHash string
	Device    string
	IP        string
	LoginAt   time.Time
	Expiry    time.Time
	Current   bool
}

type sessionsData struct {
	Sessions []sessionInfo
	Others   int
	// Revoked flags the post-action flash: "1" (one session) or "others".
	Revoked string
}

// listUserSessions walks the session store and returns the current user's
// sessions, newest first.
func (s *Server) listUserSessions(r *http.Request, userID string) ([]sessionInfo, error) {
	currentToken := s.sessions.Token(r.Context())
	var out []sessionInfo
	err := s.sessions.Iterate(r.Context(), func(ctx context.Context) error {
		if s.sessions.GetString(ctx, session.KeyUserID) != userID {
			return nil
		}
		token := s.sessions.Token(ctx)
		hash := sha256.Sum256([]byte(token))
		out = append(out, sessionInfo{
			TokenHash: hex.EncodeToString(hash[:]),
			Device:    summarizeUA(langOf(r), s.sessions.GetString(ctx, session.KeyUserAgent)),
			IP:        s.sessions.GetString(ctx, session.KeyIP),
			LoginAt:   time.Unix(s.sessions.GetInt64(ctx, session.KeyLoginAt), 0).UTC(),
			Expiry:    s.sessions.Deadline(ctx).UTC(),
			Current:   token == currentToken,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LoginAt.After(out[j].LoginAt) })
	return out, nil
}

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	sessions, err := s.listUserSessions(r, user.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	others := 0
	for _, si := range sessions {
		if !si.Current {
			others++
		}
	}
	s.render(w, r, "sessions.html", pageData{
		Title: "Sessions", Active: "sessions", CSRF: s.csrfToken(r.Context()),
		User: user, Data: sessionsData{
			Sessions: sessions, Others: others,
			Revoked: r.URL.Query().Get("revoked"),
		},
	})
}

func (s *Server) handleSessionRevoke(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	target := r.PostFormValue("token_hash")
	err := s.sessions.Iterate(r.Context(), func(ctx context.Context) error {
		if s.sessions.GetString(ctx, session.KeyUserID) != user.ID {
			return nil
		}
		token := s.sessions.Token(ctx)
		hash := sha256.Sum256([]byte(token))
		if hex.EncodeToString(hash[:]) == target {
			return s.sessions.Store.Delete(token)
		}
		return nil
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit.Record(r.Context(), user.Username, audit.ActionSessionRevoke, "", "one session", s.clientIP(r))
	http.Redirect(w, r, "/sessions?revoked=1", http.StatusSeeOther)
}

func (s *Server) handleSessionsRevokeOthers(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	currentToken := s.sessions.Token(r.Context())
	err := s.sessions.Iterate(r.Context(), func(ctx context.Context) error {
		if s.sessions.GetString(ctx, session.KeyUserID) != user.ID {
			return nil
		}
		if token := s.sessions.Token(ctx); token != currentToken {
			return s.sessions.Store.Delete(token)
		}
		return nil
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit.Record(r.Context(), user.Username, audit.ActionSessionRevoke, "", "all other sessions", s.clientIP(r))
	http.Redirect(w, r, "/sessions?revoked=others", http.StatusSeeOther)
}

// summarizeUA turns a User-Agent header into a short human label in lang.
func summarizeUA(lang, ua string) string {
	if ua == "" {
		return i18n.T(lang, "Unknown device")
	}
	browser := i18n.T(lang, "Browser")
	switch {
	case strings.Contains(ua, "Firefox/"):
		browser = "Firefox"
	case strings.Contains(ua, "Edg/"):
		browser = "Edge"
	case strings.Contains(ua, "Chrome/"), strings.Contains(ua, "Chromium/"):
		browser = "Chrome"
	case strings.Contains(ua, "Safari/"):
		browser = "Safari"
	case strings.HasPrefix(ua, "curl/"):
		browser = "curl"
	}
	os := ""
	switch {
	case strings.Contains(ua, "iPhone"), strings.Contains(ua, "iPad"):
		os = "iOS"
	case strings.Contains(ua, "Android"):
		os = "Android"
	case strings.Contains(ua, "Mac OS X"), strings.Contains(ua, "Macintosh"):
		os = "macOS"
	case strings.Contains(ua, "Windows"):
		os = "Windows"
	case strings.Contains(ua, "Linux"):
		os = "Linux"
	}
	if os == "" {
		return browser
	}
	return browser + " · " + os
}

// clientIP returns the requester's IP for rate limiting and the audit
// log. X-Forwarded-For is only honored when the direct peer is a
// configured trusted proxy — the header is trivially spoofable
// otherwise. The chain is walked from the right, skipping trusted hops;
// the first untrusted address is the client.
func (s *Server) clientIP(r *http.Request) string {
	peer, ok := remoteAddr(r)
	if !ok {
		return r.RemoteAddr
	}
	if len(s.trustedProxies) > 0 && proxyTrusted(s.trustedProxies, peer) {
		parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
		for i := len(parts) - 1; i >= 0; i-- {
			a, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
			if err != nil {
				break
			}
			if !proxyTrusted(s.trustedProxies, a) {
				return a.String()
			}
		}
	}
	return peer.String()
}

func remoteAddr(r *http.Request) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, err := netip.ParseAddr(host)
	return a, err == nil
}

func proxyTrusted(prefixes []netip.Prefix, a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
