package web

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
)

// guardAuthorize renders a branded, actionable error for the two authorize
// failures op can only surface as a bare 400 (it cannot redirect back to an
// untrusted URI): an unknown client, or a redirect_uri that is not
// registered. Everything else is delegated to op unchanged.
func (s *Server) guardAuthorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		clientID, redirectURI := q.Get("client_id"), q.Get("redirect_uri")
		if clientID != "" && redirectURI != "" {
			if title, msg, bad := s.authorizeConfigError(r.Context(), clientID, redirectURI); bad {
				s.renderError(w, r, http.StatusBadRequest, title, msg)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// authorizeConfigError reports a client/redirect-URI misconfiguration that op
// would reject without being able to redirect. bad is false when the request
// looks fine (delegate to op) or on a transient error (let op decide).
func (s *Server) authorizeConfigError(ctx context.Context, clientID, redirectURI string) (title, message string, bad bool) {
	provider, err := s.store.GetProviderByClientID(ctx, clientID)
	if errors.Is(err, sql.ErrNoRows) {
		return "Unknown application",
			fmt.Sprintf("No application on this server is registered with the client ID %q. "+
				"Check the client ID in the application's OpenID Connect configuration.", clientID), true
	}
	if err != nil {
		return "", "", false // transient: let op handle it
	}
	if slices.Contains(decodeList(provider.RedirectUris), redirectURI) {
		return "", "", false // registered — fine
	}
	// Loopback/native clients get port-agnostic matching from op; don't
	// second-guess those here.
	if isLoopbackRedirect(redirectURI) {
		return "", "", false
	}
	name := clientID
	if app, err := s.store.GetApplication(ctx, provider.ApplicationID); err == nil && app.Name != "" {
		name = app.Name
	}
	return "Redirect URI not allowed",
		fmt.Sprintf("The redirect URI %q is not registered for %q. An administrator can allow it "+
			"under Admin → Applications → %s → Redirect URIs.", redirectURI, name, name), true
}

// isRegisteredPostLogout reports whether uri is a registered post-logout
// redirect URI for any provider. Used to give RP-initiated logout a friendly
// error instead of op's raw JSON; op still does the strict per-client check.
// On a lookup error it returns true (don't block — let op decide).
func (s *Server) isRegisteredPostLogout(ctx context.Context, uri string) bool {
	lists, err := s.store.ListPostLogoutRedirectURIs(ctx)
	if err != nil {
		return true
	}
	for _, raw := range lists {
		if slices.Contains(decodeList(raw), uri) {
			return true
		}
	}
	return false
}

// isLoopbackRedirect reports whether the redirect URI targets the local
// machine, where op applies relaxed (port-agnostic) matching for native apps.
func isLoopbackRedirect(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	switch u.Hostname() {
	case "127.0.0.1", "::1", "localhost":
		return true
	}
	return false
}
