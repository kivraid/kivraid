package web

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
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
			if title, msg, bad := s.authorizeConfigError(r, clientID, redirectURI); bad {
				s.renderError(w, r, http.StatusBadRequest, title, msg)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// authorizeConfigError reports a client/redirect-URI misconfiguration that op
// would reject without being able to redirect. bad is false when the request
// looks fine (delegate to op) or on a transient error (let op decide). The
// title and message are in the request's language.
func (s *Server) authorizeConfigError(r *http.Request, clientID, redirectURI string) (title, message string, bad bool) {
	ctx := r.Context()
	provider, err := s.store.GetProviderByClientID(ctx, clientID)
	if errors.Is(err, sql.ErrNoRows) {
		return s.t(r, "Unknown application"),
			s.t(r, "No application on this server is registered with the client ID %q. Check the client ID in the application's OpenID Connect configuration.", clientID), true
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
	return s.t(r, "Redirect URI not allowed"),
		s.t(r, "The redirect URI %q is not registered for %q. An administrator can allow it under Admin → Applications → %s → Redirect URIs.", redirectURI, name, name), true
}

// endSessionClientID resolves the client an end_session request targets, the
// same way op does: the explicit client_id, else the azp of id_token_hint.
// The hint is decoded without verification — it only selects which client's
// list the guard checks; op still verifies the token itself.
func endSessionClientID(r *http.Request) string {
	if id := r.FormValue("client_id"); id != "" {
		return id
	}
	parts := strings.Split(r.FormValue("id_token_hint"), ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		AuthorizedParty string `json:"azp"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return ""
	}
	return claims.AuthorizedParty
}

// postLogoutConfigError reports a post_logout_redirect_uri that op would
// reject for this client with a raw JSON error. It mirrors op's per-client
// check; bad is false when op would accept it, when op ignores the URI (no
// client resolved), or on a lookup error (let op decide). The message is in
// the request's language.
func (s *Server) postLogoutConfigError(r *http.Request, clientID, uri string) (message string, bad bool) {
	ctx := r.Context()
	if clientID == "" {
		return "", false // op ignores post_logout_redirect_uri without a client
	}
	provider, err := s.store.GetProviderByClientID(ctx, clientID)
	if err != nil {
		return "", false
	}
	if slices.Contains(decodeList(provider.PostLogoutRedirectUris), uri) {
		return "", false
	}
	// Public (native) clients get port-agnostic loopback matching from op.
	if provider.Public && isLoopbackRedirect(uri) {
		return "", false
	}
	name := clientID
	if app, err := s.store.GetApplication(ctx, provider.ApplicationID); err == nil && app.Name != "" {
		name = app.Name
	}
	return s.t(r, "You are signed out. %q asked to return you to %q, which is not a registered post-logout redirect URI for it. An administrator can add it under Admin → Applications → %s → Post-logout redirect URIs.", name, uri, name), true
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
