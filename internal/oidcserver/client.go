package oidcserver

import (
	"encoding/json"
	"net/url"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/lporcheron/kivraid/internal/store/sqlcgen"
)

// LoginPath builds the path clients are redirected to for authentication.
// After login, the web layer resumes the flow via /oidc/resume.
func LoginPath(authRequestID string) string {
	return "/login?next=" + url.QueryEscape("/oidc/resume?id="+authRequestID)
}

// client adapts a provider row to op.Client. Confidential clients use
// client_secret_basic (op also accepts the secret via POST body);
// public clients use PKCE.
type client struct {
	p sqlcgen.Provider
}

func decodeJSONList(s string) []string {
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil
	}
	return out
}

func (c client) GetID() string                    { return c.p.ClientID }
func (c client) RedirectURIs() []string           { return decodeJSONList(c.p.RedirectUris) }
func (c client) PostLogoutRedirectURIs() []string { return decodeJSONList(c.p.PostLogoutRedirectUris) }
func (c client) LoginURL(id string) string        { return LoginPath(id) }
func (c client) AccessTokenType() op.AccessTokenType {
	return op.AccessTokenTypeBearer
}

func (c client) ApplicationType() op.ApplicationType {
	if c.p.Public {
		// Native relaxes redirect URI rules to loopback + custom schemes,
		// which is what public (PKCE) clients need.
		return op.ApplicationTypeNative
	}
	return op.ApplicationTypeWeb
}

func (c client) AuthMethod() oidc.AuthMethod {
	if c.p.Public {
		return oidc.AuthMethodNone
	}
	return oidc.AuthMethodBasic
}

func (c client) ResponseTypes() []oidc.ResponseType {
	return []oidc.ResponseType{oidc.ResponseTypeCode}
}

func (c client) GrantTypes() []oidc.GrantType {
	return []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeRefreshToken}
}

func (c client) IDTokenLifetime() time.Duration {
	return time.Duration(c.p.IDTokenTtlSeconds) * time.Second
}

func (c client) DevMode() bool            { return false }
func (c client) ClockSkew() time.Duration { return 0 }

func (c client) RestrictAdditionalIdTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string { return scopes }
}

func (c client) RestrictAdditionalAccessTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string { return scopes }
}

func (c client) IsScopeAllowed(scope string) bool {
	return scope == "groups"
}

// IDTokenUserinfoClaimsAssertion mirrors Authentik's behaviour: profile and
// email claims are asserted directly in the id_token, so simple RPs work
// without calling the userinfo endpoint.
func (c client) IDTokenUserinfoClaimsAssertion() bool { return true }
