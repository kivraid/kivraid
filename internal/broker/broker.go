// Package broker turns Kivraid into an OpenID Connect client (relying party)
// to upstream identity providers, so users can be federated from them.
package broker

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/client"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/kivraid/kivraid/internal/secrets"
	"github.com/kivraid/kivraid/internal/store"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
)

type Manager struct {
	store   *store.Store
	sealKey [32]byte
	baseURL string // Kivraid's own base URL, for building redirect URIs
	http    *http.Client
	cookies *httphelper.CookieHandler // signs/encrypts the OAuth state + PKCE cookies

	// rpCache memoizes relying parties (each does OIDC discovery to build), so
	// interactive logins don't re-discover every time. Keyed by provider id
	// and invalidated when the provider's updated_at changes.
	rpMu    sync.Mutex
	rpCache map[string]cachedRP
}

type cachedRP struct {
	rp        rp.RelyingParty
	updatedAt time.Time
}

// NewManager builds the broker. cookieHash/cookieEnc protect the short-lived
// state and PKCE cookies exchanged during a login ceremony.
func NewManager(st *store.Store, sealKey, cookieHash, cookieEnc [32]byte, baseURL string) *Manager {
	opts := []httphelper.CookieHandlerOpt{httphelper.WithMaxAge(600)}
	if !strings.HasPrefix(baseURL, "https://") {
		opts = append(opts, httphelper.WithUnsecure())
	}
	return &Manager{
		store:   st,
		sealKey: sealKey,
		baseURL: strings.TrimSuffix(baseURL, "/"),
		http:    &http.Client{Timeout: 10 * time.Second},
		cookies: httphelper.NewCookieHandler(cookieHash[:], cookieEnc[:], opts...),
		rpCache: map[string]cachedRP{},
	}
}

// SealSecret encrypts an upstream client secret for storage at rest.
func (m *Manager) SealSecret(secret string) ([]byte, error) {
	return secrets.Seal(m.sealKey, []byte(secret))
}

// RedirectURI is the callback URL the admin must register at the upstream
// provider for a given Kivraid provider id.
func (m *Manager) RedirectURI(providerID string) string {
	return m.baseURL + "/login/upstream/" + providerID + "/callback"
}

// Discovery is a trimmed view of an upstream's OIDC metadata.
type Discovery struct {
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string
	UserinfoEndpoint      string
	EndSessionEndpoint    string
}

// Discover fetches and validates the upstream's discovery document.
func (m *Manager) Discover(ctx context.Context, issuer string) (*Discovery, error) {
	cfg, err := client.Discover(ctx, strings.TrimSuffix(strings.TrimSpace(issuer), "/"), m.http)
	if err != nil {
		return nil, err
	}
	return &Discovery{
		Issuer:                cfg.Issuer,
		AuthorizationEndpoint: cfg.AuthorizationEndpoint,
		TokenEndpoint:         cfg.TokenEndpoint,
		UserinfoEndpoint:      cfg.UserinfoEndpoint,
		EndSessionEndpoint:    cfg.EndSessionEndpoint,
	}, nil
}

// LogoutURL builds the RP-initiated logout redirect to the upstream's
// end-session endpoint. Returns "" when the provider advertises no such
// endpoint (the caller then just ends the local session).
func (m *Manager) LogoutURL(ctx context.Context, p sqlcgen.UpstreamProvider, idToken, postLogoutRedirect string) (string, error) {
	d, err := m.Discover(ctx, p.Issuer)
	if err != nil {
		return "", err
	}
	if d.EndSessionEndpoint == "" {
		return "", nil
	}
	u, err := url.Parse(d.EndSessionEndpoint)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("id_token_hint", idToken)
	q.Set("client_id", p.ClientID)
	if postLogoutRedirect != "" {
		q.Set("post_logout_redirect_uri", postLogoutRedirect)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// relyingParty returns a memoized relying party for the provider, rebuilding
// (and re-running discovery) only when the provider's configuration changed.
func (m *Manager) relyingParty(ctx context.Context, p sqlcgen.UpstreamProvider) (rp.RelyingParty, error) {
	m.rpMu.Lock()
	if e, ok := m.rpCache[p.ID]; ok && e.updatedAt.Equal(p.UpdatedAt) {
		m.rpMu.Unlock()
		return e.rp, nil
	}
	m.rpMu.Unlock()

	// Build outside the lock (discovery is a network call); a rare duplicate
	// build under concurrent first-use is harmless.
	built, err := m.buildRelyingParty(ctx, p)
	if err != nil {
		return nil, err
	}
	m.rpMu.Lock()
	m.rpCache[p.ID] = cachedRP{rp: built, updatedAt: p.UpdatedAt}
	m.rpMu.Unlock()
	return built, nil
}

// buildRelyingParty constructs a fresh relying party (runs OIDC discovery).
func (m *Manager) buildRelyingParty(ctx context.Context, p sqlcgen.UpstreamProvider) (rp.RelyingParty, error) {
	secret := ""
	if len(p.ClientSecretEnc) > 0 {
		plain, err := secrets.Open(m.sealKey, p.ClientSecretEnc)
		if err != nil {
			return nil, err
		}
		secret = string(plain)
	}
	opts := []rp.Option{rp.WithHTTPClient(m.http), rp.WithCookieHandler(m.cookies)}
	// Public clients (no secret) rely on PKCE to protect the code exchange.
	if secret == "" {
		opts = append(opts, rp.WithPKCE(m.cookies))
	}
	return rp.NewRelyingPartyOIDC(ctx, p.Issuer, p.ClientID, secret,
		m.RedirectURI(p.ID), strings.Fields(p.Scopes), opts...)
}

// StartLogin redirects the browser to the provider's authorization endpoint,
// stashing state (and a PKCE verifier for public clients) in signed cookies.
func (m *Manager) StartLogin(w http.ResponseWriter, r *http.Request, p sqlcgen.UpstreamProvider) error {
	relyingParty, err := m.relyingParty(r.Context(), p)
	if err != nil {
		return err
	}
	rp.AuthURLHandler(func() string { return uuid.NewString() }, relyingParty).ServeHTTP(w, r)
	return nil
}

// Identity is the mapped result of a successful upstream login.
type Identity struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	Groups        []string
	IDToken       string // raw id_token, kept for RP-initiated logout
}

// HandleCallback completes the OAuth code exchange and returns the mapped
// identity. A (nil, nil) return means the ceremony already wrote an error
// response (e.g. bad state) and the caller should simply stop.
func (m *Manager) HandleCallback(w http.ResponseWriter, r *http.Request, p sqlcgen.UpstreamProvider) (*Identity, error) {
	relyingParty, err := m.relyingParty(r.Context(), p)
	if err != nil {
		return nil, err
	}
	var ident *Identity
	var cbErr error
	cb := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], _ string, relyingParty rp.RelyingParty) {
		ui, err := rp.Userinfo[*oidc.UserInfo](r.Context(), tokens.AccessToken, tokens.TokenType,
			tokens.IDTokenClaims.GetSubject(), relyingParty)
		if err != nil {
			cbErr = err
			return
		}
		ident = m.mapIdentity(p, ui)
		ident.IDToken = tokens.IDToken
	}
	rp.CodeExchangeHandler(cb, relyingParty).ServeHTTP(w, r)
	return ident, cbErr
}

// mapIdentity applies the provider's claim mapping to the userinfo response.
func (m *Manager) mapIdentity(p sqlcgen.UpstreamProvider, ui *oidc.UserInfo) *Identity {
	return &Identity{
		Subject:       ui.GetSubject(),
		Email:         strings.ToLower(strings.TrimSpace(claimString(ui, p.ClaimEmail))),
		EmailVerified: bool(ui.EmailVerified),
		Name:          claimString(ui, p.ClaimName),
		Groups:        claimStrings(ui, p.ClaimGroups),
	}
}

// claimStrings reads a string-list claim (groups), tolerating the several
// shapes IdPs use: a JSON array of strings, or a single string.
func claimStrings(ui *oidc.UserInfo, key string) []string {
	switch t := ui.Claims[key].(type) {
	case []string:
		return t
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// claimString reads a claim by name, preferring the standard typed fields and
// falling back to the extra-claims map for custom mappings.
func claimString(ui *oidc.UserInfo, key string) string {
	switch key {
	case "email":
		return ui.Email
	case "name":
		return ui.Name
	case "preferred_username":
		return ui.PreferredUsername
	case "given_name":
		return ui.GivenName
	case "family_name":
		return ui.FamilyName
	}
	if v, ok := ui.Claims[key].(string); ok {
		return v
	}
	return ""
}
