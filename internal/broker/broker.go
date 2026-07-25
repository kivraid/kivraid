// Package broker turns Kivraid into an OpenID Connect client (relying party)
// to upstream identity providers, so users can be federated from them. This
// file covers provider configuration helpers; the login ceremony lives
// alongside the web layer.
package broker

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/client"

	"github.com/lporcheron/kivraid/internal/secrets"
	"github.com/lporcheron/kivraid/internal/store"
)

type Manager struct {
	store   *store.Store
	sealKey [32]byte
	baseURL string // Kivraid's own base URL, for building redirect URIs
	http    *http.Client
}

func NewManager(st *store.Store, sealKey [32]byte, baseURL string) *Manager {
	return &Manager{
		store:   st,
		sealKey: sealKey,
		baseURL: strings.TrimSuffix(baseURL, "/"),
		http:    &http.Client{Timeout: 10 * time.Second},
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

// Discovery is a trimmed view of an upstream's OIDC metadata, enough to
// confirm a configuration in the admin.
type Discovery struct {
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string
	UserinfoEndpoint      string
}

// Discover fetches and validates the upstream's discovery document. It errors
// if the issuer is unreachable or the returned issuer does not match (a
// standard OIDC safeguard enforced by the client).
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
	}, nil
}
