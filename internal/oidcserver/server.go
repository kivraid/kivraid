package oidcserver

import (
	"context"
	"log/slog"
	"net/url"
	"strings"

	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/lporcheron/kivraid/internal/config"
	"github.com/lporcheron/kivraid/internal/secrets"
	"github.com/lporcheron/kivraid/internal/store"
)

// ResumePath is where the web layer completes a pending authorization
// request after login; the op callback then issues the code.
const ResumePath = "/oidc/resume"

// CallbackPath returns the op-internal callback that finalizes an
// authorization request (default endpoints: /authorize/callback).
func CallbackPath(authRequestID string) string {
	return "/authorize/callback?id=" + url.QueryEscape(authRequestID)
}

// New builds the OIDC provider and its storage. The returned provider is
// an http.Handler covering discovery, authorize, token, userinfo, keys,
// revocation and end_session under the issuer root.
func New(ctx context.Context, cfg config.Config, st *store.Store, log *slog.Logger) (*op.Provider, *Storage, error) {
	storage, err := NewStorage(ctx, st, secrets.DeriveKey(cfg.SecretKey, "signing-keys"))
	if err != nil {
		return nil, nil, err
	}

	opConfig := &op.Config{
		CryptoKey:                secrets.DeriveKey(cfg.SecretKey, "access-token-crypto"),
		CodeMethodS256:           true,
		AuthMethodPost:           true,
		GrantTypeRefreshToken:    true,
		DefaultLogoutRedirectURI: "/login",
		SupportedScopes: []string{
			"openid", "profile", "email", "offline_access", ScopeGroups,
		},
		SupportedClaims: []string{
			"sub", "aud", "exp", "iat", "iss", "auth_time", "nonce", "acr", "amr",
			"name", "preferred_username", "email", "email_verified", "updated_at",
			ScopeGroups,
		},
	}

	opts := []op.Option{op.WithLogger(log)}
	if strings.HasPrefix(cfg.BaseURL, "http://") {
		// Development / behind-TLS-proxy setups; the issuer check requires
		// https otherwise.
		opts = append(opts, op.WithAllowInsecure())
	}

	provider, err := op.NewProvider(opConfig, storage, op.StaticIssuer(strings.TrimSuffix(cfg.BaseURL, "/")), opts...)
	if err != nil {
		return nil, nil, err
	}
	return provider, storage, nil
}

// Routes lists the mux patterns that must be dispatched to the provider.
func Routes() []string {
	return []string{
		"/.well-known/openid-configuration",
		"/authorize",
		"/authorize/",
		"/oauth/",
		"/userinfo",
		"/keys",
		"/revoke",
		"/end_session",
	}
}
