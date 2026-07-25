package oidcserver

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/kivraid/kivraid/internal/config"
	"github.com/kivraid/kivraid/internal/secrets"
	"github.com/kivraid/kivraid/internal/store"
)

// signingAlgorithm maps the configured algorithm name to its jose value.
// The config layer already restricts the input to es256/rs256; this stays
// defensive.
func signingAlgorithm(s string) (jose.SignatureAlgorithm, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "es256":
		return jose.ES256, nil
	case "rs256":
		return jose.RS256, nil
	default:
		return "", fmt.Errorf("unsupported oidc signing algorithm %q (want \"es256\" or \"rs256\")", s)
	}
}

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
	alg, err := signingAlgorithm(cfg.OIDC.SigningAlgorithm)
	if err != nil {
		return nil, nil, err
	}
	storage, err := NewStorage(ctx, st,
		secrets.DeriveKey(cfg.SecretKey, "signing-keys"),
		secrets.DeriveKey(cfg.SecretKey, "client-secrets"),
		strings.TrimSuffix(cfg.BaseURL, "/"), alg)
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
			"name", "preferred_username", "picture", "email", "email_verified", "updated_at",
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
