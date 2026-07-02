// Package oidcserver implements the OpenID Connect provider on top of the
// SQLite store, using zitadel/oidc's op framework for protocol handling.
package oidcserver

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/lporcheron/kivraid/internal/store"
	"github.com/lporcheron/kivraid/internal/store/sqlcgen"
)

const (
	// authRequestTTL bounds how long a login flow may take before the
	// pending authorization request is garbage-collected.
	authRequestTTL = time.Hour

	ScopeGroups = "groups"
)

type Storage struct {
	store *store.Store
	key   *signingKey
}

var _ op.Storage = (*Storage)(nil)
var _ op.CanSetUserinfoFromRequest = (*Storage)(nil)

func NewStorage(ctx context.Context, st *store.Store, sealKey [32]byte) (*Storage, error) {
	key, err := loadOrCreateSigningKey(ctx, st, sealKey)
	if err != nil {
		return nil, fmt.Errorf("signing key: %w", err)
	}
	return &Storage{store: st, key: key}, nil
}

func notFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return oidc.ErrInvalidRequest().WithDescription("not found")
	}
	return err
}

// --- Auth requests -------------------------------------------------------

func (s *Storage) CreateAuthRequest(ctx context.Context, r *oidc.AuthRequest, userID string) (op.AuthRequest, error) {
	now := time.Now().UTC()
	// Opportunistic cleanup keeps the table from growing without a
	// dedicated background job.
	_ = s.store.DeleteExpiredAuthRequests(ctx, now.Add(-authRequestTTL))

	req := newAuthRequest(uuid.NewString(), r, now)
	if userID != "" {
		req.UserID = userID
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if err := s.store.CreateAuthRequest(ctx, sqlcgen.CreateAuthRequestParams{
		ID: req.ID, Request: string(raw), CreatedAt: now,
	}); err != nil {
		return nil, err
	}
	return req, nil
}

func (s *Storage) authRequestFromRow(row sqlcgen.AuthRequest) (*authRequest, error) {
	var req authRequest
	if err := json.Unmarshal([]byte(row.Request), &req); err != nil {
		return nil, err
	}
	if time.Since(req.CreatedAt) > authRequestTTL {
		return nil, oidc.ErrInvalidRequest().WithDescription("authorization request expired")
	}
	return &req, nil
}

func (s *Storage) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	row, err := s.store.GetAuthRequestByID(ctx, id)
	if err != nil {
		return nil, notFound(err)
	}
	return s.authRequestFromRow(row)
}

func (s *Storage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	row, err := s.store.GetAuthRequestByCode(ctx, &code)
	if err != nil {
		return nil, notFound(err)
	}
	return s.authRequestFromRow(row)
}

func (s *Storage) SaveAuthCode(ctx context.Context, id string, code string) error {
	return s.store.SetAuthRequestCode(ctx, sqlcgen.SetAuthRequestCodeParams{Code: &code, ID: id})
}

func (s *Storage) DeleteAuthRequest(ctx context.Context, id string) error {
	return s.store.DeleteAuthRequest(ctx, id)
}

// ClientIDForAuthRequest returns the client a pending authorization
// request belongs to, so the web layer can enforce access policies
// before completing it.
func (s *Storage) ClientIDForAuthRequest(ctx context.Context, id string) (string, error) {
	row, err := s.store.GetAuthRequestByID(ctx, id)
	if err != nil {
		return "", notFound(err)
	}
	req, err := s.authRequestFromRow(row)
	if err != nil {
		return "", err
	}
	return req.ClientID, nil
}

// CompleteAuthRequest binds the authenticated user to a pending
// authorization request. Called by the web layer after login.
func (s *Storage) CompleteAuthRequest(ctx context.Context, id, userID string) error {
	row, err := s.store.GetAuthRequestByID(ctx, id)
	if err != nil {
		return notFound(err)
	}
	req, err := s.authRequestFromRow(row)
	if err != nil {
		return err
	}
	req.UserID = userID
	req.AuthTime = time.Now().UTC()
	req.IsDone = true
	raw, err := json.Marshal(req)
	if err != nil {
		return err
	}
	return s.store.UpdateAuthRequest(ctx, sqlcgen.UpdateAuthRequestParams{Request: string(raw), ID: id})
}

// --- Tokens --------------------------------------------------------------

func clientIDFromRequest(req op.TokenRequest) string {
	if r, ok := req.(interface{ GetClientID() string }); ok {
		return r.GetClientID()
	}
	if aud := req.GetAudience(); len(aud) > 0 {
		return aud[0]
	}
	return ""
}

func encodeJSONList(items []string) string {
	if items == nil {
		items = []string{}
	}
	raw, _ := json.Marshal(items)
	return string(raw)
}

func (s *Storage) CreateAccessToken(ctx context.Context, req op.TokenRequest) (string, time.Time, error) {
	clientID := clientIDFromRequest(req)
	id, exp, err := s.insertAccessToken(ctx, req, clientID, nil)
	return id, exp, err
}

func (s *Storage) insertAccessToken(ctx context.Context, req op.TokenRequest, clientID string, refreshTokenID *string) (string, time.Time, error) {
	provider, err := s.store.GetProviderByClientID(ctx, clientID)
	if err != nil {
		return "", time.Time{}, notFound(err)
	}
	now := time.Now().UTC()
	exp := now.Add(time.Duration(provider.AccessTokenTtlSeconds) * time.Second)
	id := uuid.NewString()
	err = s.store.CreateAccessToken(ctx, sqlcgen.CreateAccessTokenParams{
		ID:             id,
		UserID:         req.GetSubject(),
		ClientID:       clientID,
		Scopes:         encodeJSONList(req.GetScopes()),
		Audience:       encodeJSONList(req.GetAudience()),
		RefreshTokenID: refreshTokenID,
		ExpiresAt:      exp,
		CreatedAt:      now,
	})
	if err != nil {
		return "", time.Time{}, err
	}
	return id, exp, nil
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (s *Storage) CreateAccessAndRefreshTokens(ctx context.Context, req op.TokenRequest, currentRefreshToken string) (string, string, time.Time, error) {
	clientID := clientIDFromRequest(req)
	now := time.Now().UTC()

	authTime := now
	amr := []string{"pwd"}
	if r, ok := req.(interface{ GetAuthTime() time.Time }); ok && !r.GetAuthTime().IsZero() {
		authTime = r.GetAuthTime().UTC()
	}
	if r, ok := req.(interface{ GetAMR() []string }); ok && r.GetAMR() != nil {
		amr = r.GetAMR()
	}

	// Refresh token rotation: the presented token (and the access tokens
	// minted from it) die with the exchange.
	if currentRefreshToken != "" {
		oldID := HashToken(currentRefreshToken)
		if err := s.store.DeleteAccessTokensByRefreshToken(ctx, &oldID); err != nil {
			return "", "", time.Time{}, err
		}
		if err := s.store.DeleteRefreshToken(ctx, oldID); err != nil {
			return "", "", time.Time{}, err
		}
	}

	provider, err := s.store.GetProviderByClientID(ctx, clientID)
	if err != nil {
		return "", "", time.Time{}, notFound(err)
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", time.Time{}, err
	}
	refreshValue := hex.EncodeToString(raw)
	refreshID := HashToken(refreshValue)

	if err := s.store.CreateRefreshToken(ctx, sqlcgen.CreateRefreshTokenParams{
		ID:        refreshID,
		UserID:    req.GetSubject(),
		ClientID:  clientID,
		Scopes:    encodeJSONList(req.GetScopes()),
		Audience:  encodeJSONList(req.GetAudience()),
		Amr:       encodeJSONList(amr),
		AuthTime:  authTime,
		ExpiresAt: now.Add(time.Duration(provider.RefreshTokenTtlSeconds) * time.Second),
		CreatedAt: now,
	}); err != nil {
		return "", "", time.Time{}, err
	}

	accessID, exp, err := s.insertAccessToken(ctx, req, clientID, &refreshID)
	if err != nil {
		return "", "", time.Time{}, err
	}
	return accessID, refreshValue, exp, nil
}

// refreshTokenRequest adapts a refresh_tokens row to op.RefreshTokenRequest.
type refreshTokenRequest struct {
	row    sqlcgen.RefreshToken
	scopes []string
}

func (r *refreshTokenRequest) GetAMR() []string            { return decodeJSONList(r.row.Amr) }
func (r *refreshTokenRequest) GetAudience() []string       { return decodeJSONList(r.row.Audience) }
func (r *refreshTokenRequest) GetAuthTime() time.Time      { return r.row.AuthTime }
func (r *refreshTokenRequest) GetClientID() string         { return r.row.ClientID }
func (r *refreshTokenRequest) GetScopes() []string         { return r.scopes }
func (r *refreshTokenRequest) GetSubject() string          { return r.row.UserID }
func (r *refreshTokenRequest) SetCurrentScopes(s []string) { r.scopes = s }

func (s *Storage) TokenRequestByRefreshToken(ctx context.Context, refreshToken string) (op.RefreshTokenRequest, error) {
	row, err := s.store.GetRefreshToken(ctx, HashToken(refreshToken))
	if err != nil || time.Now().UTC().After(row.ExpiresAt) {
		return nil, op.ErrInvalidRefreshToken
	}
	return &refreshTokenRequest{row: row, scopes: decodeJSONList(row.Scopes)}, nil
}

func (s *Storage) GetRefreshTokenInfo(ctx context.Context, clientID string, token string) (string, string, error) {
	row, err := s.store.GetRefreshToken(ctx, HashToken(token))
	if err != nil || row.ClientID != clientID {
		return "", "", op.ErrInvalidRefreshToken
	}
	return row.UserID, row.ID, nil
}

func (s *Storage) TerminateSession(ctx context.Context, userID string, clientID string) error {
	if err := s.store.DeleteAccessTokensByUserClient(ctx, sqlcgen.DeleteAccessTokensByUserClientParams{
		UserID: userID, ClientID: clientID,
	}); err != nil {
		return err
	}
	return s.store.DeleteRefreshTokensByUserClient(ctx, sqlcgen.DeleteRefreshTokensByUserClientParams{
		UserID: userID, ClientID: clientID,
	})
}

func (s *Storage) RevokeToken(ctx context.Context, tokenOrTokenID string, userID string, clientID string) *oidc.Error {
	if userID != "" {
		// Access token: tokenOrTokenID is the token ID.
		row, err := s.store.GetAccessToken(ctx, tokenOrTokenID)
		if errors.Is(err, sql.ErrNoRows) {
			return nil // already gone: revocation is idempotent
		}
		if err != nil {
			return oidc.ErrServerError().WithParent(err)
		}
		if row.ClientID != clientID {
			return oidc.ErrInvalidClient().WithDescription("token was not issued for this client")
		}
		if err := s.store.DeleteAccessToken(ctx, tokenOrTokenID); err != nil {
			return oidc.ErrServerError().WithParent(err)
		}
		return nil
	}

	// Refresh token: tokenOrTokenID is the raw token value.
	id := HashToken(tokenOrTokenID)
	row, err := s.store.GetRefreshToken(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return oidc.ErrServerError().WithParent(err)
	}
	if row.ClientID != clientID {
		return oidc.ErrInvalidClient().WithDescription("token was not issued for this client")
	}
	if err := s.store.DeleteAccessTokensByRefreshToken(ctx, &id); err != nil {
		return oidc.ErrServerError().WithParent(err)
	}
	if err := s.store.DeleteRefreshToken(ctx, id); err != nil {
		return oidc.ErrServerError().WithParent(err)
	}
	return nil
}

// --- Signing keys --------------------------------------------------------

func (s *Storage) SigningKey(context.Context) (op.SigningKey, error) {
	return s.key, nil
}

func (s *Storage) SignatureAlgorithms(context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{s.key.alg}, nil
}

func (s *Storage) KeySet(context.Context) ([]op.Key, error) {
	return []op.Key{publicKey{s.key}}, nil
}

// --- Clients & userinfo --------------------------------------------------

func (s *Storage) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	provider, err := s.store.GetProviderByClientID(ctx, clientID)
	if err != nil {
		return nil, notFound(err)
	}
	return client{p: provider}, nil
}

func (s *Storage) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	provider, err := s.store.GetProviderByClientID(ctx, clientID)
	if err != nil {
		return notFound(err)
	}
	if provider.ClientSecretHash == nil {
		return oidc.ErrInvalidClient().WithDescription("client has no secret")
	}
	// Client secrets are 256-bit random values, so a fast hash comparison
	// is safe (unlike user passwords).
	if subtle.ConstantTimeCompare([]byte(HashToken(clientSecret)), []byte(*provider.ClientSecretHash)) != 1 {
		return oidc.ErrInvalidClient().WithDescription("invalid client secret")
	}
	return nil
}

func (s *Storage) setUserinfo(ctx context.Context, ui *oidc.UserInfo, userID string, scopes []string) error {
	user, err := s.store.GetUserByID(ctx, userID)
	if err != nil {
		return notFound(err)
	}
	for _, scope := range scopes {
		switch scope {
		case oidc.ScopeOpenID:
			ui.Subject = user.ID
		case oidc.ScopeProfile:
			ui.Name = user.Name
			ui.PreferredUsername = user.Username
			ui.UpdatedAt = oidc.FromTime(user.UpdatedAt)
		case oidc.ScopeEmail:
			ui.Email = user.Email
			ui.EmailVerified = true
		case ScopeGroups:
			groups, err := s.store.ListUserGroups(ctx, user.ID)
			if err != nil {
				return err
			}
			names := make([]string, len(groups))
			for i, g := range groups {
				names[i] = g.Name
			}
			ui.AppendClaims(ScopeGroups, names)
		}
	}
	return nil
}

// SetUserinfoFromScopes is deprecated in op; SetUserinfoFromRequest is the
// implementation that matters.
func (s *Storage) SetUserinfoFromScopes(ctx context.Context, ui *oidc.UserInfo, userID, clientID string, scopes []string) error {
	return nil
}

func (s *Storage) SetUserinfoFromRequest(ctx context.Context, ui *oidc.UserInfo, req op.IDTokenRequest, scopes []string) error {
	return s.setUserinfo(ctx, ui, req.GetSubject(), scopes)
}

func (s *Storage) SetUserinfoFromToken(ctx context.Context, ui *oidc.UserInfo, tokenID, subject, origin string) error {
	token, err := s.store.GetAccessToken(ctx, tokenID)
	if err != nil {
		return notFound(err)
	}
	if time.Now().UTC().After(token.ExpiresAt) {
		return oidc.ErrInvalidRequest().WithDescription("token expired")
	}
	return s.setUserinfo(ctx, ui, token.UserID, decodeJSONList(token.Scopes))
}

func (s *Storage) SetIntrospectionFromToken(ctx context.Context, resp *oidc.IntrospectionResponse, tokenID, subject, clientID string) error {
	token, err := s.store.GetAccessToken(ctx, tokenID)
	if err != nil {
		return notFound(err)
	}
	if time.Now().UTC().After(token.ExpiresAt) {
		return nil // Active stays false
	}
	// Only the audience may introspect a token.
	if !slices.Contains(decodeJSONList(token.Audience), clientID) && token.ClientID != clientID {
		return oidc.ErrInvalidClient().WithDescription("token was not issued for this client")
	}
	ui := new(oidc.UserInfo)
	if err := s.setUserinfo(ctx, ui, token.UserID, decodeJSONList(token.Scopes)); err != nil {
		return err
	}
	resp.SetUserInfo(ui)
	resp.Active = true
	resp.Scope = decodeJSONList(token.Scopes)
	resp.ClientID = token.ClientID
	resp.TokenType = oidc.BearerToken
	resp.Expiration = oidc.FromTime(token.ExpiresAt)
	resp.IssuedAt = oidc.FromTime(token.CreatedAt)
	resp.Audience = decodeJSONList(token.Audience)
	return nil
}

func (s *Storage) GetPrivateClaimsFromScopes(ctx context.Context, userID, clientID string, scopes []string) (map[string]any, error) {
	if !slices.Contains(scopes, ScopeGroups) {
		return nil, nil
	}
	groups, err := s.store.ListUserGroups(ctx, userID)
	if err != nil {
		return nil, err
	}
	names := make([]string, len(groups))
	for i, g := range groups {
		names[i] = g.Name
	}
	return map[string]any{ScopeGroups: names}, nil
}

func (s *Storage) GetKeyByIDAndClientID(ctx context.Context, keyID, clientID string) (*jose.JSONWebKey, error) {
	return nil, errors.New("private_key_jwt is not supported")
}

func (s *Storage) ValidateJWTProfileScopes(ctx context.Context, userID string, scopes []string) ([]string, error) {
	return nil, errors.New("JWT profile grant is not supported")
}

func (s *Storage) Health(ctx context.Context) error {
	return s.store.DB.PingContext(ctx)
}

// CleanupExpired removes expired tokens; called periodically by the server.
func (s *Storage) CleanupExpired(ctx context.Context) error {
	now := time.Now().UTC()
	if err := s.store.DeleteExpiredAccessTokens(ctx, now); err != nil {
		return err
	}
	if err := s.store.DeleteExpiredRefreshTokens(ctx, now); err != nil {
		return err
	}
	return s.store.DeleteExpiredAuthRequests(ctx, now.Add(-authRequestTTL))
}
