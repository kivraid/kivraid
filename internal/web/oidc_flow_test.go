package web

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/lporcheron/kivraid/internal/config"
	"github.com/lporcheron/kivraid/internal/oidcserver"
	"github.com/lporcheron/kivraid/internal/session"
	"github.com/lporcheron/kivraid/internal/sources/local"
	"github.com/lporcheron/kivraid/internal/store"
	"github.com/lporcheron/kivraid/internal/store/sqlcgen"
	"github.com/lporcheron/kivraid/internal/store/storetest"
)

const (
	testClientID     = "it-client-id"
	testClientSecret = "it-client-secret-0123456789abcdef"
	testRedirectURI  = "http://127.0.0.1:1/callback" // never contacted; redirects are intercepted
)

// startIssuer runs a full Kivraid instance on a real port (the OIDC issuer
// must match the listen address) with one user and one confidential client.
func startIssuer(t *testing.T, public bool) (issuer string, st *store.Store) {
	t.Helper()
	ctx := context.Background()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	issuer = "http://" + l.Addr().String()

	st = storetest.Open(t)

	user, err := local.NewSource(st).CreateUser(ctx,
		"alice", "alice@example.com", "Alice Liddell", "s3cret-pass", false)
	if err != nil {
		t.Fatal(err)
	}
	// Group membership for the groups scope.
	if _, err := st.DB.Exec(`INSERT INTO groups (id, name, created_at) VALUES ('g1', 'infra', $1)`,
		time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB.Exec(`INSERT INTO user_groups (user_id, group_id) VALUES ($1, 'g1')`, user.ID); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	app, err := st.CreateApplication(ctx, sqlcgen.CreateApplicationParams{
		ID: "app1", Name: "IT App", Slug: "it-app", CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	secretHash := oidcserver.HashToken(testClientSecret)
	params := sqlcgen.CreateProviderParams{
		ID: "prov1", ApplicationID: app.ID, ClientID: testClientID,
		ClientSecretHash: &secretHash,
		RedirectUris:     `["` + testRedirectURI + `"]`, PostLogoutRedirectUris: `[]`,
		Public:                public,
		AccessTokenTtlSeconds: 300, RefreshTokenTtlSeconds: 3600, IDTokenTtlSeconds: 3600,
		CreatedAt: now, UpdatedAt: now,
	}
	if public {
		params.ClientSecretHash = nil
	}
	if _, err := st.CreateProvider(ctx, params); err != nil {
		t.Fatal(err)
	}

	cfg := config.Config{BaseURL: issuer, SecretKey: strings.Repeat("k", 32),
		Session: config.Session{Lifetime: config.Duration(7 * 24 * time.Hour)}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	provider, storage, err := oidcserver.New(ctx, cfg, st, log)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(Deps{
		Config: cfg, Store: st, Sessions: session.NewManager(st.DB, st.Driver, false,
			time.Duration(cfg.Session.Lifetime), time.Duration(cfg.Session.IdleTimeout)),
		OIDC: provider, OIDCStore: storage, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}

	httpSrv := &http.Server{Handler: srv.Handler()}
	go httpSrv.Serve(l)
	t.Cleanup(func() { httpSrv.Close() })
	return issuer, st
}

// browseAuthFlow drives the user-agent part of the flow: authorize →
// login → resume → callback, and returns the authorization code.
func browseAuthFlow(t *testing.T, authURL string) string {
	t.Helper()
	c := newClient(t)

	follow := func(u string) *http.Response {
		t.Helper()
		resp, err := c.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			t.Fatalf("GET %s: expected redirect, got %d", u, resp.StatusCode)
		}
		return resp
	}

	base, _ := url.Parse(authURL)
	abs := func(location string) string {
		u, err := base.Parse(location)
		if err != nil {
			t.Fatal(err)
		}
		return u.String()
	}

	// /authorize stores the request and bounces to the login page.
	resp := follow(authURL)
	loginURL := abs(resp.Header.Get("Location"))
	if !strings.Contains(loginURL, "/login?next=") {
		t.Fatalf("expected login redirect, got %s", loginURL)
	}

	// Log in, preserving the OIDC resume target.
	u, _ := url.Parse(loginURL)
	next := u.Query().Get("next")
	csrf := fetchCSRF(t, c, loginURL)
	postResp, err := c.PostForm(abs("/login"), url.Values{
		"_csrf": {csrf}, "username": {"alice"}, "password": {"s3cret-pass"}, "next": {next},
	})
	if err != nil {
		t.Fatal(err)
	}
	postResp.Body.Close()
	if postResp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login: want 303, got %d", postResp.StatusCode)
	}

	// resume → op callback → client redirect_uri with the code.
	resp = follow(abs(postResp.Header.Get("Location")))
	resp = follow(abs(resp.Header.Get("Location")))
	final, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(final.String(), testRedirectURI) {
		t.Fatalf("expected redirect to client, got %s", final)
	}
	if final.Query().Get("state") != "teststate" {
		t.Fatalf("state mismatch: %q", final.Query().Get("state"))
	}
	code := final.Query().Get("code")
	if code == "" {
		t.Fatalf("no authorization code in %s", final)
	}
	return code
}

func TestOIDCCodeFlowConfidential(t *testing.T) {
	issuer, _ := startIssuer(t, false)
	ctx := context.Background()

	relying, err := rp.NewRelyingPartyOIDC(ctx, issuer, testClientID, testClientSecret,
		testRedirectURI, []string{"openid", "profile", "email", "groups", "offline_access"})
	if err != nil {
		t.Fatalf("discovery failed: %v", err)
	}

	authURL := rp.AuthURL("teststate", relying)
	code := browseAuthFlow(t, authURL)

	tokens, err := rp.CodeExchange[*oidc.IDTokenClaims](ctx, code, relying)
	if err != nil {
		t.Fatalf("code exchange: %v", err)
	}
	if tokens.AccessToken == "" || tokens.IDToken == "" {
		t.Fatal("missing tokens")
	}
	if tokens.RefreshToken == "" {
		t.Fatal("offline_access requested but no refresh token issued")
	}

	claims := tokens.IDTokenClaims
	if claims.PreferredUsername != "alice" {
		t.Errorf("preferred_username: want alice, got %q", claims.PreferredUsername)
	}
	if claims.Email != "alice@example.com" {
		t.Errorf("email claim: got %q", claims.Email)
	}

	// userinfo endpoint with the opaque access token.
	info, err := rp.Userinfo[*oidc.UserInfo](ctx, tokens.AccessToken, oidc.BearerToken, claims.Subject, relying)
	if err != nil {
		t.Fatalf("userinfo: %v", err)
	}
	if info.Name != "Alice Liddell" || info.Email != "alice@example.com" {
		t.Errorf("userinfo mismatch: %+v", info)
	}
	groups, _ := info.Claims["groups"].([]any)
	if len(groups) != 1 || groups[0] != "infra" {
		t.Errorf("groups claim: got %v", info.Claims["groups"])
	}

	// Refresh rotation: new tokens are issued, the old refresh token dies.
	oldRefresh := tokens.RefreshToken
	refreshed, err := rp.RefreshTokens[*oidc.IDTokenClaims](ctx, relying, oldRefresh, "", "")
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if refreshed.AccessToken == "" || refreshed.RefreshToken == "" || refreshed.RefreshToken == oldRefresh {
		t.Fatal("expected rotated refresh token")
	}
	if _, err := rp.RefreshTokens[*oidc.IDTokenClaims](ctx, relying, oldRefresh, "", ""); err == nil {
		t.Fatal("reusing a rotated refresh token must fail")
	}
}

func TestOIDCAccessPolicyDenied(t *testing.T) {
	issuer, st := startIssuer(t, false)

	// Bind the application to a group alice is not a member of.
	if _, err := st.DB.Exec(`INSERT INTO groups (id, name, created_at) VALUES ('g2', 'admins', $1)`,
		time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB.Exec(`INSERT INTO app_policies (application_id, group_id) VALUES ('app1', 'g2')`); err != nil {
		t.Fatal(err)
	}

	authURL := issuer + "/authorize?" + url.Values{
		"client_id":     {testClientID},
		"redirect_uri":  {testRedirectURI},
		"response_type": {"code"},
		"scope":         {"openid"},
		"state":         {"teststate"},
	}.Encode()

	c := newClient(t)
	resp, err := c.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loginLoc := resp.Header.Get("Location")
	u, _ := url.Parse(issuer + loginLoc)
	next := u.Query().Get("next")

	csrf := fetchCSRF(t, c, issuer+loginLoc)
	resp, err = c.PostForm(issuer+"/login", url.Values{
		"_csrf": {csrf}, "username": {"alice"}, "password": {"s3cret-pass"}, "next": {next},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// The resume step must refuse to complete the authorization.
	resp, err = c.Get(issuer + resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403, got %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "No access to IT App") {
		t.Fatal("denied page missing application name")
	}
}

func TestOIDCCodeFlowPublicPKCE(t *testing.T) {
	issuer, _ := startIssuer(t, true)

	verifierRaw := make([]byte, 32)
	rand.Read(verifierRaw)
	verifier := base64.RawURLEncoding.EncodeToString(verifierRaw)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	authURL := issuer + "/authorize?" + url.Values{
		"client_id":             {testClientID},
		"redirect_uri":          {testRedirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid profile email"},
		"state":                 {"teststate"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}.Encode()

	code := browseAuthFlow(t, authURL)

	// Public client: token exchange with the verifier, no secret.
	resp, err := http.PostForm(issuer+"/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {testRedirectURI},
		"client_id":     {testClientID},
		"code_verifier": {verifier},
	})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token endpoint: %d: %s", resp.StatusCode, body)
	}
	var tokens struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(body, &tokens); err != nil {
		t.Fatal(err)
	}
	if tokens.AccessToken == "" || tokens.IDToken == "" {
		t.Fatalf("missing tokens in %s", body)
	}

	// Wrong verifier must be rejected.
	authURL2 := strings.Replace(authURL, "teststate", "teststate", 1)
	code2 := browseAuthFlow(t, authURL2)
	resp2, err := http.PostForm(issuer+"/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code2},
		"redirect_uri":  {testRedirectURI},
		"client_id":     {testClientID},
		"code_verifier": {"wrong-" + hex.EncodeToString(verifierRaw)},
	})
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode == http.StatusOK {
		t.Fatal("token exchange with wrong PKCE verifier must fail")
	}
}
