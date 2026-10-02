package web

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kivraid/kivraid/internal/store/sqlcgen"
)

// getBody fetches a URL without following redirects and returns the status
// and body. Uses the redirect-suppressing client from the OIDC flow tests.
func getBody(t *testing.T, c *http.Client, u string) (int, string) {
	t.Helper()
	resp, err := c.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// authorizeURL builds an /authorize request with the given client_id and
// redirect_uri (the other params are valid and constant).
func authorizeURL(issuer, clientID, redirectURI string) string {
	q := url.Values{
		"response_type": {"code"},
		"scope":         {"openid"},
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"state":         {"xyz"},
	}
	return issuer + "/authorize?" + q.Encode()
}

func TestAuthorizeGuardUnregisteredRedirectURI(t *testing.T) {
	issuer, _ := startIssuer(t, false)
	c := newClient(t)

	bad := "https://evil.example.com/callback"
	status, body := getBody(t, c, authorizeURL(issuer, testClientID, bad))

	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}
	// Branded, actionable page — not op's raw error.
	if !strings.Contains(body, "Redirect URI not allowed") {
		t.Errorf("body missing the branded title; got:\n%s", body)
	}
	// Names the offending URI and the application so the admin knows what to fix.
	if !strings.Contains(body, bad) {
		t.Errorf("body should show the rejected redirect_uri %q", bad)
	}
	if !strings.Contains(body, "IT App") {
		t.Errorf("body should name the application")
	}
}

func TestAuthorizeGuardUnknownClient(t *testing.T) {
	issuer, _ := startIssuer(t, false)
	c := newClient(t)

	status, body := getBody(t, c, authorizeURL(issuer, "no-such-client", testRedirectURI))

	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}
	if !strings.Contains(body, "Unknown application") {
		t.Errorf("body missing the branded title; got:\n%s", body)
	}
}

func TestAuthorizeGuardValidRequestPassesThrough(t *testing.T) {
	issuer, _ := startIssuer(t, false)
	c := newClient(t)

	// A registered redirect_uri must not hit the guard's error page; op takes
	// over and redirects the (unauthenticated) user to login.
	status, body := getBody(t, c, authorizeURL(issuer, testClientID, testRedirectURI))

	if strings.Contains(body, "Redirect URI not allowed") || strings.Contains(body, "Unknown application") {
		t.Fatalf("valid request hit the guard error page; status %d, body:\n%s", status, body)
	}
	if status < 300 || status >= 400 {
		t.Fatalf("valid request: want a redirect to login, got %d", status)
	}
}

// endSessionURL builds an /end_session request with the given params.
func endSessionURL(issuer string, params url.Values) string {
	return issuer + "/end_session?" + params.Encode()
}

// assertPostLogoutRejected checks the guard's branded page for a rejected
// post_logout_redirect_uri.
func assertPostLogoutRejected(t *testing.T, status int, body, uri string) {
	t.Helper()
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body:\n%s", status, body)
	}
	// Branded page, not op's raw invalid_request JSON.
	if !strings.Contains(body, "Sign-out redirect not allowed") {
		t.Errorf("body missing the branded title; got:\n%s", body)
	}
	if strings.Contains(body, "invalid_request") {
		t.Errorf("body leaked op's raw JSON error")
	}
	if !strings.Contains(body, uri) {
		t.Errorf("body should show the rejected post_logout_redirect_uri %q", uri)
	}
	if !strings.Contains(body, "IT App") {
		t.Errorf("body should name the application")
	}
}

func TestEndSessionGuardUnregisteredPostLogout(t *testing.T) {
	issuer, _ := startIssuer(t, false)
	c := newClient(t)

	bad := "https://evil.example.com/loggedout"
	status, body := getBody(t, c, endSessionURL(issuer, url.Values{
		"client_id": {testClientID}, "post_logout_redirect_uri": {bad},
	}))
	assertPostLogoutRejected(t, status, body, bad)
}

// A URI registered for another client must still be rejected for this one:
// op checks per client, so a global check would leak op's raw JSON.
func TestEndSessionGuardPostLogoutRegisteredForOtherClient(t *testing.T) {
	issuer, st := startIssuer(t, false)
	c := newClient(t)
	ctx := context.Background()

	other := "https://other.example.com/loggedout"
	now := time.Now().UTC()
	app, err := st.CreateApplication(ctx, sqlcgen.CreateApplicationParams{
		ID: "app2", Name: "Other App", Slug: "other-app", CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateProvider(ctx, sqlcgen.CreateProviderParams{
		ID: "prov2", ApplicationID: app.ID, ClientID: "other-client-id",
		RedirectUris: `["https://other.example.com/callback"]`, PostLogoutRedirectUris: `["` + other + `"]`,
		Public:                true,
		AccessTokenTtlSeconds: 300, RefreshTokenTtlSeconds: 3600, IDTokenTtlSeconds: 3600,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	status, body := getBody(t, c, endSessionURL(issuer, url.Values{
		"client_id": {testClientID}, "post_logout_redirect_uri": {other},
	}))
	assertPostLogoutRejected(t, status, body, other)
}

// Without client_id, the client comes from the id_token_hint's azp, as in op.
func TestEndSessionGuardResolvesClientFromIDTokenHint(t *testing.T) {
	issuer, _ := startIssuer(t, false)
	c := newClient(t)

	enc := base64.RawURLEncoding.EncodeToString
	hint := enc([]byte(`{"alg":"none"}`)) + "." + enc([]byte(`{"azp":"`+testClientID+`"}`)) + ".sig"
	bad := "https://evil.example.com/loggedout"
	status, body := getBody(t, c, endSessionURL(issuer, url.Values{
		"id_token_hint": {hint}, "post_logout_redirect_uri": {bad},
	}))
	assertPostLogoutRejected(t, status, body, bad)
}

// Requests op accepts must reach op untouched: a registered URI, and a URI
// with no resolvable client (op ignores it and uses its default redirect).
func TestEndSessionGuardPassesThrough(t *testing.T) {
	issuer, st := startIssuer(t, false)
	c := newClient(t)

	good := "https://app.example.com/loggedout"
	if _, err := st.DB.Exec(`UPDATE providers SET post_logout_redirect_uris = $1 WHERE id = 'prov1'`,
		`["`+good+`"]`); err != nil {
		t.Fatal(err)
	}

	for name, params := range map[string]url.Values{
		"registered": {"client_id": {testClientID}, "post_logout_redirect_uri": {good}},
		"no client":  {"post_logout_redirect_uri": {"https://evil.example.com/loggedout"}},
	} {
		t.Run(name, func(t *testing.T) {
			status, body := getBody(t, c, endSessionURL(issuer, params))
			if strings.Contains(body, "Sign-out redirect not allowed") {
				t.Fatalf("request hit the guard error page; status %d", status)
			}
			if status < 300 || status >= 400 {
				t.Fatalf("want a redirect from op, got %d; body:\n%s", status, body)
			}
		})
	}
}
