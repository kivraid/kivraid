package web

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
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

func TestEndSessionGuardUnregisteredPostLogout(t *testing.T) {
	issuer, _ := startIssuer(t, false)
	c := newClient(t)

	bad := "https://evil.example.com/loggedout"
	status, body := getBody(t, c, issuer+"/end_session?post_logout_redirect_uri="+url.QueryEscape(bad))

	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}
	// Branded page, not op's raw invalid_request JSON.
	if !strings.Contains(body, "Sign-out redirect not allowed") {
		t.Errorf("body missing the branded title; got:\n%s", body)
	}
	if strings.Contains(body, "invalid_request") {
		t.Errorf("body leaked op's raw JSON error")
	}
	if !strings.Contains(body, bad) {
		t.Errorf("body should show the rejected post_logout_redirect_uri %q", bad)
	}
}
