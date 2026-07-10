package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/lporcheron/kivraid/internal/config"
	"github.com/lporcheron/kivraid/internal/mfa"
	"github.com/lporcheron/kivraid/internal/oidcserver"
	"github.com/lporcheron/kivraid/internal/secrets"
	"github.com/lporcheron/kivraid/internal/session"
	"github.com/lporcheron/kivraid/internal/sources/ldap"
	"github.com/lporcheron/kivraid/internal/sources/local"
	"github.com/lporcheron/kivraid/internal/store"
	"github.com/lporcheron/kivraid/internal/store/storetest"
	"github.com/lporcheron/kivraid/internal/webauthn"
)

// newServerForStore wires a full web server around an existing store.
func newServerForStore(t *testing.T, st *store.Store, forwardAuthDomains []string) *httptest.Server {
	t.Helper()
	cfg := config.Config{
		BaseURL:     "http://localhost",
		SecretKey:   strings.Repeat("k", 32),
		ForwardAuth: config.ForwardAuth{Domains: forwardAuthDomains},
		Session:     config.Session{Lifetime: config.Duration(7 * 24 * time.Hour)},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	oidcProvider, oidcStorage, err := oidcserver.New(context.Background(), cfg, st, log)
	if err != nil {
		t.Fatal(err)
	}
	waManager, err := webauthn.New(st, cfg.BaseURL)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(Deps{
		Config: cfg, Store: st, Sessions: session.NewManager(st.DB, st.Driver, false,
			time.Duration(cfg.Session.Lifetime), time.Duration(cfg.Session.IdleTimeout)),
		OIDC: oidcProvider, OIDCStore: oidcStorage,
		LDAP:     ldap.NewManager(st, secrets.DeriveKey(cfg.SecretKey, "ldap-bind-passwords"), log),
		MFA:      mfa.NewManager(st, secrets.DeriveKey(cfg.SecretKey, "totp-secrets")),
		WebAuthn: waManager,
		Log:      log,
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func buildTestServer(t *testing.T, forwardAuthDomains []string) (*httptest.Server, *store.Store) {
	t.Helper()
	st := storetest.Open(t)
	if _, err := local.NewSource(st).CreateUser(context.Background(),
		"alice", "alice@example.com", "Alice Liddell", "s3cret-pass", false); err != nil {
		t.Fatal(err)
	}
	return newServerForStore(t, st, forwardAuthDomains), st
}

func newTestServer(t *testing.T) *httptest.Server {
	ts, _ := buildTestServer(t, nil)
	return ts
}

func newClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

var csrfRe = regexp.MustCompile(`name="_csrf" value="([0-9a-f]+)"`)

func fetchCSRF(t *testing.T, c *http.Client, url string) string {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d", url, resp.StatusCode)
	}
	m := csrfRe.FindSubmatch(body)
	if m == nil {
		t.Fatal("no CSRF token in login page")
	}
	return string(m[1])
}

func TestLoginFlow(t *testing.T) {
	ts := newTestServer(t)
	c := newClient(t)

	csrf := identify(t, c, ts.URL, "alice", "")

	// Wrong password: 401, page shows the error.
	resp := passwordStep(t, c, ts.URL, csrf, "nope")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad password: want 401, got %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "Invalid username or password") {
		t.Fatal("error message missing from login page")
	}

	// Good password (same session keeps the pending identifier): redirect to /.
	resp = passwordStep(t, c, ts.URL, csrf, "s3cret-pass")
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
		t.Fatalf("login: want 303 to /, got %d to %q", resp.StatusCode, resp.Header.Get("Location"))
	}

	// Profile now renders.
	resp, err := c.Get(ts.URL + "/profile")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("profile: want 200, got %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "Alice Liddell") || !strings.Contains(string(body), "alice@example.com") {
		t.Fatal("profile page missing user identity")
	}
}

func TestCSRFRequired(t *testing.T) {
	ts := newTestServer(t)
	c := newClient(t)

	resp, err := c.PostForm(ts.URL+"/login", url.Values{
		"username": {"alice"}, "password": {"s3cret-pass"},
	})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("POST without CSRF token: want 403, got %d", resp.StatusCode)
	}
	// A form posted from a session with no CSRF token (the expired-tab
	// case) gets the styled session-expired page with a way back in,
	// not a bare plain-text 403.
	if !strings.Contains(string(body), "Session expired") ||
		!strings.Contains(string(body), "Sign in again") {
		t.Fatalf("expired-session CSRF failure should render the styled page, got: %.200s", body)
	}
}

func TestCSRFMismatchRendersFormExpired(t *testing.T) {
	ts := newTestServer(t)
	c := newClient(t)

	// Prime a session (and its CSRF token), then post a stale token.
	fetchCSRF(t, c, ts.URL+"/login")
	resp, err := c.PostForm(ts.URL+"/login", url.Values{
		"_csrf": {"deadbeef"}, "username": {"alice"}, "password": {"s3cret-pass"},
	})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("POST with wrong CSRF token: want 403, got %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "Form expired") {
		t.Fatalf("CSRF mismatch should render the styled page, got: %.200s", body)
	}
}

func TestAnonymousRedirectedToLogin(t *testing.T) {
	ts := newTestServer(t)
	c := newClient(t)

	resp, err := c.Get(ts.URL + "/profile")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("want 303, got %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/login?next=%2Fprofile" {
		t.Fatalf("unexpected redirect target %q", loc)
	}
}

// identify runs the first login step (identifier form) and returns the
// session CSRF token to reuse for the password step. next, when set, is
// carried as the post-login redirect target.
func identify(t *testing.T, c *http.Client, baseURL, username, next string) string {
	t.Helper()
	csrf := fetchCSRF(t, c, baseURL+"/login")
	form := url.Values{"_csrf": {csrf}, "username": {username}}
	if next != "" {
		form.Set("next", next)
	}
	resp, err := c.PostForm(baseURL+"/login", form)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login/password" {
		t.Fatalf("identify %s: want 303 to /login/password, got %d to %q",
			username, resp.StatusCode, resp.Header.Get("Location"))
	}
	return csrf
}

// passwordStep submits the second login step and returns the raw response
// for the caller to inspect (status, redirect target).
func passwordStep(t *testing.T, c *http.Client, baseURL, csrf, password string) *http.Response {
	t.Helper()
	resp, err := c.PostForm(baseURL+"/login/password", url.Values{"_csrf": {csrf}, "password": {password}})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func login(t *testing.T, c *http.Client, baseURL, username, password string) {
	t.Helper()
	csrf := identify(t, c, baseURL, username, "")
	resp := passwordStep(t, c, baseURL, csrf, password)
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login %s: want 303, got %d", username, resp.StatusCode)
	}
}

func TestPasswordChangeLocal(t *testing.T) {
	ts := newTestServer(t)
	c := newClient(t)
	login(t, c, ts.URL, "alice", "s3cret-pass")
	csrf := fetchCSRFFromPage(t, c, ts.URL+"/profile")

	// Wrong current password is rejected.
	resp, err := c.PostForm(ts.URL+"/profile/password", url.Values{
		"_csrf": {csrf}, "current_password": {"wrong"},
		"new_password": {"new-pass-123"}, "confirm_password": {"new-pass-123"},
	})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(string(body), "current password is incorrect") {
		t.Fatalf("wrong current: got %d", resp.StatusCode)
	}

	// Correct current password changes it.
	resp, err = c.PostForm(ts.URL+"/profile/password", url.Values{
		"_csrf": {csrf}, "current_password": {"s3cret-pass"},
		"new_password": {"new-pass-123"}, "confirm_password": {"new-pass-123"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("change: want 303, got %d", resp.StatusCode)
	}

	// Old password no longer works, the new one does.
	c2 := newClient(t)
	csrf2 := identify(t, c2, ts.URL, "alice", "")
	resp = passwordStep(t, c2, ts.URL, csrf2, "s3cret-pass")
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old password still accepted: %d", resp.StatusCode)
	}
	login(t, c2, ts.URL, "alice", "new-pass-123")
}

var tokenHashRe = regexp.MustCompile(`name="token_hash" value="([0-9a-f]+)"`)

func TestSessionsListAndRevoke(t *testing.T) {
	ts := newTestServer(t)

	// Two sessions for the same user.
	c1 := newClient(t)
	login(t, c1, ts.URL, "alice", "s3cret-pass")
	c2 := newClient(t)
	login(t, c2, ts.URL, "alice", "s3cret-pass")

	resp, err := c1.Get(ts.URL + "/sessions")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	page := string(body)
	if !strings.Contains(page, "This device") {
		t.Fatal("current session not marked")
	}
	m := tokenHashRe.FindStringSubmatch(page)
	if m == nil {
		t.Fatal("no revocable session listed")
	}

	// Revoke the other session; it must be logged out.
	csrf := csrfRe.FindSubmatch(body)
	resp, err = c1.PostForm(ts.URL+"/sessions/revoke", url.Values{
		"_csrf": {string(csrf[1])}, "token_hash": {m[1]},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	resp, err = c2.Get(ts.URL + "/profile")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("revoked session still alive: %d", resp.StatusCode)
	}
}

// fetchCSRFFromPage extracts the CSRF token from any authenticated page.
func fetchCSRFFromPage(t *testing.T, c *http.Client, url string) string {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := csrfRe.FindSubmatch(body)
	if m == nil {
		t.Fatalf("no CSRF token on %s", url)
	}
	return string(m[1])
}

func TestSecurityHeaders(t *testing.T) {
	ts := newTestServer(t)
	resp, err := http.Get(ts.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	for header, want := range map[string]string{
		"X-Frame-Options":        "DENY",
		"X-Content-Type-Options": "nosniff",
	} {
		if got := resp.Header.Get(header); got != want {
			t.Errorf("%s: want %q, got %q", header, want, got)
		}
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("missing CSP, got %q", resp.Header.Get("Content-Security-Policy"))
	}
}
