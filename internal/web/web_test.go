package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/lporcheron/kivraid/internal/config"
	"github.com/lporcheron/kivraid/internal/oidcserver"
	"github.com/lporcheron/kivraid/internal/secrets"
	"github.com/lporcheron/kivraid/internal/session"
	"github.com/lporcheron/kivraid/internal/sources/ldap"
	"github.com/lporcheron/kivraid/internal/sources/local"
	"github.com/lporcheron/kivraid/internal/store"
)

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	ctx := context.Background()

	st, err := store.Open(ctx, "sqlite", filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	if _, err := local.NewSource(st).CreateUser(ctx,
		"alice", "alice@example.com", "Alice Liddell", "s3cret-pass", false); err != nil {
		t.Fatal(err)
	}

	cfg := config.Config{BaseURL: "http://localhost", SecretKey: strings.Repeat("k", 32)}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	oidcProvider, oidcStorage, err := oidcserver.New(ctx, cfg, st, log)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(Deps{
		Config: cfg, Store: st, Sessions: session.NewManager(st.DB, false),
		OIDC: oidcProvider, OIDCStore: oidcStorage,
		LDAP: ldap.NewManager(st, secrets.DeriveKey(cfg.SecretKey, "ldap-bind-passwords"), log),
		Log:  log,
	})
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
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

	csrf := fetchCSRF(t, c, ts.URL+"/login")

	// Wrong password: 401, page shows the error.
	resp, err := c.PostForm(ts.URL+"/login", url.Values{
		"_csrf": {csrf}, "username": {"alice"}, "password": {"nope"},
	})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad password: want 401, got %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "Invalid username or password") {
		t.Fatal("error message missing from login page")
	}

	// Good password: redirect to /.
	resp, err = c.PostForm(ts.URL+"/login", url.Values{
		"_csrf": {csrf}, "username": {"alice"}, "password": {"s3cret-pass"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
		t.Fatalf("login: want 303 to /, got %d to %q", resp.StatusCode, resp.Header.Get("Location"))
	}

	// Profile now renders.
	resp, err = c.Get(ts.URL + "/profile")
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
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("POST without CSRF token: want 403, got %d", resp.StatusCode)
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
