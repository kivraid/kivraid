package web

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/lporcheron/kivraid/internal/sources/local"
	"github.com/lporcheron/kivraid/internal/store/storetest"
)

var secretRe = regexp.MustCompile(`[0-9a-f]{64}`)

// findSecret extracts the displayed client secret: the 64-hex string that
// is not the (equally 64-hex) CSRF token.
func findSecret(page, csrf string) string {
	for _, m := range secretRe.FindAllString(page, -1) {
		if m != csrf {
			return m
		}
	}
	return ""
}

func TestClientTypeAndSecretLifecycle(t *testing.T) {
	st := storetest.Open(t)
	ts := newServerForStore(t, st, nil)
	ctx := context.Background()

	if _, err := local.NewSource(st).CreateUser(ctx,
		"root", "root@example.com", "Root", "root-pass-123", true); err != nil {
		t.Fatal(err)
	}
	c := newClient(t)
	login(t, c, ts.URL, "root", "root-pass-123")
	csrf := fetchCSRFFromPage(t, c, ts.URL+"/admin/applications")

	appForm := url.Values{
		"_csrf": {csrf}, "name": {"Grafana"},
		"redirect_uris": {"https://grafana.example.com/login/generic_oauth"},
		"client_type":   {"confidential"},
	}
	resp, err := c.PostForm(ts.URL+"/admin/applications", appForm)
	if err != nil {
		t.Fatal(err)
	}
	created, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	secret := findSecret(string(created), csrf)
	if secret == "" {
		t.Fatal("no secret on the creation page")
	}

	var appID string
	if err := st.DB.QueryRowContext(ctx,
		`SELECT id FROM applications WHERE slug = 'grafana'`).Scan(&appID); err != nil {
		t.Fatal(err)
	}

	// The secret stays visible on the detail page (encrypted at rest).
	detailURL := ts.URL + "/admin/applications/" + appID
	resp, err = c.Get(detailURL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), secret) {
		t.Fatal("secret not displayed on the detail page")
	}

	// Switching to public drops the secret and shows the PKCE badge.
	update := url.Values{
		"_csrf": {csrf}, "name": {"Grafana"}, "slug": {"grafana"},
		"redirect_uris": {"https://grafana.example.com/login/generic_oauth"},
		"client_type":   {"public"},
	}
	resp, err = c.PostForm(detailURL, update)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSeeOther {
		msg, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("switch to public: status %d: %.300s", resp.StatusCode, msg)
	}
	resp.Body.Close()
	resp, err = c.Get(detailURL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	page := string(body)
	if !strings.Contains(page, "Public · PKCE") || strings.Contains(page, secret) {
		t.Fatal("switch to public did not drop the secret")
	}

	// Switching back to confidential mints a fresh, visible secret.
	update.Set("client_type", "confidential")
	resp, err = c.PostForm(detailURL, update)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	resp, err = c.Get(detailURL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	fresh := findSecret(string(body), csrf)
	if fresh == "" || fresh == secret {
		t.Fatalf("expected a fresh visible secret, got %q", fresh)
	}

	// The new secret authenticates at the token endpoint layer.
	if resp, err = http.PostForm(ts.URL+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {"bogus"},
		"client_id": {clientIDFromDetail(t, string(body))}, "client_secret": {fresh},
		"redirect_uri": {"https://grafana.example.com/login/generic_oauth"},
	}); err != nil {
		t.Fatal(err)
	}
	msg, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	// A bogus code must fail on the code, not on client authentication.
	if strings.Contains(string(msg), "invalid client secret") {
		t.Fatalf("fresh secret rejected: %s", msg)
	}
}

var clientIDRe = regexp.MustCompile(`[0-9a-f]{40}`)

func clientIDFromDetail(t *testing.T, page string) string {
	t.Helper()
	id := clientIDRe.FindString(page)
	if id == "" {
		t.Fatal("no client id on the detail page")
	}
	return id
}
