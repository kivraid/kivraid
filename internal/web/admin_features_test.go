package web

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kivraid/kivraid/internal/sources/local"
	"github.com/kivraid/kivraid/internal/store"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
	"github.com/kivraid/kivraid/internal/store/storetest"
)

func adminClient(t *testing.T) (*httptest.Server, *store.Store, *http.Client, string) {
	t.Helper()
	st := storetest.Open(t)
	ts := newServerForStore(t, st, nil)
	if _, err := local.NewSource(st).CreateUser(context.Background(),
		"root", "root@example.com", "Root", "root-pass-123", true); err != nil {
		t.Fatal(err)
	}
	c := newClient(t)
	login(t, c, ts.URL, "root", "root-pass-123")
	csrf := fetchCSRFFromPage(t, c, ts.URL+"/admin/applications")
	return ts, st, c, csrf
}

func TestProxyApplicationForwardAuth(t *testing.T) {
	ts, st, c, csrf := adminClient(t)
	ctx := context.Background()

	// Create a forward-auth application protecting a host.
	resp, err := c.PostForm(ts.URL+"/admin/applications", url.Values{
		"_csrf": {csrf}, "kind": {"proxy"}, "name": {"Jellyfin"},
		"proxy_hosts": {"jellyfin.home.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("create proxy app: want 303, got %d", resp.StatusCode)
	}
	var appID string
	if err := st.DB.QueryRowContext(ctx,
		`SELECT id FROM applications WHERE slug = 'jellyfin' AND kind = 'proxy'`).Scan(&appID); err != nil {
		t.Fatalf("proxy app not persisted: %v", err)
	}

	// An ordinary member: no policy yet → allowed, identity headers set.
	alice, err := local.NewSource(st).CreateUser(ctx, "alice", "alice@example.com", "Alice", "alice-pass-1", false)
	if err != nil {
		t.Fatal(err)
	}
	ca := newClient(t)
	login(t, ca, ts.URL, "alice", "alice-pass-1")

	fa := func(client *http.Client) *http.Response {
		req, _ := http.NewRequest("GET", ts.URL+"/outpost/auth", nil)
		req.Header.Set("X-Forwarded-Host", "jellyfin.home.example.com")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	resp = fa(ca)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Remote-User") != "alice" {
		t.Fatalf("open policy: want 200 with headers, got %d / %q", resp.StatusCode, resp.Header.Get("Remote-User"))
	}

	// Bind the app to a group alice is not in → she is denied.
	grp, err := st.CreateGroup(ctx, sqlcgen.CreateGroupParams{
		ID: "media", Name: "media", Source: "local", CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.AddAppPolicy(ctx, sqlcgen.AddAppPolicyParams{ApplicationID: appID, GroupID: grp.ID}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetApplicationRestricted(ctx, sqlcgen.SetApplicationRestrictedParams{Restricted: true, ID: appID}); err != nil {
		t.Fatal(err)
	}
	resp = fa(ca)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("policy denies non-member: want 403, got %d", resp.StatusCode)
	}

	// Add alice to the group → allowed again.
	if err := st.AddUserGroup(ctx, sqlcgen.AddUserGroupParams{UserID: alice.ID, GroupID: grp.ID}); err != nil {
		t.Fatal(err)
	}
	resp = fa(ca)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("policy allows member: want 200, got %d", resp.StatusCode)
	}

	// Anonymous request for a proxy host redirects to login (host known).
	anon := newClient(t)
	resp = fa(anon)
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("anonymous on known host: want 302, got %d", resp.StatusCode)
	}
}

func TestTokenLifetimesEditable(t *testing.T) {
	ts, st, c, csrf := adminClient(t)
	ctx := context.Background()

	resp, err := c.PostForm(ts.URL+"/admin/applications", url.Values{
		"_csrf": {csrf}, "kind": {"oidc"}, "name": {"App"},
		"redirect_uris": {"https://app.example.com/cb"}, "client_type": {"confidential"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	var appID string
	if err := st.DB.QueryRowContext(ctx, `SELECT id FROM applications WHERE slug = 'app'`).Scan(&appID); err != nil {
		t.Fatal(err)
	}

	resp, err = c.PostForm(ts.URL+"/admin/applications/"+appID, url.Values{
		"_csrf": {csrf}, "name": {"App"}, "slug": {"app"},
		"redirect_uris": {"https://app.example.com/cb"}, "client_type": {"confidential"},
		"access_ttl": {"120"}, "refresh_ttl": {"7200"}, "id_ttl": {"600"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("update ttls: want 303, got %d", resp.StatusCode)
	}

	p, err := st.GetProviderByApplication(ctx, appID)
	if err != nil {
		t.Fatal(err)
	}
	if p.AccessTokenTtlSeconds != 120 || p.RefreshTokenTtlSeconds != 7200 || p.IDTokenTtlSeconds != 600 {
		t.Fatalf("ttls not persisted: %d/%d/%d", p.AccessTokenTtlSeconds, p.RefreshTokenTtlSeconds, p.IDTokenTtlSeconds)
	}
}

func TestApplicationIcon(t *testing.T) {
	ts, st, c, csrf := adminClient(t)
	ctx := context.Background()

	resp, err := c.PostForm(ts.URL+"/admin/applications", url.Values{
		"_csrf": {csrf}, "kind": {"proxy"}, "name": {"Icon App"},
		"proxy_hosts": {"icon.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	var appID string
	if err := st.DB.QueryRowContext(ctx, `SELECT id FROM applications WHERE slug = 'icon-app'`).Scan(&appID); err != nil {
		t.Fatal(err)
	}

	// Upload a PNG.
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.WriteField("_csrf", csrf)
	fw, _ := mw.CreateFormFile("icon", "logo.png")
	fw.Write([]byte("\x89PNG\r\n\x1a\nfake-png-body"))
	mw.Close()
	req, _ := http.NewRequest("POST", ts.URL+"/admin/applications/"+appID+"/icon", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("icon upload: want 303, got %d", resp.StatusCode)
	}

	resp, err = c.Get(ts.URL + "/appicon/" + appID)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "image/png") {
		t.Fatalf("icon fetch: %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if !bytes.Contains(body, []byte("fake-png-body")) {
		t.Fatal("icon bytes mismatch")
	}
}
