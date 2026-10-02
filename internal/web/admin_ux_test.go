package web

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kivraid/kivraid/internal/sources/local"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
)

func TestDurationSeconds(t *testing.T) {
	for raw, want := range map[string]int64{"300": 300, "5m": 300, " 30d ": 2592000, "1H": 3600, "90s": 90} {
		got, err := parseDurationSeconds(raw)
		if err != nil || got != want {
			t.Errorf("parseDurationSeconds(%q) = %d, %v; want %d", raw, got, err, want)
		}
	}
	for _, raw := range []string{"", "abc", "-5m", "0", "5w", "1.5h"} {
		if _, err := parseDurationSeconds(raw); err == nil {
			t.Errorf("parseDurationSeconds(%q) should fail", raw)
		}
	}
	for n, want := range map[int64]string{300: "5m", 2592000: "30d", 3600: "1h", 90: "90s", 86400: "1d"} {
		if got := formatDurationSeconds(n); got != want {
			t.Errorf("formatDurationSeconds(%d) = %q, want %q", n, got, want)
		}
	}
}

// createOIDCApp posts the new-application form and returns the credentials
// page body and the application ID.
func createOIDCApp(t *testing.T, c *http.Client, baseURL, csrf string, extra url.Values) (string, string) {
	t.Helper()
	form := url.Values{
		"_csrf": {csrf}, "kind": {"oidc"}, "name": {"Grafana"},
		"launch_url": {"https://grafana.example.com"}, "redirect_uris": {"https://grafana.example.com/login/generic_oauth"},
		"client_type": {"confidential"},
	}
	for k, v := range extra {
		form[k] = v
	}
	resp, err := c.PostForm(baseURL+"/admin/applications", form)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	body := string(b)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create app: want 200, got %d:\n%s", resp.StatusCode, body)
	}
	i := strings.Index(body, `href="/admin/applications/`)
	if i < 0 {
		t.Fatal("credentials page has no link to the application")
	}
	id := body[i+len(`href="/admin/applications/`):]
	return body, id[:strings.IndexByte(id, '"')]
}

func TestAppCreationPresetAndPostLogout(t *testing.T) {
	ts, st, c, csrf := adminClient(t)
	body, appID := createOIDCApp(t, c, ts.URL, csrf, url.Values{
		"preset": {"grafana"}, "post_logout_uris": {"https://grafana.example.com"},
	})
	// The Grafana snippet is selected and carries the real client ID.
	if !strings.Contains(body, "[auth.generic_oauth]") || !strings.Contains(body, `<option value="grafana" selected>`) {
		t.Fatal("credentials page should preselect the Grafana snippet")
	}
	p, err := st.GetProviderByApplication(context.Background(), appID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "client_id = "+p.ClientID) {
		t.Error("snippet should embed the client ID")
	}
	if p.PostLogoutRedirectUris != `["https://grafana.example.com"]` {
		t.Errorf("post-logout URIs not saved from the creation form: %s", p.PostLogoutRedirectUris)
	}
}

func TestAppTokenLifetimesAsDurations(t *testing.T) {
	ts, st, c, csrf := adminClient(t)
	_, appID := createOIDCApp(t, c, ts.URL, csrf, nil)

	update := func(access, refresh, id string) int {
		resp, err := c.PostForm(ts.URL+"/admin/applications/"+appID, url.Values{
			"_csrf": {csrf}, "name": {"Grafana"}, "slug": {"grafana"},
			"redirect_uris": {"https://grafana.example.com/login/generic_oauth"}, "client_type": {"confidential"},
			"access": {"everyone"}, "access_ttl": {access}, "refresh_ttl": {refresh}, "id_ttl": {id},
		})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if got := update("10m", "7d", "2h"); got != http.StatusSeeOther {
		t.Fatalf("valid lifetimes: want 303, got %d", got)
	}
	p, _ := st.GetProviderByApplication(context.Background(), appID)
	if p.AccessTokenTtlSeconds != 600 || p.RefreshTokenTtlSeconds != 7*86400 || p.IDTokenTtlSeconds != 7200 {
		t.Fatalf("lifetimes stored as %d/%d/%d", p.AccessTokenTtlSeconds, p.RefreshTokenTtlSeconds, p.IDTokenTtlSeconds)
	}
	if _, body := getPage(t, c, ts.URL+"/admin/applications/"+appID); !strings.Contains(body, `value="10m"`) {
		t.Error("detail page should show lifetimes as durations")
	}
	if got := update("soon", "7d", "2h"); got != http.StatusUnprocessableEntity {
		t.Errorf("invalid lifetime: want 422, got %d", got)
	}
	if got := update("2d", "7d", "2h"); got != http.StatusUnprocessableEntity {
		t.Errorf("access token over 1 day: want 422, got %d", got)
	}
}

func TestUsersListFilters(t *testing.T) {
	ts, st, c, _ := adminClient(t)
	ctx := context.Background()
	src := local.NewSource(st)
	if _, err := src.CreateUser(ctx, "bob", "bob@example.com", "Bob Active", "bob-pass-123", false); err != nil {
		t.Fatal(err)
	}
	carol, err := src.CreateUser(ctx, "carol", "carol@example.com", "Carol Gone", "carol-pass-123", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB.Exec(`UPDATE users SET active = $1 WHERE id = $2`, false, carol.ID); err != nil {
		t.Fatal(err)
	}

	_, body := getPage(t, c, ts.URL+"/admin/users?status=inactive")
	if !strings.Contains(body, "Carol Gone") || strings.Contains(body, "Bob Active") {
		t.Error("status=inactive should list only deactivated users")
	}
	_, body = getPage(t, c, ts.URL+"/admin/users?role=admin")
	if !strings.Contains(body, "root@example.com") || strings.Contains(body, "Bob Active") {
		t.Error("role=admin should list only administrators")
	}
	_, body = getPage(t, c, ts.URL+"/admin/users?source=ldap")
	if strings.Contains(body, "Bob Active") {
		t.Error("source=ldap should exclude local users")
	}
	if _, body = getPage(t, c, ts.URL+"/admin/users"); !strings.Contains(body, "Never signed in") {
		t.Error("users list should show the last sign-in")
	}
}

// A password chosen by an administrator must be replaced at first sign-in.
func TestNewUserMustChangePassword(t *testing.T) {
	ts, st, c, csrf := adminClient(t)
	grp, err := st.CreateGroup(context.Background(), sqlcgen.CreateGroupParams{
		ID: "staff", Name: "staff", Source: "local", CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.PostForm(ts.URL+"/admin/users", url.Values{
		"_csrf": {csrf}, "username": {"dave"}, "email": {"dave@example.com"}, "name": {"Dave"},
		"password_mode": {"set"}, "password": {"given-pass-1"}, "must_change": {"on"}, "groups": {grp.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("create user: want 303, got %d", resp.StatusCode)
	}
	dave, err := st.GetUserByUsername(context.Background(), "dave")
	if err != nil {
		t.Fatal(err)
	}
	if groups, _ := st.ListUserGroups(context.Background(), dave.ID); len(groups) != 1 || groups[0].ID != grp.ID {
		t.Error("new user should be added to the selected group")
	}

	cd := newClient(t)
	login(t, cd, ts.URL, "dave", "given-pass-1")
	resp, err = cd.Get(ts.URL + "/profile")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, passwordChangePath) {
		t.Fatalf("first sign-in should redirect to %s, got %d %q", passwordChangePath, resp.StatusCode, loc)
	}

	change := func(pw string) *http.Response {
		csrf := fetchCSRFFromPage(t, cd, ts.URL+passwordChangePath)
		resp, err := cd.PostForm(ts.URL+passwordChangePath, url.Values{
			"_csrf": {csrf}, "password": {pw}, "confirm_password": {pw}, "next": {"/profile"},
		})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	if resp := change("given-pass-1"); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("reusing the given password: want 422, got %d", resp.StatusCode)
	}
	if resp := change("my-own-pass-1"); resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/profile" {
		t.Fatalf("change: want 303 to /profile, got %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if status, _ := getPage(t, cd, ts.URL+"/profile"); status != http.StatusOK {
		t.Fatalf("profile after the change: want 200, got %d", status)
	}
}

func TestUserDetailGroupMembership(t *testing.T) {
	ts, st, c, csrf := adminClient(t)
	ctx := context.Background()
	bob, err := local.NewSource(st).CreateUser(ctx, "bob", "bob@example.com", "Bob", "bob-pass-123", false)
	if err != nil {
		t.Fatal(err)
	}
	grp, err := st.CreateGroup(ctx, sqlcgen.CreateGroupParams{ID: "ops", Name: "ops", Source: "local", CreatedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	post := func(path string) {
		resp, err := c.PostForm(ts.URL+"/admin/users/"+bob.ID+path, url.Values{"_csrf": {csrf}, "group_id": {grp.ID}})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("POST %s: want 303, got %d", path, resp.StatusCode)
		}
	}
	post("/groups")
	if groups, _ := st.ListUserGroups(ctx, bob.ID); len(groups) != 1 {
		t.Fatal("user not added to the group")
	}
	post("/groups/remove")
	if groups, _ := st.ListUserGroups(ctx, bob.ID); len(groups) != 0 {
		t.Fatal("user not removed from the group")
	}
}

func TestGroupSettingsAndMemberByUsername(t *testing.T) {
	ts, st, c, csrf := adminClient(t)
	ctx := context.Background()
	if _, err := local.NewSource(st).CreateUser(ctx, "bob", "bob@example.com", "Bob", "bob-pass-123", false); err != nil {
		t.Fatal(err)
	}
	grp, err := st.CreateGroup(ctx, sqlcgen.CreateGroupParams{ID: "ops", Name: "ops", Source: "local", CreatedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.PostForm(ts.URL+"/admin/groups/"+grp.ID, url.Values{
		"_csrf": {csrf}, "name": {"operations"}, "grants_admin": {"on"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	got, _ := st.GetGroup(ctx, grp.ID)
	if got.Name != "operations" || !got.GrantsAdmin {
		t.Fatalf("group settings not saved: %+v", got)
	}

	resp, err = c.PostForm(ts.URL+"/admin/groups/"+grp.ID+"/members", url.Values{"_csrf": {csrf}, "username": {"BOB"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("add member by username: want 303, got %d", resp.StatusCode)
	}
	resp, err = c.PostForm(ts.URL+"/admin/groups/"+grp.ID+"/members", url.Values{"_csrf": {csrf}, "username": {"nobody"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("unknown username: want 422, got %d", resp.StatusCode)
	}
}

// Forward-auth applications also wait for the required password change.
func TestMustChangePasswordBlocksForwardAuth(t *testing.T) {
	ts, _, c, csrf := adminClient(t)
	resp, err := c.PostForm(ts.URL+"/admin/applications", url.Values{
		"_csrf": {csrf}, "kind": {"proxy"}, "name": {"Wiki"}, "proxy_hosts": {"wiki.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	resp, err = c.PostForm(ts.URL+"/admin/users", url.Values{
		"_csrf": {csrf}, "username": {"erin"}, "email": {"erin@example.com"},
		"password_mode": {"set"}, "password": {"given-pass-1"}, "must_change": {"on"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	ce := newClient(t)
	login(t, ce, ts.URL, "erin", "given-pass-1")
	req, _ := http.NewRequest("GET", ts.URL+"/outpost/auth", nil)
	req.Header.Set("X-Forwarded-Host", "wiki.example.com")
	req.Header.Set("X-Forwarded-Uri", "/page")
	resp, err = ce.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	// The redirect targets the issuer (the test config's base URL).
	want := "http://localhost" + passwordChangePath + "?next=" + url.QueryEscape("https://wiki.example.com/page")
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != want {
		t.Fatalf("forward auth with a required change: want 302 to %s, got %d %q", want, resp.StatusCode, resp.Header.Get("Location"))
	}
}
