package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kivraid/kivraid/internal/sources/local"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
)

// Deleting the only group an application is restricted to must lock the
// application, never open it to every authenticated user.
func TestAccessPolicyFailsClosedWhenGroupDeleted(t *testing.T) {
	ts, st, c, csrf := adminClient(t)
	ctx := context.Background()

	resp, err := c.PostForm(ts.URL+"/admin/applications", url.Values{
		"_csrf": {csrf}, "kind": {"proxy"}, "name": {"Vault"},
		"proxy_hosts": {"vault.example.com"}, "launch_url": {"https://vault.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	var appID string
	if err := st.DB.QueryRowContext(ctx, `SELECT id FROM applications WHERE slug = 'vault'`).Scan(&appID); err != nil {
		t.Fatal(err)
	}

	grp, err := st.CreateGroup(ctx, sqlcgen.CreateGroupParams{
		ID: "family", Name: "family", Source: "local", CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	alice, err := local.NewSource(st).CreateUser(ctx, "alice", "alice@example.com", "Alice", "alice-pass-1", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.AddUserGroup(ctx, sqlcgen.AddUserGroupParams{UserID: alice.ID, GroupID: grp.ID}); err != nil {
		t.Fatal(err)
	}
	ca := newClient(t)
	login(t, ca, ts.URL, "alice", "alice-pass-1")

	forwardAuth := func() int {
		req, _ := http.NewRequest("GET", ts.URL+"/outpost/auth", nil)
		req.Header.Set("X-Forwarded-Host", "vault.example.com")
		resp, err := ca.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	saveAccess := func(access string, groups ...string) {
		t.Helper()
		resp, err := c.PostForm(ts.URL+"/admin/applications/"+appID, url.Values{
			"_csrf": {csrf}, "name": {"Vault"}, "slug": {"vault"},
			"proxy_hosts": {"vault.example.com"}, "launch_url": {"https://vault.example.com"},
			"access": {access}, "policy_groups": groups,
		})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("save access %s: want 303, got %d", access, resp.StatusCode)
		}
	}
	launcherShowsVault := func() bool {
		_, body := getPage(t, ca, ts.URL+"/")
		return strings.Contains(body, "Vault")
	}

	saveAccess("groups", grp.ID)
	if got := forwardAuth(); got != http.StatusOK {
		t.Fatalf("member of the allowed group: want 200, got %d", got)
	}

	// The group page warns that it is the application's only way in.
	if _, body := getPage(t, c, ts.URL+"/admin/groups/"+grp.ID); !strings.Contains(body, "only this group") {
		t.Error("group page should list the application restricted to it")
	}

	resp, err = c.PostForm(ts.URL+"/admin/groups/"+grp.ID+"/delete", url.Values{"_csrf": {csrf}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if got := forwardAuth(); got != http.StatusForbidden {
		t.Fatalf("after deleting the only allowed group: want 403, got %d", got)
	}
	if launcherShowsVault() {
		t.Error("locked application still offered in the launcher")
	}
	if _, body := getPage(t, c, ts.URL+"/admin/applications/"+appID); !strings.Contains(body, "Nobody can sign in") {
		t.Error("application page should warn that nobody can sign in")
	}

	// Opening it to everyone is an explicit choice.
	saveAccess("everyone")
	if got := forwardAuth(); got != http.StatusOK {
		t.Fatalf("open to everyone: want 200, got %d", got)
	}
	if !launcherShowsVault() {
		t.Error("open application missing from the launcher")
	}

	// "Only selected groups" with none selected locks it as well.
	saveAccess("groups")
	if got := forwardAuth(); got != http.StatusForbidden {
		t.Fatalf("restricted with no groups: want 403, got %d", got)
	}
}
