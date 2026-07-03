package web

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lporcheron/kivraid/internal/sources/local"
	"github.com/lporcheron/kivraid/internal/store/sqlcgen"
	"github.com/lporcheron/kivraid/internal/store/storetest"
)

func TestFirstRunSetup(t *testing.T) {
	// A server with no users at all.
	st := storetest.Open(t)
	ts := newServerForStore(t, st, nil)
	c := newClient(t)

	// The login page hands the first visitor over to setup.
	resp, err := c.Get(ts.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/setup" {
		t.Fatalf("want redirect to /setup, got %d to %q", resp.StatusCode, resp.Header.Get("Location"))
	}

	// Register the first administrator.
	csrf := fetchCSRF(t, c, ts.URL+"/setup")
	resp, err = c.PostForm(ts.URL+"/setup", url.Values{
		"_csrf": {csrf}, "username": {"Lionel"}, "email": {"lionel@example.com"},
		"name": {"Lionel"}, "password": {"first-admin-pass"}, "confirm_password": {"first-admin-pass"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
		t.Fatalf("setup: want 303 to /, got %d to %q", resp.StatusCode, resp.Header.Get("Location"))
	}

	// Logged straight in, as an administrator (Admin menu visible).
	resp, err = c.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "Admin") {
		t.Fatalf("expected the launcher with the Admin menu, got %d", resp.StatusCode)
	}

	// Setup is now sealed: both the page and the POST bounce to login.
	c2 := newClient(t)
	resp, err = c2.Get(ts.URL + "/setup")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
		t.Fatalf("setup page after first user: want redirect to /login, got %d", resp.StatusCode)
	}
}

func TestAdminUsersGuards(t *testing.T) {
	st := storetest.Open(t)
	ts := newServerForStore(t, st, nil)
	ctx := context.Background()

	admin, err := local.NewSource(st).CreateUser(ctx,
		"root", "root@example.com", "Root Admin", "root-pass-123", true)
	if err != nil {
		t.Fatal(err)
	}

	c := newClient(t)
	login(t, c, ts.URL, "root", "root-pass-123")
	csrf := fetchCSRFFromPage(t, c, ts.URL+"/admin/users")

	// Create a local user through the admin.
	resp, err := c.PostForm(ts.URL+"/admin/users", url.Values{
		"_csrf": {csrf}, "username": {"bob"}, "email": {"bob@example.com"},
		"name": {"Bob"}, "password": {"bob-pass-123"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("create user: want 303, got %d", resp.StatusCode)
	}
	bob, err := st.GetUserByUsername(ctx, "bob")
	if err != nil || bob.IsAdmin {
		t.Fatalf("bob not created correctly: %v admin=%v", err, bob.IsAdmin)
	}

	// Self-guard: the admin cannot drop their own admin role.
	resp, err = c.PostForm(ts.URL+"/admin/users/"+admin.ID, url.Values{
		"_csrf": {csrf}, "name": {"Root Admin"}, "email": {"root@example.com"}, "active": {"on"},
	})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(string(body), "your own") {
		t.Fatalf("self de-admin: want 422 with guard message, got %d", resp.StatusCode)
	}

	// Deactivating bob revokes his sessions.
	cBob := newClient(t)
	login(t, cBob, ts.URL, "bob", "bob-pass-123")
	resp, err = c.PostForm(ts.URL+"/admin/users/"+bob.ID, url.Values{
		"_csrf": {csrf}, "name": {"Bob"}, "email": {"bob@example.com"},
	}) // no active checkbox → deactivated
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("deactivate: want 303, got %d", resp.StatusCode)
	}
	resp, err = cBob.Get(ts.URL + "/profile")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("deactivated user still has a session: %d", resp.StatusCode)
	}

	// Local groups: create, add bob, and verify membership.
	resp, err = c.PostForm(ts.URL+"/admin/groups", url.Values{"_csrf": {csrf}, "name": {"staff"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	group, err := st.GetGroupByName(ctx, "staff")
	if err != nil || group.Source != "local" {
		t.Fatalf("group not created as local: %v %+v", err, group)
	}
	resp, err = c.PostForm(ts.URL+"/admin/groups/"+group.ID+"/members", url.Values{
		"_csrf": {csrf}, "user_id": {bob.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	members, err := st.ListGroupMembers(ctx, group.ID)
	if err != nil || len(members) != 1 || members[0].Username != "bob" {
		t.Fatalf("membership not recorded: %v %v", members, err)
	}
}

func TestAvatarEndpoint(t *testing.T) {
	ts, st := buildTestServer(t, nil)
	ctx := context.Background()

	alice, err := st.GetUserByUsername(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	photo := []byte("\xff\xd8\xff\xe0fakejpegdata")
	mime := "image/jpeg"
	if err := st.UpdateUserPhoto(ctx, sqlcgen.UpdateUserPhotoParams{
		Photo: photo, PhotoMime: &mime, UpdatedAt: time.Now().UTC(), ID: alice.ID,
	}); err != nil {
		t.Fatal(err)
	}

	c := newClient(t)
	login(t, c, ts.URL, "alice", "s3cret-pass")
	resp, err := c.Get(ts.URL + "/avatar/" + alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "image/jpeg" {
		t.Fatalf("avatar: got %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if string(body) != string(photo) {
		t.Fatal("avatar bytes mismatch")
	}
}
