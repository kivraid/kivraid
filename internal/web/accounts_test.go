package web

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/kivraid/kivraid/internal/store"
)

const chooserMarker = "Choose an account"

// getPage fetches a page and returns its status and body.
func getPage(t *testing.T, c *http.Client, u string) (int, string) {
	t.Helper()
	resp, err := c.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// logout ends the current session; the account cookie survives it.
func logout(t *testing.T, c *http.Client, baseURL string) {
	t.Helper()
	csrf := fetchCSRFFromPage(t, c, baseURL+"/profile")
	resp, err := c.PostForm(baseURL+"/logout", url.Values{"_csrf": {csrf}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func aliceID(t *testing.T, st *store.Store) string {
	t.Helper()
	u, err := st.GetUserByUsername(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	return u.ID
}

func TestAccountChooserAfterSignIn(t *testing.T) {
	ts, st := buildTestServer(t, nil)
	c := newClient(t)

	// A browser that never signed in gets the plain identifier form.
	if _, body := getPage(t, c, ts.URL+"/login"); strings.Contains(body, chooserMarker) {
		t.Fatal("fresh browser should not see the account chooser")
	}

	login(t, c, ts.URL, "alice", "s3cret-pass")
	logout(t, c, ts.URL)

	_, body := getPage(t, c, ts.URL+"/login")
	if !strings.Contains(body, chooserMarker) || !strings.Contains(body, "Alice Liddell") ||
		!strings.Contains(body, "alice@example.com") {
		t.Fatalf("chooser missing the remembered account; body:\n%s", body)
	}
	if strings.Contains(body, `name="username"`) {
		t.Error("chooser should replace the identifier form")
	}

	// "Use another account" falls back to the identifier form.
	if _, body := getPage(t, c, ts.URL+"/login?other=1"); strings.Contains(body, chooserMarker) ||
		!strings.Contains(body, `name="username"`) {
		t.Error("?other=1 should show the identifier form")
	}

	// Picking the account goes to the password step, greeted by name.
	csrf := fetchCSRF(t, c, ts.URL+"/login")
	resp, err := c.PostForm(ts.URL+"/login/account", url.Values{"_csrf": {csrf}, "account": {aliceID(t, st)}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login/password" {
		t.Fatalf("pick account: want 303 to /login/password, got %d to %q",
			resp.StatusCode, resp.Header.Get("Location"))
	}
	if _, body := getPage(t, c, ts.URL+"/login/password"); !strings.Contains(body, "Welcome back, Alice Liddell") {
		t.Fatalf("password step should greet the picked account; body:\n%s", body)
	}
	resp = passwordStep(t, c, ts.URL, csrf, "s3cret-pass")
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
		t.Fatalf("sign in: want 303 to /, got %d to %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

// The password step must reveal nothing to a browser that never signed in
// as the account: no name, no avatar, whatever the identifier.
func TestPasswordStepNoGreetingForUnknownBrowser(t *testing.T) {
	ts := newTestServer(t)
	c := newClient(t)

	identify(t, c, ts.URL, "alice@example.com", "")
	_, body := getPage(t, c, ts.URL+"/login/password")
	if strings.Contains(body, "Welcome back") || strings.Contains(body, "Alice Liddell") {
		t.Fatal("password step leaked the account identity to an unknown browser")
	}
}

// Typing the identifier of a remembered account greets it like a pick.
func TestPasswordStepGreetsTypedRememberedAccount(t *testing.T) {
	ts := newTestServer(t)
	c := newClient(t)
	login(t, c, ts.URL, "alice", "s3cret-pass")
	logout(t, c, ts.URL)

	identify(t, c, ts.URL, "ALICE@example.com", "")
	if _, body := getPage(t, c, ts.URL+"/login/password"); !strings.Contains(body, "Welcome back, Alice Liddell") {
		t.Fatal("typed remembered identifier should be greeted")
	}
}

// Only accounts in this browser's sealed cookie can be picked.
func TestAccountPickRejectsUnrememberedID(t *testing.T) {
	ts, st := buildTestServer(t, nil)
	c := newClient(t)

	csrf := fetchCSRF(t, c, ts.URL+"/login")
	resp, err := c.PostForm(ts.URL+"/login/account", url.Values{"_csrf": {csrf}, "account": {aliceID(t, st)}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/login?") {
		t.Fatalf("unremembered pick: want a redirect back to /login, got %d to %q", resp.StatusCode, loc)
	}

	// A forged cookie is ignored too.
	u, _ := url.Parse(ts.URL)
	c.Jar.SetCookies(u, []*http.Cookie{{Name: accountsCookie, Value: "forged", Path: "/"}})
	if _, body := getPage(t, c, ts.URL+"/login"); strings.Contains(body, chooserMarker) {
		t.Fatal("forged account cookie should be ignored")
	}
}

func TestAccountForget(t *testing.T) {
	ts, st := buildTestServer(t, nil)
	c := newClient(t)
	login(t, c, ts.URL, "alice", "s3cret-pass")
	logout(t, c, ts.URL)

	csrf := fetchCSRF(t, c, ts.URL+"/login")
	resp, err := c.PostForm(ts.URL+"/login/account/forget", url.Values{"_csrf": {csrf}, "account": {aliceID(t, st)}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if _, body := getPage(t, c, ts.URL+"/login"); strings.Contains(body, chooserMarker) {
		t.Fatal("forgotten account still offered")
	}
}

// Deactivated accounts drop out of the chooser.
func TestAccountChooserSkipsInactive(t *testing.T) {
	ts, st := buildTestServer(t, nil)
	c := newClient(t)
	login(t, c, ts.URL, "alice", "s3cret-pass")
	logout(t, c, ts.URL)

	if _, err := st.DB.Exec(`UPDATE users SET active = $1 WHERE username = 'alice'`, false); err != nil {
		t.Fatal(err)
	}
	if _, body := getPage(t, c, ts.URL+"/login"); strings.Contains(body, chooserMarker) {
		t.Fatal("inactive account still offered")
	}
}
