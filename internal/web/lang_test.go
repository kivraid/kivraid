package web

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func getWithHeaders(t *testing.T, c *http.Client, u string, headers map[string]string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", u, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestLanguageFromBrowserAndPicker(t *testing.T) {
	ts := newTestServer(t)
	c := newClient(t)

	// The browser's Accept-Language picks French...
	_, body := getWithHeaders(t, c, ts.URL+"/login", map[string]string{"Accept-Language": "fr-FR,fr;q=0.9,en;q=0.5"})
	if !strings.Contains(body, `<html lang="fr">`) || !strings.Contains(body, "Continuer") {
		t.Fatal("Accept-Language fr should render the sign-in page in French")
	}
	// ...English stays the default...
	if _, body = getPage(t, c, ts.URL+"/login"); !strings.Contains(body, "Username or email") {
		t.Fatal("no Accept-Language should render English")
	}
	// ...and the picker's cookie wins over the browser.
	resp, err := c.Get(ts.URL + "/lang?set=fr&next=" + url.QueryEscape("/login"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
		t.Fatalf("picker: want 303 back to /login, got %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	_, body = getWithHeaders(t, c, ts.URL+"/login", map[string]string{"Accept-Language": "en"})
	if !strings.Contains(body, "Continuer") {
		t.Fatal("the language cookie should override Accept-Language")
	}
}

// A signed-in user's choice is saved on the account and follows them to a
// new browser at sign-in.
func TestLanguagePreferenceFollowsAccount(t *testing.T) {
	ts, st := buildTestServer(t, nil)
	c := newClient(t)
	login(t, c, ts.URL, "alice", "s3cret-pass")
	resp, err := c.Get(ts.URL + "/lang?set=fr&next=/profile")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	u, err := st.GetUserByUsername(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if u.Locale != "fr" {
		t.Fatalf("locale not saved on the account: %q", u.Locale)
	}

	other := newClient(t)
	login(t, other, ts.URL, "alice", "s3cret-pass")
	if _, body := getPage(t, other, ts.URL+"/"); !strings.Contains(body, `<html lang="fr">`) {
		t.Fatal("a new browser should switch to the account's language at sign-in")
	}
}
