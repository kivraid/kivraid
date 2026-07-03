package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

var (
	secretRe2       = regexp.MustCompile(`data-copy="([A-Z2-7]{16,})"`)
	recoveryBlockRe = regexp.MustCompile(`data-copy="([a-z2-7\s-]+)"`)
	recoveryRe      = regexp.MustCompile(`[a-z2-7]{4}-[a-z2-7]{4}`)
)

// enrollTOTP takes an already-logged-in client through enrollment and
// returns the shared secret and the recovery codes shown once.
func enrollTOTP(t *testing.T, ts *httptest.Server, c *http.Client, csrf string) (string, []string) {
	t.Helper()
	resp, err := c.PostForm(ts.URL+"/profile/mfa/begin", url.Values{"_csrf": {csrf}})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := secretRe2.FindSubmatch(body)
	if m == nil {
		t.Fatal("no TOTP secret on the enrollment page")
	}
	secret := string(m[1])

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp, err = c.PostForm(ts.URL+"/profile/mfa/enable", url.Values{"_csrf": {csrf}, "code": {code}})
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enable: want 200 recovery page, got %d", resp.StatusCode)
	}
	block := recoveryBlockRe.FindSubmatch(body)
	if block == nil {
		t.Fatal("no recovery-code block on the page")
	}
	codes := recoveryRe.FindAllString(string(block[1]), -1)
	if len(codes) != 10 {
		t.Fatalf("want 10 recovery codes, got %d", len(codes))
	}
	return secret, codes
}

func TestMFAEnrollAndChallenge(t *testing.T) {
	ts := newTestServer(t)
	c := newClient(t)
	login(t, c, ts.URL, "alice", "s3cret-pass")
	csrf := fetchCSRFFromPage(t, c, ts.URL+"/profile")

	secret, codes := enrollTOTP(t, ts, c, csrf)

	// A new session: password alone lands on the MFA challenge, not in.
	c2 := newClient(t)
	csrf2 := fetchCSRF(t, c2, ts.URL+"/login")
	resp, _ := c2.PostForm(ts.URL+"/login", url.Values{
		"_csrf": {csrf2}, "username": {"alice"}, "password": {"s3cret-pass"},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login/mfa" {
		t.Fatalf("password step: want 303 to /login/mfa, got %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	// The pending session grants no access.
	resp, _ = c2.Get(ts.URL + "/profile")
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("pending session must not access /profile, got %d", resp.StatusCode)
	}

	// Wrong code is rejected.
	resp, _ = c2.PostForm(ts.URL+"/login/mfa", url.Values{"_csrf": {csrf2}, "code": {"000000"}})
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong code: want 401, got %d", resp.StatusCode)
	}

	// Correct code completes login.
	code, _ := totp.GenerateCode(secret, time.Now())
	resp, _ = c2.PostForm(ts.URL+"/login/mfa", url.Values{"_csrf": {csrf2}, "code": {code}})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("correct code: want 303, got %d", resp.StatusCode)
	}
	resp, _ = c2.Get(ts.URL + "/profile")
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("after MFA: want 200, got %d", resp.StatusCode)
	}

	// A recovery code also works, once.
	c3 := newClient(t)
	csrf3 := fetchCSRF(t, c3, ts.URL+"/login")
	c3.PostForm(ts.URL+"/login", url.Values{"_csrf": {csrf3}, "username": {"alice"}, "password": {"s3cret-pass"}})
	resp, _ = c3.PostForm(ts.URL+"/login/mfa", url.Values{"_csrf": {csrf3}, "code": {codes[0]}})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("recovery code: want 303, got %d", resp.StatusCode)
	}
	// The same recovery code cannot be reused.
	c4 := newClient(t)
	csrf4 := fetchCSRF(t, c4, ts.URL+"/login")
	c4.PostForm(ts.URL+"/login", url.Values{"_csrf": {csrf4}, "username": {"alice"}, "password": {"s3cret-pass"}})
	resp, _ = c4.PostForm(ts.URL+"/login/mfa", url.Values{"_csrf": {csrf4}, "code": {codes[0]}})
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("reused recovery code: want 401, got %d", resp.StatusCode)
	}
}

func TestMFAAdminReset(t *testing.T) {
	ts, st := buildTestServer(t, nil)

	// Give alice admin so she can reach the admin area, and enroll her.
	if _, err := st.DB.Exec(`UPDATE users SET is_admin = TRUE WHERE username = 'alice'`); err != nil {
		t.Fatal(err)
	}
	c := newClient(t)
	login(t, c, ts.URL, "alice", "s3cret-pass")
	csrf := fetchCSRFFromPage(t, c, ts.URL+"/profile")
	enrollTOTP(t, ts, c, csrf)

	alice, _ := st.GetUserByUsername(t.Context(), "alice")
	if !alice.TotpEnabled {
		t.Fatal("alice should have TOTP enabled")
	}

	// Admin resets her MFA.
	resp, err := c.PostForm(ts.URL+"/admin/users/"+alice.ID+"/mfa/reset", url.Values{"_csrf": {csrf}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("reset: want 303, got %d", resp.StatusCode)
	}
	alice, _ = st.GetUserByUsername(t.Context(), "alice")
	if alice.TotpEnabled || len(alice.TotpSecretEnc) != 0 {
		t.Fatal("MFA should be cleared after reset")
	}

	// Password alone now signs in (no challenge).
	c2 := newClient(t)
	csrf2 := fetchCSRF(t, c2, ts.URL+"/login")
	resp, _ = c2.PostForm(ts.URL+"/login", url.Values{"_csrf": {csrf2}, "username": {"alice"}, "password": {"s3cret-pass"}})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
		t.Fatalf("after reset password login: want 303 to /, got %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}
