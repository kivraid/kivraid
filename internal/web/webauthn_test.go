package web

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// TestPasskeyRegisterBegin checks the full wiring of the passkey
// registration ceremony's first leg: an authenticated user gets valid
// credential-creation options, and the CSRF header (not a form field) is
// honored so the JSON body stays intact for the finish step.
func TestPasskeyRegisterBegin(t *testing.T) {
	ts := newTestServer(t)
	c := newClient(t)
	login(t, c, ts.URL, "alice", "s3cret-pass")
	csrf := fetchCSRFFromPage(t, c, ts.URL+"/profile")

	// Without the CSRF header the state-changing call is rejected.
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/profile/passkeys/begin", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("begin without CSRF: want 403, got %d", resp.StatusCode)
	}

	// With the header it returns the creation options.
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/profile/passkeys/begin", nil)
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("begin: want 200, got %d (%s)", resp.StatusCode, body)
	}
	var out struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
			RP        struct {
				ID string `json:"id"`
			} `json:"rp"`
			User struct {
				ID string `json:"id"`
			} `json:"user"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode options: %v (%s)", err, body)
	}
	if out.PublicKey.Challenge == "" {
		t.Fatal("no challenge in creation options")
	}
	if out.PublicKey.RP.ID != "localhost" {
		t.Fatalf("relying-party ID: want localhost, got %q", out.PublicKey.RP.ID)
	}
	if out.PublicKey.User.ID == "" {
		t.Fatal("no user handle in creation options")
	}
}

// TestPasskeyLoginBeginAnonymous confirms the passwordless entry point is
// reachable without a session and returns a discoverable-login challenge.
func TestPasskeyLoginBeginAnonymous(t *testing.T) {
	ts := newTestServer(t)
	c := newClient(t)
	csrf := fetchCSRF(t, c, ts.URL+"/login")

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/login/passkey/begin", nil)
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login begin: want 200, got %d (%s)", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), `"challenge"`) {
		t.Fatalf("no challenge in assertion options: %s", body)
	}
}

// TestLoginPageOffersPasskey checks the login page ships the passkey
// affordance and the CSRF meta tag the ceremony JS reads.
func TestLoginPageOffersPasskey(t *testing.T) {
	ts := newTestServer(t)
	resp, err := http.Get(ts.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "Sign in with a passkey") {
		t.Fatal("login page missing passkey button")
	}
	if !strings.Contains(string(body), `name="csrf-token"`) {
		t.Fatal("login page missing csrf-token meta tag")
	}
}
