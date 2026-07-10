package web

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestLoginThrottledAfterRepeatedFailures(t *testing.T) {
	ts := newTestServer(t)
	c := newClient(t)
	// The identifier step reveals nothing and costs no budget; throttling
	// applies to the password step.
	csrf := identify(t, c, ts.URL, "alice", "")

	attempt := func() int {
		resp := passwordStep(t, c, ts.URL, csrf, "definitely-wrong")
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}

	// The per-username budget is 5 failures; the next attempt throttles.
	for i := range 5 {
		if code := attempt(); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: want 401, got %d", i+1, code)
		}
	}
	if code := attempt(); code != http.StatusTooManyRequests {
		t.Fatalf("throttled attempt: want 429, got %d", code)
	}

	// Even the correct password is refused while throttled.
	resp := passwordStep(t, c, ts.URL, csrf, "s3cret-pass")
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("correct password while throttled: want 429, got %d", resp.StatusCode)
	}
}

func TestForwardAuth(t *testing.T) {
	ts, _ := buildTestServer(t, []string{".home.example.com"})

	// Anonymous, host not allowlisted: plain 401.
	req, _ := http.NewRequest("GET", ts.URL+"/outpost/auth", nil)
	req.Header.Set("X-Forwarded-Host", "evil.example.net")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unlisted host: want 401, got %d", resp.StatusCode)
	}

	// Anonymous, allowlisted host: redirect to login with absolute next.
	c := newClient(t)
	req, _ = http.NewRequest("GET", ts.URL+"/outpost/auth", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "grafana.home.example.com")
	req.Header.Set("X-Forwarded-Uri", "/dashboards")
	resp, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("allowlisted host: want 302, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "/login?next=") ||
		!strings.Contains(loc, url.QueryEscape("https://grafana.home.example.com/dashboards")) {
		t.Fatalf("unexpected redirect %q", loc)
	}

	// Authenticated: 200 with identity headers.
	login(t, c, ts.URL, "alice", "s3cret-pass")
	req, _ = http.NewRequest("GET", ts.URL+"/outpost/auth", nil)
	resp, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authenticated: want 200, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Remote-User"); got != "alice" {
		t.Errorf("Remote-User: got %q", got)
	}
	if got := resp.Header.Get("Remote-Email"); got != "alice@example.com" {
		t.Errorf("Remote-Email: got %q", got)
	}
}

func TestEndSessionDestroysWebSession(t *testing.T) {
	ts := newTestServer(t)
	c := newClient(t)
	login(t, c, ts.URL, "alice", "s3cret-pass")

	// RP-initiated logout without id_token_hint: op redirects to the
	// default logout URI; the Kivraid session must be gone either way.
	resp, err := c.Get(ts.URL + "/end_session")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	resp, err = c.Get(ts.URL + "/profile")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("session survived end_session: got %d", resp.StatusCode)
	}
}

func TestAuditRecordsLoginEvents(t *testing.T) {
	ts, st := buildTestServer(t, nil)
	c := newClient(t)

	csrf := identify(t, c, ts.URL, "alice", "")
	resp := passwordStep(t, c, ts.URL, csrf, "wrong")
	resp.Body.Close()
	login(t, c, ts.URL, "alice", "s3cret-pass")

	entries, err := st.ListAudit(t.Context(), 10)
	if err != nil {
		t.Fatal(err)
	}
	actions := map[string]bool{}
	for _, e := range entries {
		actions[e.Action] = true
		if e.Actor != "alice" {
			t.Errorf("unexpected actor %q for %s", e.Actor, e.Action)
		}
	}
	if !actions["login.failed"] || !actions["login"] {
		t.Fatalf("missing audit events, got %v", actions)
	}
}
