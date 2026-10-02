package web

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The SMTP test uses the values typed in the form, and keeps them on the
// page, without saving anything.
func TestSMTPTestUsesUnsavedValues(t *testing.T) {
	ts, st, c, csrf := adminClient(t)
	resp, err := c.PostForm(ts.URL+"/admin/settings/email/test", url.Values{
		"_csrf": {csrf}, "host": {"127.0.0.1"}, "port": {"1"}, "encryption": {"none"},
		"from_address": {"noreply@example.com"}, "test_to": {"root@example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "Test failed") {
		t.Fatalf("unreachable server: want 422 with the error, got %d", resp.StatusCode)
	}
	if !strings.Contains(body, `value="127.0.0.1"`) {
		t.Error("the typed host should stay in the form after a test")
	}
	cfg, err := st.GetSMTPSettings(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Host == "127.0.0.1" {
		t.Error("a test must not save the settings")
	}
}

func TestRoutingEmptyStateWithoutProviders(t *testing.T) {
	ts, _, c, _ := adminClient(t)
	if _, body := getPage(t, c, ts.URL+"/admin/routing"); !strings.Contains(body, "Add a provider first") {
		t.Error("routing without providers should explain that one is needed")
	}
}

func TestReadableDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{
		7 * 24 * time.Hour: "7 days", 30 * time.Minute: "30 minutes", time.Hour: "1 hour", 1500 * time.Millisecond: "1.5s",
	} {
		if got := readableDuration(d); got != want {
			t.Errorf("readableDuration(%s) = %q, want %q", d, got, want)
		}
	}
	if tileClass("Grafana") != tileClass("grafana") {
		t.Error("tileClass should not depend on case")
	}
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
