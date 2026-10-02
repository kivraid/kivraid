package web

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kivraid/kivraid/internal/sources/local"
)

func TestNewDeviceAlert(t *testing.T) {
	ts, st, c, csrf := adminClient(t)
	smtp := startFakeSMTP(t)
	host, port, _ := net.SplitHostPort(smtp.addr)

	post := func(path string, form url.Values) {
		t.Helper()
		form.Set("_csrf", csrf)
		resp, err := c.PostForm(ts.URL+path, form)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("POST %s: want 303, got %d", path, resp.StatusCode)
		}
	}
	post("/admin/settings/email", url.Values{
		"enabled": {"on"}, "host": {host}, "port": {port}, "encryption": {"none"},
		"from_address": {"kivraid@example.com"},
	})
	post("/admin/settings/security", url.Values{"mfa_policy": {mfaPolicyOff}, "new_device_alerts": {"on"}})

	if _, err := local.NewSource(st).CreateUser(context.Background(),
		"bob", "bob@example.com", "Bob", "bob-pass-123", false); err != nil {
		t.Fatal(err)
	}
	laptop, phone := newClient(t), newClient(t)
	login(t, laptop, ts.URL, "bob", "bob-pass-123") // first ever sign-in: no alert
	login(t, phone, ts.URL, "bob", "bob-pass-123")  // new browser: alert
	logout(t, laptop, ts.URL)
	login(t, laptop, ts.URL, "bob", "bob-pass-123") // known browser: no alert

	select {
	case <-smtp.got:
	case <-time.After(10 * time.Second):
		t.Fatal("no new-device alert was sent")
	}
	time.Sleep(300 * time.Millisecond) // let any unexpected extra message arrive
	msgs := smtp.messages()
	if len(msgs) != 1 {
		t.Fatalf("want exactly 1 alert, got %d", len(msgs))
	}
	if !strings.Contains(msgs[0], "bob@example.com") || !strings.Contains(msgs[0], "New sign-in") {
		t.Errorf("alert should go to bob and say what happened; got:\n%s", msgs[0])
	}
}
