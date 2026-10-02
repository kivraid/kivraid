package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/kivraid/kivraid/internal/sources/local"
)

func setMFAPolicy(t *testing.T, c *http.Client, baseURL, csrf, policy string) {
	t.Helper()
	resp, err := c.PostForm(baseURL+"/admin/settings/security", url.Values{"_csrf": {csrf}, "mfa_policy": {policy}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("save policy %s: want 303, got %d", policy, resp.StatusCode)
	}
}

func redirectTarget(t *testing.T, c *http.Client, u string) (int, string) {
	t.Helper()
	resp, err := c.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("Location")
}

// With the "admins" policy, a password-only admin session must set up a
// second factor before reaching anything else, and then continues.
func TestMFAPolicyAdminsRequiresEnrollment(t *testing.T) {
	ts, st, c, csrf := adminClient(t)
	if _, err := local.NewSource(st).CreateUser(context.Background(),
		"bob", "bob@example.com", "Bob", "bob-pass-123", false); err != nil {
		t.Fatal(err)
	}
	setMFAPolicy(t, c, ts.URL, csrf, mfaPolicyAdmins)

	status, loc := redirectTarget(t, c, ts.URL+"/admin/users")
	if status != http.StatusSeeOther || !strings.HasPrefix(loc, mfaRequiredPath+"?next=") {
		t.Fatalf("admin without 2FA: want redirect to %s, got %d %q", mfaRequiredPath, status, loc)
	}
	if _, body := getPage(t, c, ts.URL+loc); !strings.Contains(body, "Set up two-factor") {
		t.Fatal("the required page should offer enrollment")
	}

	// Non-admins are not affected by the admins-only policy.
	cb := newClient(t)
	login(t, cb, ts.URL, "bob", "bob-pass-123")
	if status, _ := getPage(t, cb, ts.URL+"/profile"); status != http.StatusOK {
		t.Fatalf("non-admin under the admins policy: want 200, got %d", status)
	}

	// Enrolling proves the factor for this session: the admin continues.
	enrollTOTP(t, ts, c, csrf)
	if status, _ := getPage(t, c, ts.URL+"/admin/users"); status != http.StatusOK {
		t.Fatalf("after enrolling: want 200, got %d", status)
	}

	// And it can no longer be turned off.
	if _, body := getPage(t, c, ts.URL+"/profile"); strings.Contains(body, "Disable two-factor") {
		t.Error("required two-factor should not offer to disable it")
	}
}

// An application can require a second factor on its own.
func TestAppRequireMFAForwardAuth(t *testing.T) {
	ts, st, c, csrf := adminClient(t)
	ctx := context.Background()
	resp, err := c.PostForm(ts.URL+"/admin/applications", url.Values{
		"_csrf": {csrf}, "kind": {"proxy"}, "name": {"Vault"}, "proxy_hosts": {"vault.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	var appID string
	if err := st.DB.QueryRowContext(ctx, `SELECT id FROM applications WHERE slug = 'vault'`).Scan(&appID); err != nil {
		t.Fatal(err)
	}
	resp, err = c.PostForm(ts.URL+"/admin/applications/"+appID, url.Values{
		"_csrf": {csrf}, "name": {"Vault"}, "slug": {"vault"}, "proxy_hosts": {"vault.example.com"},
		"access": {"everyone"}, "require_mfa": {"on"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if _, err := local.NewSource(st).CreateUser(ctx, "bob", "bob@example.com", "Bob", "bob-pass-123", false); err != nil {
		t.Fatal(err)
	}
	cb := newClient(t)
	login(t, cb, ts.URL, "bob", "bob-pass-123")
	req, _ := http.NewRequest("GET", ts.URL+"/outpost/auth", nil)
	req.Header.Set("X-Forwarded-Host", "vault.example.com")
	resp, err = cb.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || !strings.Contains(resp.Header.Get("Location"), mfaRequiredPath) {
		t.Fatalf("password-only session on a 2FA app: want redirect to %s, got %d %q",
			mfaRequiredPath, resp.StatusCode, resp.Header.Get("Location"))
	}
	// Kivraid's own pages stay reachable: the instance policy is off.
	if status, _ := getPage(t, cb, ts.URL+"/profile"); status != http.StatusOK {
		t.Fatalf("profile: want 200, got %d", status)
	}
}

func TestSecuritySettingsSave(t *testing.T) {
	ts, st, c, csrf := adminClient(t)
	resp, err := c.PostForm(ts.URL+"/admin/settings/security", url.Values{
		"_csrf": {csrf}, "mfa_policy": {mfaPolicyOff}, "key_rotation_days": {"90"}, "audit_retention_days": {"365"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	settings, err := st.GetInstanceSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if settings.KeyRotationDays != 90 || settings.AuditRetentionDays != 365 {
		t.Fatalf("saved rotation %d / retention %d", settings.KeyRotationDays, settings.AuditRetentionDays)
	}
	if _, body := getPage(t, c, ts.URL+"/admin/audit"); !strings.Contains(body, "Kept for 365 days") {
		t.Error("activity page should state the retention period")
	}
	resp, err = c.PostForm(ts.URL+"/admin/settings/security", url.Values{
		"_csrf": {csrf}, "mfa_policy": {mfaPolicyOff}, "audit_retention_days": {"7"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("unsupported retention: want 422, got %d", resp.StatusCode)
	}
}
