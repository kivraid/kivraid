package web

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestLdapFormGroupFilterValidation(t *testing.T) {
	base := ldapForm{
		Name: "d", URL: "ldap://ldap.example.com:389",
		BindDN: "cn=svc,dc=example,dc=com", BaseDN: "dc=example,dc=com",
		UserFilter: "(uid={username})",
	}

	cases := []struct {
		filter string
		ok     bool
	}{
		{"", true}, // group sync disabled
		{"(&(objectClass=groupOfNames)(member={dn}))", true},
		{"(&(objectClass=posixGroup)(memberUid={username}))", true}, // posix-only, no {dn}
		{"(|(&(objectClass=groupOfUniqueNames)(uniqueMember={dn}))(&(objectClass=posixGroup)(memberUid={username})))", true},
		{"(objectClass=posixGroup)", false}, // no placeholder at all
	}
	for _, tc := range cases {
		f := base
		f.GroupFilter = tc.filter
		err := f.validate()
		if tc.ok && err != nil {
			t.Errorf("filter %q rejected: %v", tc.filter, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("filter %q accepted but should be rejected", tc.filter)
		}
	}
}

// Testing the connection must not wipe the bind password the admin just
// typed: it is echoed back into the re-rendered form so the follow-up
// save still has it. The page must be uncacheable since it then carries
// the secret in its DOM.
func TestLdapTestPreservesBindPassword(t *testing.T) {
	ts, _, c, csrf := adminClient(t)
	const pw = "s3cr3t-bind-pw"

	resp, err := c.PostForm(ts.URL+"/admin/ldap/test", url.Values{
		"_csrf":         {csrf},
		"name":          {"Directory"},
		"url":           {"ldap://127.0.0.1:1/"}, // unreachable: the test fails, form re-renders
		"bind_dn":       {"cn=svc,dc=example,dc=com"},
		"bind_password": {pw},
		"base_dn":       {"dc=example,dc=com"},
		"user_filter":   {"(uid={username})"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("test: want 200, got %d", resp.StatusCode)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control: want no-store, got %q", cc)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `value="`+pw+`"`) {
		t.Fatal("bind password was not preserved in the re-rendered form")
	}
}
