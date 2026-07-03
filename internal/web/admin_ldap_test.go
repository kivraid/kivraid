package web

import "testing"

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
