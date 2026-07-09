package web

import (
	"strings"
	"testing"
)

func TestRedactDSN(t *testing.T) {
	cases := []struct {
		driver, dsn, wantContains, wantAbsent string
	}{
		// SQLite DSNs are file paths — shown as-is, nothing to redact.
		{"sqlite", "kivraid.db?_pragma=busy_timeout(5000)", "kivraid.db", ""},
		// Postgres URL form: password stripped, host/db kept.
		{"postgres", "postgres://kivraid:s3cret@db:5432/kivraid?sslmode=disable", "db:5432/kivraid", "s3cret"},
		// Postgres keyword form: password value masked.
		{"postgres", "host=db user=kivraid password=s3cret dbname=kivraid", "host=db", "s3cret"},
		// No credentials: unchanged, no crash.
		{"postgres", "postgres://db:5432/kivraid", "db:5432/kivraid", ""},
	}
	for _, tc := range cases {
		got := redactDSN(tc.driver, tc.dsn)
		if tc.wantContains != "" && !strings.Contains(got, tc.wantContains) {
			t.Errorf("redactDSN(%q): want contains %q, got %q", tc.dsn, tc.wantContains, got)
		}
		if tc.wantAbsent != "" && strings.Contains(got, tc.wantAbsent) {
			t.Errorf("redactDSN(%q): leaked secret %q in %q", tc.dsn, tc.wantAbsent, got)
		}
	}
}
