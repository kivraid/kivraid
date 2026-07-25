package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kivraid/kivraid/internal/config"
)

func TestClientIP(t *testing.T) {
	trusted, err := config.ParseTrustedProxies([]string{"10.0.0.0/8", "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	withProxies := &Server{trustedProxies: trusted}
	noProxies := &Server{}

	req := func(remote, xff string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}

	cases := []struct {
		name string
		s    *Server
		r    *http.Request
		want string
	}{
		{"direct peer, no header", withProxies, req("203.0.113.7:4242", ""), "203.0.113.7"},
		{"spoofed header from untrusted peer is ignored", withProxies,
			req("203.0.113.7:4242", "1.2.3.4"), "203.0.113.7"},
		{"header honored from trusted proxy", withProxies,
			req("10.1.2.3:80", "198.51.100.9"), "198.51.100.9"},
		{"trusted hops are skipped right to left", withProxies,
			req("127.0.0.1:80", "198.51.100.9, 10.0.0.5"), "198.51.100.9"},
		{"attacker-prefixed chain still yields the real client", withProxies,
			req("10.1.2.3:80", "6.6.6.6, 198.51.100.9"), "198.51.100.9"},
		{"fully trusted chain falls back to the peer", withProxies,
			req("10.1.2.3:80", "10.9.9.9"), "10.1.2.3"},
		{"no trusted proxies configured: header always ignored", noProxies,
			req("203.0.113.7:4242", "1.2.3.4"), "203.0.113.7"},
	}
	for _, tc := range cases {
		if got := tc.s.clientIP(tc.r); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestHSTSHeader(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	get := func(baseURL string) http.Header {
		s := &Server{cfg: config.Config{BaseURL: baseURL}}
		rec := httptest.NewRecorder()
		s.secureHeaders(inner).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		return rec.Header()
	}

	if h := get("https://sso.example.com"); h.Get("Strict-Transport-Security") == "" {
		t.Error("HSTS header missing on an https instance")
	}
	if h := get("http://localhost:9000"); h.Get("Strict-Transport-Security") != "" {
		t.Error("HSTS header must not be set on a plain-http instance")
	}
}
