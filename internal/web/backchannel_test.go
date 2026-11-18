package web

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/kivraid/kivraid/internal/sources/local"
	"github.com/kivraid/kivraid/internal/store"
	"github.com/kivraid/kivraid/internal/store/storetest"
)

// logoutReceiver is a relying party's back-channel logout endpoint that
// hands every logout token it receives to the test.
func logoutReceiver(t *testing.T) (uri string, tokens <-chan string) {
	t.Helper()
	ch := make(chan string, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		ch <- r.PostFormValue("logout_token")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/backchannel-logout", ch
}

func awaitLogoutToken(t *testing.T, tokens <-chan string) string {
	t.Helper()
	select {
	case tok := <-tokens:
		return tok
	case <-time.After(5 * time.Second):
		t.Fatal("no logout token received")
		return ""
	}
}

// verifyLogoutToken checks a logout token's signature against the
// issuer's JWKS and returns its claims.
func verifyLogoutToken(t *testing.T, issuer, raw string) oidc.LogoutTokenClaims {
	t.Helper()
	resp, err := http.Get(issuer + "/keys")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		t.Fatal(err)
	}
	jws, err := jose.ParseSignedCompact(raw, []jose.SignatureAlgorithm{jose.ES256, jose.RS256})
	if err != nil {
		t.Fatalf("parse logout token: %v", err)
	}
	hdr := jws.Signatures[0].Header
	if typ, _ := hdr.ExtraHeaders["typ"].(string); typ != "logout+jwt" {
		t.Errorf("typ header: want logout+jwt, got %q", typ)
	}
	keys := jwks.Key(hdr.KeyID)
	if len(keys) == 0 {
		t.Fatalf("logout token signed with unknown key %q", hdr.KeyID)
	}
	payload, err := jws.Verify(keys[0])
	if err != nil {
		t.Fatalf("logout token signature: %v", err)
	}
	var claims oidc.LogoutTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != issuer || !slices.Contains(claims.Audience, testClientID) {
		t.Errorf("iss/aud: got %q %v", claims.Issuer, claims.Audience)
	}
	if _, ok := claims.Events["http://schemas.openid.net/event/backchannel-logout"]; !ok {
		t.Errorf("missing back-channel logout event: %v", claims.Events)
	}
	if _, ok := claims.Claims["nonce"]; ok {
		t.Error("a logout token must not carry a nonce")
	}
	if time.Until(claims.Expiration.AsTime()) <= 0 || claims.JWTID == "" {
		t.Errorf("exp/jti: got %v %q", claims.Expiration.AsTime(), claims.JWTID)
	}
	return claims
}

func setBackchannelURI(t *testing.T, st *store.Store, uri string) {
	t.Helper()
	if _, err := st.DB.Exec(`UPDATE providers SET backchannel_logout_uri = $1 WHERE id = 'prov1'`, uri); err != nil {
		t.Fatal(err)
	}
}

// signIn runs the code flow in browser c and returns the ID token claims.
func signIn(t *testing.T, issuer string, c *http.Client) *oidc.Tokens[*oidc.IDTokenClaims] {
	t.Helper()
	ctx := context.Background()
	relying, err := rp.NewRelyingPartyOIDC(ctx, issuer, testClientID, testClientSecret,
		testRedirectURI, []string{"openid", "profile", "offline_access"})
	if err != nil {
		t.Fatal(err)
	}
	code := browseAuthFlowWith(t, c, rp.AuthURL("teststate", relying))
	tokens, err := rp.CodeExchange[*oidc.IDTokenClaims](ctx, code, relying)
	if err != nil {
		t.Fatalf("code exchange: %v", err)
	}
	if tokens.IDTokenClaims.SessionID == "" {
		t.Fatal("the ID token should carry a sid claim")
	}
	// An ID token minted on refresh keeps the session's sid.
	refreshed, err := rp.RefreshTokens[*oidc.IDTokenClaims](ctx, relying, tokens.RefreshToken, "", "")
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if refreshed.IDTokenClaims == nil || refreshed.IDTokenClaims.SessionID != tokens.IDTokenClaims.SessionID {
		t.Errorf("refreshed ID token sid: want %q, got %+v", tokens.IDTokenClaims.SessionID, refreshed.IDTokenClaims)
	}
	return tokens
}

func TestBackchannelLogoutOnSignOut(t *testing.T) {
	issuer, st := startIssuer(t, false)
	uri, received := logoutReceiver(t)
	setBackchannelURI(t, st, uri)

	// Discovery advertises the capability.
	resp, err := http.Get(issuer + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	var disco oidc.DiscoveryConfiguration
	json.NewDecoder(resp.Body).Decode(&disco)
	resp.Body.Close()
	if !disco.BackChannelLogoutSupported || !disco.BackChannelLogoutSessionSupported {
		t.Error("discovery should advertise back-channel logout with sid")
	}

	browser := newClient(t)
	tokens := signIn(t, issuer, browser)

	// Signing out of Kivraid sends one logout token for that session.
	csrf := fetchCSRFFromPage(t, browser, issuer+"/profile")
	out, err := browser.PostForm(issuer+"/logout", url.Values{"_csrf": {csrf}})
	if err != nil {
		t.Fatal(err)
	}
	out.Body.Close()
	claims := verifyLogoutToken(t, issuer, awaitLogoutToken(t, received))
	if claims.Subject != tokens.IDTokenClaims.Subject || claims.SessionID != tokens.IDTokenClaims.SessionID {
		t.Errorf("logout token sub/sid: want %q/%q, got %q/%q",
			tokens.IDTokenClaims.Subject, tokens.IDTokenClaims.SessionID, claims.Subject, claims.SessionID)
	}

	// The session is forgotten: nothing is sent twice.
	var n int
	if err := st.DB.QueryRow(`SELECT COUNT(*) FROM oidc_sessions`).Scan(&n); err != nil || n != 0 {
		t.Errorf("oidc_sessions after logout: %d rows (err %v)", n, err)
	}
}

func TestBackchannelLogoutOnDeactivation(t *testing.T) {
	issuer, st := startIssuer(t, false)
	uri, received := logoutReceiver(t)
	setBackchannelURI(t, st, uri)
	ctx := context.Background()

	// Alice signs in to the application from two browsers.
	first := signIn(t, issuer, newClient(t))
	second := signIn(t, issuer, newClient(t))
	if first.IDTokenClaims.SessionID == second.IDTokenClaims.SessionID {
		t.Fatal("two browsers should have two sids")
	}

	if _, err := local.NewSource(st).CreateUser(ctx, "root", "root@example.com", "Root", "root-pass-123", true); err != nil {
		t.Fatal(err)
	}
	admin := newClient(t)
	login(t, admin, issuer, "root", "root-pass-123")
	csrf := fetchCSRFFromPage(t, admin, issuer+"/admin/users")
	alice, err := st.GetUserByUsername(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	// Deactivating the account (active unchecked) signs both sessions out.
	resp, err := admin.PostForm(issuer+"/admin/users/"+alice.ID, url.Values{
		"_csrf": {csrf}, "name": {alice.Name}, "email": {alice.Email},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("deactivate: want 303, got %d", resp.StatusCode)
	}
	got := map[string]bool{}
	for range 2 {
		claims := verifyLogoutToken(t, issuer, awaitLogoutToken(t, received))
		if claims.Subject != alice.ID {
			t.Errorf("logout token sub: want %q, got %q", alice.ID, claims.Subject)
		}
		got[claims.SessionID] = true
	}
	if !got[first.IDTokenClaims.SessionID] || !got[second.IDTokenClaims.SessionID] {
		t.Errorf("want a logout token per session, got sids %v", got)
	}
}

// An application without a back-channel logout URI is left alone.
func TestBackchannelLogoutNotConfigured(t *testing.T) {
	issuer, _ := startIssuer(t, false)
	_, received := logoutReceiver(t)
	browser := newClient(t)
	signIn(t, issuer, browser)
	csrf := fetchCSRFFromPage(t, browser, issuer+"/profile")
	out, err := browser.PostForm(issuer+"/logout", url.Values{"_csrf": {csrf}})
	if err != nil {
		t.Fatal(err)
	}
	out.Body.Close()
	select {
	case <-received:
		t.Fatal("no logout token expected without a back-channel logout URI")
	case <-time.After(300 * time.Millisecond):
	}
}

// The back-channel logout URI is set on creation, editable, and validated.
func TestBackchannelLogoutURIForm(t *testing.T) {
	st := storetest.Open(t)
	ts := newServerForStore(t, st, nil)
	ctx := context.Background()
	if _, err := local.NewSource(st).CreateUser(ctx, "root", "root@example.com", "Root", "root-pass-123", true); err != nil {
		t.Fatal(err)
	}
	c := newClient(t)
	login(t, c, ts.URL, "root", "root-pass-123")
	csrf := fetchCSRFFromPage(t, c, ts.URL+"/admin/applications")

	form := url.Values{
		"_csrf": {csrf}, "name": {"Immich"}, "client_type": {"confidential"},
		"redirect_uris":          {"https://immich.example.com/auth/login"},
		"backchannel_logout_uri": {"https://immich.example.com/api/oauth/backchannel-logout"},
	}
	resp, err := c.PostForm(ts.URL+"/admin/applications", form)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	var appID, uri string
	if err := st.DB.QueryRowContext(ctx, `SELECT a.id, p.backchannel_logout_uri FROM applications a
		JOIN providers p ON p.application_id = a.id WHERE a.slug = 'immich'`).Scan(&appID, &uri); err != nil {
		t.Fatal(err)
	}
	if uri != "https://immich.example.com/api/oauth/backchannel-logout" {
		t.Errorf("stored URI on creation: got %q", uri)
	}

	detailURL := ts.URL + "/admin/applications/" + appID
	form.Set("slug", "immich")
	form.Set("backchannel_logout_uri", "/relative/path")
	resp, err = c.PostForm(detailURL, form)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode == http.StatusSeeOther || !strings.Contains(string(body), "back-channel logout URI must be an absolute") {
		t.Fatalf("relative URI: want a validation error, got %d", resp.StatusCode)
	}

	// Clearing it turns the feature off for the application.
	form.Set("backchannel_logout_uri", "")
	resp, err = c.PostForm(detailURL, form)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if err := st.DB.QueryRowContext(ctx, `SELECT backchannel_logout_uri FROM providers p
		JOIN applications a ON p.application_id = a.id WHERE a.id = $1`, appID).Scan(&uri); err != nil || uri != "" {
		t.Errorf("cleared URI: got %q (err %v)", uri, err)
	}
}
