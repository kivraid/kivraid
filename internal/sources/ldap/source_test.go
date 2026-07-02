package ldap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jimlambrt/gldap"

	"github.com/lporcheron/kivraid/internal/secrets"
	"github.com/lporcheron/kivraid/internal/sources/local"
	"github.com/lporcheron/kivraid/internal/store"
	"github.com/lporcheron/kivraid/internal/store/sqlcgen"
	"github.com/lporcheron/kivraid/internal/store/storetest"
)

const (
	testBaseDN     = "dc=example,dc=org"
	testServiceDN  = "cn=kivraid," + testBaseDN
	testServicePW  = "svc-secret"
	testAliceDN    = "uid=alice,ou=people," + testBaseDN
	testAlicePW    = "alice-pass"
	testBobDN      = "uid=bob,ou=people," + testBaseDN
	testBobPW      = "bob-pass"
	testSealSecret = "0123456789abcdef0123456789abcdef"
)

// startFakeDirectory runs an in-process LDAP server that mimics a small
// OpenLDAP tree: a service account, two users and two groups.
func startFakeDirectory(t *testing.T) string {
	t.Helper()

	// Reserve a free port; gldap needs an explicit address.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()

	server, err := gldap.NewServer()
	if err != nil {
		t.Fatal(err)
	}

	mux, err := gldap.NewMux()
	if err != nil {
		t.Fatal(err)
	}
	// boundDNs tracks which DN each connection is bound as, so the
	// password-modify handler can require a user bind.
	var mu sync.Mutex
	boundDNs := map[int]string{}
	mux.Bind(func(w *gldap.ResponseWriter, r *gldap.Request) {
		resp := r.NewBindResponse(gldap.WithResponseCode(gldap.ResultInvalidCredentials))
		defer func() { w.Write(resp) }()
		m, err := r.GetSimpleBindMessage()
		if err != nil {
			return
		}
		creds := map[string]string{
			testServiceDN: testServicePW,
			testAliceDN:   testAlicePW,
			testBobDN:     testBobPW,
		}
		if pw, ok := creds[m.UserName]; ok && pw == string(m.Password) && pw != "" {
			resp.SetResultCode(gldap.ResultSuccess)
			mu.Lock()
			boundDNs[r.ConnectionID()] = m.UserName
			mu.Unlock()
		}
	})
	mux.ExtendedOperation(func(w *gldap.ResponseWriter, r *gldap.Request) {
		resp := r.NewExtendedResponse(gldap.WithResponseCode(gldap.ResultUnwillingToPerform))
		mu.Lock()
		dn := boundDNs[r.ConnectionID()]
		mu.Unlock()
		if dn == testAliceDN || dn == testBobDN {
			resp.SetResultCode(gldap.ResultSuccess)
		}
		w.Write(resp)
	}, gldap.ExtendedOperationPasswordModify)
	mux.Search(func(w *gldap.ResponseWriter, r *gldap.Request) {
		m, err := r.GetSearchMessage()
		if err != nil {
			w.Write(r.NewSearchDoneResponse())
			return
		}
		users := map[string]map[string][]string{
			"alice": {
				"uid":  {"alice"},
				"mail": {"Alice@example.org"},
				"cn":   {"Alice Directory"},
			},
			"bob": {
				"uid":  {"bob"},
				"mail": {"bob@example.org"},
				"cn":   {"Bob Directory"},
			},
		}
		for username, attrs := range users {
			if m.Filter == fmt.Sprintf("(&(objectClass=person)(uid=%s))", username) {
				w.Write(r.NewSearchResponseEntry(
					fmt.Sprintf("uid=%s,ou=people,%s", username, testBaseDN),
					gldap.WithAttributes(attrs),
				))
			}
		}
		if strings.Contains(m.Filter, "member="+testAliceDN) {
			for _, g := range []string{"infra", "dev"} {
				w.Write(r.NewSearchResponseEntry(
					fmt.Sprintf("cn=%s,ou=groups,%s", g, testBaseDN),
					gldap.WithAttributes(map[string][]string{"cn": {g}}),
				))
			}
		}
		w.Write(r.NewSearchDoneResponse(gldap.WithResponseCode(gldap.ResultSuccess)))
	})
	if err := server.Router(mux); err != nil {
		t.Fatal(err)
	}

	go server.Run(addr)
	t.Cleanup(func() { server.Stop() })

	// Wait until the server accepts connections.
	for range 100 {
		conn, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			conn.Close()
			return addr
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("fake LDAP server did not start on %s", addr)
	return ""
}

func newTestManager(t *testing.T) (*Manager, *store.Store) {
	t.Helper()
	ctx := context.Background()
	addr := startFakeDirectory(t)

	st := storetest.Open(t)

	sealKey := secrets.DeriveKey(testSealSecret, "ldap-bind-passwords")
	sealed, err := secrets.Seal(sealKey, []byte(testServicePW))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := st.CreateLdapSource(ctx, sqlcgen.CreateLdapSourceParams{
		ID: "src1", Name: "Test Directory", Url: "ldap://" + addr,
		BindDn: testServiceDN, BindPasswordEnc: sealed, BaseDn: testBaseDN,
		UserFilter:   "(&(objectClass=person)(uid={username}))",
		UsernameAttr: "uid", EmailAttr: "mail", NameAttr: "cn",
		GroupFilter: "(&(objectClass=groupOfNames)(member={dn}))", GroupNameAttr: "cn",
		PasswordWriteback: true,
		Enabled:           true, Position: 0, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewManager(st, sealKey, log), st
}

func TestAuthenticateCreatesShadowUser(t *testing.T) {
	m, st := newTestManager(t)
	ctx := context.Background()

	user, err := m.Authenticate(ctx, "alice", testAlicePW)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if user.Source != "ldap" || user.PasswordHash != nil {
		t.Fatalf("shadow user malformed: source=%q hash=%v", user.Source, user.PasswordHash)
	}
	if user.Email != "alice@example.org" || user.Name != "Alice Directory" {
		t.Errorf("profile not mirrored: %q %q", user.Email, user.Name)
	}
	if user.LdapDn == nil || *user.LdapDn != testAliceDN {
		t.Errorf("ldap_dn not recorded: %v", user.LdapDn)
	}

	groups, err := st.ListUserGroups(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(groups))
	for i, g := range groups {
		names[i] = g.Name
	}
	if len(names) != 2 || names[0] != "dev" || names[1] != "infra" {
		t.Errorf("groups not synced: %v", names)
	}

	// Second login reuses the shadow row instead of duplicating it.
	again, err := m.Authenticate(ctx, "alice", testAlicePW)
	if err != nil {
		t.Fatalf("second authenticate: %v", err)
	}
	if again.ID != user.ID {
		t.Fatalf("shadow user duplicated: %s != %s", again.ID, user.ID)
	}
}

func TestAuthenticateRejectsBadPassword(t *testing.T) {
	m, _ := newTestManager(t)
	ctx := context.Background()

	if _, err := m.Authenticate(ctx, "alice", "wrong"); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("want ErrBadCredentials, got %v", err)
	}
	if _, err := m.Authenticate(ctx, "nobody", "whatever"); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("unknown user: want ErrBadCredentials, got %v", err)
	}
	if _, err := m.Authenticate(ctx, "alice", ""); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("empty password: want ErrBadCredentials, got %v", err)
	}
}

func TestChangePasswordWriteback(t *testing.T) {
	m, st := newTestManager(t)
	ctx := context.Background()

	user, err := m.Authenticate(ctx, "alice", testAlicePW)
	if err != nil {
		t.Fatal(err)
	}

	// Wrong current password: the user bind fails, nothing is written.
	if err := m.ChangePassword(ctx, user, "wrong", "brand-new-pass"); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("wrong current: want ErrBadCredentials, got %v", err)
	}

	// Correct current password: RFC 3062 password modify succeeds.
	if err := m.ChangePassword(ctx, user, testAlicePW, "brand-new-pass"); err != nil {
		t.Fatalf("change password: %v", err)
	}

	// Write-back disabled on the source: refused before contacting LDAP.
	if _, err := st.DB.Exec(`UPDATE ldap_sources SET password_writeback = FALSE`); err != nil {
		t.Fatal(err)
	}
	if err := m.ChangePassword(ctx, user, testAlicePW, "another-pass"); !errors.Is(err, ErrWritebackDisabled) {
		t.Fatalf("want ErrWritebackDisabled, got %v", err)
	}
}

func TestAuthenticateDeniesUsernameCollision(t *testing.T) {
	m, st := newTestManager(t)
	ctx := context.Background()

	// A local account already owns the username "bob".
	if _, err := local.NewSource(st).CreateUser(ctx,
		"bob", "bob@local.test", "Local Bob", "local-pass", false); err != nil {
		t.Fatal(err)
	}

	// Directory bob authenticates fine against LDAP, but must be denied to
	// avoid shadowing the local identity.
	if _, err := m.Authenticate(ctx, "bob", testBobPW); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("want ErrBadCredentials on collision, got %v", err)
	}
}
