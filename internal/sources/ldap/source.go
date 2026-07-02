// Package ldap implements LDAP directories as a live user source: users
// authenticate with a bind, profile and groups are read at login, and a
// local shadow row (never the password) is maintained for identity,
// sessions and group membership. Targets OpenLDAP and LLDAP.
package ldap

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"

	"github.com/lporcheron/kivraid/internal/secrets"
	"github.com/lporcheron/kivraid/internal/store"
	"github.com/lporcheron/kivraid/internal/store/sqlcgen"
)

// ErrBadCredentials mirrors local.ErrBadCredentials: every failure mode
// collapses into one indistinguishable error.
var ErrBadCredentials = errors.New("invalid username or password")

const dialTimeout = 5 * time.Second

var netDialer = net.Dialer{Timeout: dialTimeout}

type Manager struct {
	store   *store.Store
	sealKey [32]byte
	log     *slog.Logger
}

func NewManager(st *store.Store, sealKey [32]byte, log *slog.Logger) *Manager {
	return &Manager{store: st, sealKey: sealKey, log: log}
}

// SealKey returns the key used to encrypt bind passwords at rest; the
// admin UI needs it when saving sources.
func (m *Manager) SealKey() [32]byte { return m.sealKey }

// Authenticate tries every enabled source in order and returns the shadow
// user on the first success.
func (m *Manager) Authenticate(ctx context.Context, username, password string) (sqlcgen.User, error) {
	if password == "" {
		// An empty password would turn the user bind into an anonymous
		// bind, which many directories accept. Never forward it.
		return sqlcgen.User{}, ErrBadCredentials
	}
	sources, err := m.store.ListEnabledLdapSources(ctx)
	if err != nil {
		return sqlcgen.User{}, err
	}
	for _, src := range sources {
		user, err := m.authenticateAgainst(ctx, src, username, password)
		if err == nil {
			return user, nil
		}
		if !errors.Is(err, ErrBadCredentials) {
			// Operational failure (network, misconfig): log and keep
			// trying the remaining sources.
			m.log.Warn("ldap source error", "source", src.Name, "err", err)
		}
	}
	return sqlcgen.User{}, ErrBadCredentials
}

type Entry struct {
	DN       string
	Username string
	Email    string
	Name     string
	Groups   []string
}

func (m *Manager) authenticateAgainst(ctx context.Context, src sqlcgen.LdapSource, username, password string) (sqlcgen.User, error) {
	entry, err := m.lookupAndBind(src, username, password)
	if err != nil {
		return sqlcgen.User{}, err
	}
	return m.upsertShadowUser(ctx, src, entry)
}

// lookupAndBind performs the LDAP conversation: service bind, user
// search, group search, then a bind as the user to verify the password.
func (m *Manager) lookupAndBind(src sqlcgen.LdapSource, username, password string) (*Entry, error) {
	conn, err := m.Connect(src)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	entry, err := m.findUser(conn, src, username)
	if err != nil {
		return nil, err
	}
	entry.Groups, err = m.findGroups(conn, src, entry.DN)
	if err != nil {
		return nil, err
	}

	// The user bind is last: it leaves the connection authenticated as
	// the user, which is fine because it is closed right after.
	if err := conn.Bind(entry.DN, password); err != nil {
		return nil, ErrBadCredentials
	}
	return entry, nil
}

// Connect dials the source and binds with the service account.
func (m *Manager) Connect(src sqlcgen.LdapSource) (*goldap.Conn, error) {
	u, err := url.Parse(src.Url)
	if err != nil {
		return nil, fmt.Errorf("invalid url: %w", err)
	}
	tlsConfig := &tls.Config{
		ServerName:         u.Hostname(),
		InsecureSkipVerify: src.SkipTlsVerify,
	}
	conn, err := goldap.DialURL(src.Url,
		goldap.DialWithDialer(&netDialer),
		goldap.DialWithTLSConfig(tlsConfig))
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	if src.StartTls {
		if err := conn.StartTLS(tlsConfig); err != nil {
			conn.Close()
			return nil, fmt.Errorf("starttls: %w", err)
		}
	}
	bindPassword, err := secrets.Open(m.sealKey, src.BindPasswordEnc)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("decrypt bind password: %w", err)
	}
	if err := conn.Bind(src.BindDn, string(bindPassword)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("service bind: %w", err)
	}
	return conn, nil
}

// FindUser searches the directory for username; exported for the admin
// "test connection" action.
func (m *Manager) FindUser(src sqlcgen.LdapSource, username string) (*Entry, error) {
	conn, err := m.Connect(src)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	entry, err := m.findUser(conn, src, username)
	if err != nil {
		return nil, err
	}
	entry.Groups, err = m.findGroups(conn, src, entry.DN)
	return entry, err
}

func (m *Manager) findUser(conn *goldap.Conn, src sqlcgen.LdapSource, username string) (*Entry, error) {
	filter := strings.ReplaceAll(src.UserFilter, "{username}", goldap.EscapeFilter(username))
	res, err := conn.Search(goldap.NewSearchRequest(
		src.BaseDn, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
		2, int(dialTimeout/time.Second), false,
		filter,
		[]string{src.UsernameAttr, src.EmailAttr, src.NameAttr},
		nil,
	))
	if err != nil {
		return nil, fmt.Errorf("user search: %w", err)
	}
	if len(res.Entries) == 0 {
		return nil, ErrBadCredentials
	}
	if len(res.Entries) > 1 {
		return nil, fmt.Errorf("user filter matched %d entries for %q", len(res.Entries), username)
	}
	e := res.Entries[0]
	entry := &Entry{
		DN:       e.DN,
		Username: strings.ToLower(e.GetAttributeValue(src.UsernameAttr)),
		Email:    strings.ToLower(e.GetAttributeValue(src.EmailAttr)),
		Name:     e.GetAttributeValue(src.NameAttr),
	}
	if entry.Username == "" {
		return nil, fmt.Errorf("entry %s has no %s attribute", e.DN, src.UsernameAttr)
	}
	if entry.Name == "" {
		entry.Name = entry.Username
	}
	return entry, nil
}

func (m *Manager) findGroups(conn *goldap.Conn, src sqlcgen.LdapSource, userDN string) ([]string, error) {
	if src.GroupFilter == "" {
		return nil, nil
	}
	filter := strings.ReplaceAll(src.GroupFilter, "{dn}", goldap.EscapeFilter(userDN))
	res, err := conn.Search(goldap.NewSearchRequest(
		src.BaseDn, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
		0, int(dialTimeout/time.Second), false,
		filter,
		[]string{src.GroupNameAttr},
		nil,
	))
	if err != nil {
		return nil, fmt.Errorf("group search: %w", err)
	}
	var groups []string
	for _, e := range res.Entries {
		if name := e.GetAttributeValue(src.GroupNameAttr); name != "" {
			groups = append(groups, name)
		}
	}
	return groups, nil
}

// upsertShadowUser creates or refreshes the local row mirroring the
// directory identity, and replaces the user's group memberships with the
// directory-derived ones.
func (m *Manager) upsertShadowUser(ctx context.Context, src sqlcgen.LdapSource, entry *Entry) (sqlcgen.User, error) {
	now := time.Now().UTC()

	user, err := m.store.GetUserByUsername(ctx, entry.Username)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		user, err = m.store.CreateUser(ctx, sqlcgen.CreateUserParams{
			ID:           uuid.NewString(),
			Username:     entry.Username,
			Email:        entry.Email,
			Name:         entry.Name,
			PasswordHash: nil,
			Source:       "ldap",
			LdapSourceID: &src.ID,
			LdapDn:       &entry.DN,
			IsAdmin:      false,
			Active:       true,
			CreatedAt:    now,
			UpdatedAt:    now,
		})
		if err != nil {
			return sqlcgen.User{}, err
		}
	case err != nil:
		return sqlcgen.User{}, err
	default:
		// Username collision with a local account (or another source):
		// deny rather than silently shadowing an existing identity.
		if user.Source != "ldap" || user.LdapSourceID == nil || *user.LdapSourceID != src.ID {
			m.log.Warn("ldap login denied: username owned by another source",
				"username", entry.Username, "source", src.Name)
			return sqlcgen.User{}, ErrBadCredentials
		}
		if !user.Active {
			return sqlcgen.User{}, ErrBadCredentials
		}
		if err := m.store.UpdateUserLdapProfile(ctx, sqlcgen.UpdateUserLdapProfileParams{
			Email: entry.Email, Name: entry.Name, LdapDn: &entry.DN,
			UpdatedAt: now, ID: user.ID,
		}); err != nil {
			return sqlcgen.User{}, err
		}
		user.Email, user.Name, user.LdapDn = entry.Email, entry.Name, &entry.DN
	}

	if err := m.syncGroups(ctx, user.ID, entry.Groups); err != nil {
		return sqlcgen.User{}, err
	}
	return user, nil
}

// syncGroups replaces the user's memberships with the directory groups,
// creating Kivraid groups on first sight.
func (m *Manager) syncGroups(ctx context.Context, userID string, names []string) error {
	tx, err := m.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	q := m.store.Queries.WithTx(tx)

	if err := q.DeleteUserGroups(ctx, userID); err != nil {
		return err
	}
	for _, name := range names {
		group, err := q.GetGroupByName(ctx, name)
		if errors.Is(err, sql.ErrNoRows) {
			group, err = q.CreateGroup(ctx, sqlcgen.CreateGroupParams{
				ID: uuid.NewString(), Name: name, CreatedAt: time.Now().UTC(),
			})
		}
		if err != nil {
			return err
		}
		if err := q.AddUserGroup(ctx, sqlcgen.AddUserGroupParams{UserID: userID, GroupID: group.ID}); err != nil {
			return err
		}
	}
	return tx.Commit()
}
