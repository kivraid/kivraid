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
	"net/http"
	"net/url"
	"strings"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"

	"github.com/kivraid/kivraid/internal/secrets"
	"github.com/kivraid/kivraid/internal/store"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
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

// maxPhotoSize bounds directory photos mirrored into the local store.
const maxPhotoSize = 1 << 20

type Entry struct {
	DN       string
	Username string
	Email    string
	Name     string
	Photo    []byte
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
	entry.Groups, err = m.findGroups(conn, src, entry.DN, entry.Username)
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

// dial opens an unauthenticated connection to the source.
func (m *Manager) dial(src sqlcgen.LdapSource) (*goldap.Conn, error) {
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
	return conn, nil
}

// Connect dials the source and binds with the service account. An empty
// bind DN means anonymous: lookups run unauthenticated (the directory
// must allow anonymous search). User authentication and password
// write-back are unaffected — both bind as the user.
func (m *Manager) Connect(src sqlcgen.LdapSource) (*goldap.Conn, error) {
	conn, err := m.dial(src)
	if err != nil {
		return nil, err
	}
	if src.BindDn == "" {
		return conn, nil
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

// ErrWritebackDisabled is returned when the user's source does not allow
// password changes from Kivraid.
var ErrWritebackDisabled = errors.New("password changes are disabled for this directory")

// ErrResetDisabled is returned when the user's source does not allow Kivraid
// to reset passwords with the service account.
var ErrResetDisabled = errors.New("password reset is disabled for this directory")

// ResetPassword force-sets a directory user's password using the service
// (bind) account, without knowing the current one — the mechanism behind
// email-based and admin-initiated resets. It requires the bind account to
// hold write permission on the target's password, and the source's
// password_reset flag to be enabled. Unlike ChangePassword it never binds
// as the user.
func (m *Manager) ResetPassword(ctx context.Context, user sqlcgen.User, newPassword string) error {
	if user.LdapSourceID == nil || user.LdapDn == nil {
		return errors.New("user has no directory binding")
	}
	src, err := m.store.GetLdapSource(ctx, *user.LdapSourceID)
	if err != nil {
		return err
	}
	if !src.PasswordReset {
		return ErrResetDisabled
	}
	if src.BindDn == "" {
		return fmt.Errorf("password reset requires a service account (bind DN) with write access")
	}
	conn, err := m.Connect(src) // binds as the service account
	if err != nil {
		return err
	}
	defer conn.Close()
	// Target the user's DN explicitly; bound as the service account, this is
	// an administrative set rather than a self-service change.
	if _, err := conn.PasswordModify(goldap.NewPasswordModifyRequest(*user.LdapDn, "", newPassword)); err != nil {
		return fmt.Errorf("password modify: %w", err)
	}
	m.log.Info("ldap password reset", "user", user.Username, "source", src.Name)
	return nil
}

// ChangePassword performs the RFC 3062 Password Modify extended operation
// on the user's own connection: the current password is verified by the
// user bind, and the directory's ACLs decide whether self-service change
// is allowed. Works with OpenLDAP and LLDAP.
func (m *Manager) ChangePassword(ctx context.Context, user sqlcgen.User, current, newPassword string) error {
	if user.LdapSourceID == nil || user.LdapDn == nil {
		return errors.New("user has no directory binding")
	}
	if current == "" {
		return ErrBadCredentials // avoid an anonymous bind
	}
	src, err := m.store.GetLdapSource(ctx, *user.LdapSourceID)
	if err != nil {
		return err
	}
	if !src.PasswordWriteback {
		return ErrWritebackDisabled
	}
	conn, err := m.dial(src)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.Bind(*user.LdapDn, current); err != nil {
		return ErrBadCredentials
	}
	// Empty user identity means "the bound user" (most compatible across
	// OpenLDAP and LLDAP).
	if _, err := conn.PasswordModify(goldap.NewPasswordModifyRequest("", current, newPassword)); err != nil {
		return fmt.Errorf("password modify: %w", err)
	}
	m.log.Info("ldap password changed", "user", user.Username, "source", src.Name)
	return nil
}

// SyncResult summarizes a manual directory synchronization.
type SyncResult struct {
	Created int
	Updated int
	Skipped int
	// Missing counts shadow users of this source that no longer match
	// the directory; they are reported, never auto-deactivated.
	Missing int
}

// SyncAll enumerates the directory (the user filter with {username}
// replaced by a wildcard) and imports or refreshes every user and their
// groups, without waiting for individual sign-ins.
func (m *Manager) SyncAll(ctx context.Context, src sqlcgen.LdapSource) (SyncResult, error) {
	var res SyncResult
	conn, err := m.Connect(src)
	if err != nil {
		return res, err
	}
	defer conn.Close()

	filter := strings.ReplaceAll(src.UserFilter, "{username}", "*")
	attrs := []string{src.UsernameAttr, src.EmailAttr, src.NameAttr}
	if src.PhotoAttr != "" {
		attrs = append(attrs, src.PhotoAttr)
	}
	// Paged search (RFC 2696) so directories larger than the server's size
	// limit are fully enumerated. Falls back to a plain search for the rare
	// server that does not support the paging control.
	req := goldap.NewSearchRequest(
		src.BaseDn, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
		0, 60, false, filter, attrs, nil,
	)
	found, err := conn.SearchWithPaging(req, 500)
	if err != nil {
		m.log.Warn("ldap paged search failed, retrying without paging", "source", src.Name, "err", err)
		if found, err = conn.Search(req); err != nil {
			return res, fmt.Errorf("user enumeration: %w", err)
		}
	}

	seen := map[string]bool{}
	for _, e := range found.Entries {
		entry := &Entry{
			DN:       e.DN,
			Username: strings.ToLower(e.GetAttributeValue(src.UsernameAttr)),
			Email:    strings.ToLower(e.GetAttributeValue(src.EmailAttr)),
			Name:     e.GetAttributeValue(src.NameAttr),
		}
		if entry.Username == "" {
			res.Skipped++
			continue
		}
		if entry.Name == "" {
			entry.Name = entry.Username
		}
		if src.PhotoAttr != "" {
			if photo := e.GetRawAttributeValue(src.PhotoAttr); len(photo) > 0 && len(photo) <= maxPhotoSize {
				entry.Photo = photo
			}
		}
		entry.Groups, err = m.findGroups(conn, src, entry.DN, entry.Username)
		if err != nil {
			return res, err
		}
		seen[entry.Username] = true

		existed := true
		if _, err := m.store.GetUserByUsername(ctx, entry.Username); errors.Is(err, sql.ErrNoRows) {
			existed = false
		}
		if _, err := m.upsertShadowUser(ctx, src, entry); err != nil {
			// Collisions and deactivated accounts are skipped, not fatal.
			res.Skipped++
			continue
		}
		if existed {
			res.Updated++
		} else {
			res.Created++
		}
	}

	// Report shadow users of this source that the directory no longer
	// returns (renamed, removed, or excluded by the filter).
	users, err := m.store.ListUsers(ctx)
	if err != nil {
		return res, err
	}
	for _, u := range users {
		if u.Source == "ldap" && u.LdapSourceID != nil && *u.LdapSourceID == src.ID && !seen[u.Username] {
			res.Missing++
		}
	}
	m.log.Info("ldap sync", "source", src.Name,
		"created", res.Created, "updated", res.Updated, "skipped", res.Skipped, "missing", res.Missing)
	return res, nil
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
	entry.Groups, err = m.findGroups(conn, src, entry.DN, entry.Username)
	return entry, err
}

func (m *Manager) findUser(conn *goldap.Conn, src sqlcgen.LdapSource, username string) (*Entry, error) {
	filter := strings.ReplaceAll(src.UserFilter, "{username}", goldap.EscapeFilter(username))
	attrs := []string{src.UsernameAttr, src.EmailAttr, src.NameAttr}
	if src.PhotoAttr != "" {
		attrs = append(attrs, src.PhotoAttr)
	}
	res, err := conn.Search(goldap.NewSearchRequest(
		src.BaseDn, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
		2, int(dialTimeout/time.Second), false,
		filter,
		attrs,
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
	if src.PhotoAttr != "" {
		if photo := e.GetRawAttributeValue(src.PhotoAttr); len(photo) > 0 && len(photo) <= maxPhotoSize {
			entry.Photo = photo
		}
	}
	if entry.Username == "" {
		return nil, fmt.Errorf("entry %s has no %s attribute", e.DN, src.UsernameAttr)
	}
	if entry.Name == "" {
		entry.Name = entry.Username
	}
	return entry, nil
}

// findGroups resolves the user's directory groups. The filter supports
// two placeholders so both membership models work, together if needed:
// {dn} for member/uniqueMember (groupOfNames, groupOfUniqueNames) and
// {username} for memberUid (posixGroup).
func (m *Manager) findGroups(conn *goldap.Conn, src sqlcgen.LdapSource, userDN, username string) ([]string, error) {
	if src.GroupFilter == "" {
		return nil, nil
	}
	filter := strings.ReplaceAll(src.GroupFilter, "{dn}", goldap.EscapeFilter(userDN))
	filter = strings.ReplaceAll(filter, "{username}", goldap.EscapeFilter(username))
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
// directory identity (profile, photo), and syncs the user's memberships
// in this source's groups.
func (m *Manager) upsertShadowUser(ctx context.Context, src sqlcgen.LdapSource, entry *Entry) (sqlcgen.User, error) {
	now := time.Now().UTC()

	var photoMime *string
	if len(entry.Photo) > 0 {
		mime := http.DetectContentType(entry.Photo)
		photoMime = &mime
	}

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
		if entry.Photo != nil {
			if err := m.store.UpdateUserPhoto(ctx, sqlcgen.UpdateUserPhotoParams{
				Photo: entry.Photo, PhotoMime: photoMime, UpdatedAt: now, ID: user.ID,
			}); err != nil {
				return sqlcgen.User{}, err
			}
			user.Photo, user.PhotoMime = entry.Photo, photoMime
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
			Photo: entry.Photo, PhotoMime: photoMime,
			UpdatedAt: now, ID: user.ID,
		}); err != nil {
			return sqlcgen.User{}, err
		}
		user.Email, user.Name, user.LdapDn = entry.Email, entry.Name, &entry.DN
		user.Photo, user.PhotoMime = entry.Photo, photoMime
	}

	if err := m.syncGroups(ctx, src, user.ID, entry.Groups); err != nil {
		return sqlcgen.User{}, err
	}
	return user, nil
}

// syncGroups mirrors the user's memberships in this source's groups:
// only ldap-sourced groups belonging to src are touched, so memberships
// in local groups (managed in the admin) survive directory logins.
func (m *Manager) syncGroups(ctx context.Context, src sqlcgen.LdapSource, userID string, names []string) error {
	tx, err := m.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	q := m.store.Queries.WithTx(tx)

	if err := q.DeleteUserGroupsFromSource(ctx, sqlcgen.DeleteUserGroupsFromSourceParams{
		UserID: userID, LdapSourceID: &src.ID,
	}); err != nil {
		return err
	}
	for _, name := range names {
		group, err := q.GetGroupByName(ctx, name)
		if errors.Is(err, sql.ErrNoRows) {
			group, err = q.CreateGroup(ctx, sqlcgen.CreateGroupParams{
				ID: uuid.NewString(), Name: name,
				Source: "ldap", LdapSourceID: &src.ID,
				CreatedAt: time.Now().UTC(),
			})
		}
		if err != nil {
			return err
		}
		// A same-named group owned by another source (or created locally
		// in the admin) is not hijacked; the membership is skipped.
		if group.Source != "ldap" || group.LdapSourceID == nil || *group.LdapSourceID != src.ID {
			m.log.Warn("ldap group sync skipped: name owned by another source",
				"group", name, "source", src.Name)
			continue
		}
		if err := q.AddUserGroup(ctx, sqlcgen.AddUserGroupParams{UserID: userID, GroupID: group.ID}); err != nil {
			return err
		}
	}
	return tx.Commit()
}
