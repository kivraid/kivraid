// Package session configures the server-side session manager. Sessions
// live in the database (revocable, listable — a portal feature), the
// cookie only carries the session token.
package session

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/alexedwards/scs/postgresstore"
	"github.com/alexedwards/scs/sqlite3store"
	"github.com/alexedwards/scs/v2"
)

const (
	// KeyUserID is the session key holding the authenticated user's ID.
	KeyUserID = "userID"
	// KeyCSRF is the session key holding the CSRF token.
	KeyCSRF = "csrf"
	// KeyIP, KeyUserAgent and KeyLoginAt describe the login that created
	// the session; shown on the portal's sessions page.
	KeyIP        = "ip"
	KeyUserAgent = "ua"
	KeyLoginAt   = "loginAt"
	// KeyPendingLogin holds the identifier entered on the first login step,
	// carried to the password step. It grants no access on its own.
	KeyPendingLogin = "pendingLogin"
	// KeyPendingMFA holds the user ID that passed the password step but
	// still owes a TOTP code; it grants no access on its own. KeyPendingNext
	// carries the post-login redirect target across login steps.
	KeyPendingMFA  = "pendingMFA"
	KeyPendingNext = "pendingNext"
	// KeyMFAEnroll holds a not-yet-confirmed TOTP secret during profile
	// enrollment.
	KeyMFAEnroll = "mfaEnroll"
	// KeyWebAuthnReg and KeyWebAuthnLogin hold the opaque WebAuthn session
	// data (challenge state) between the begin and finish steps of a passkey
	// registration or passwordless login ceremony.
	KeyWebAuthnReg   = "waReg"
	KeyWebAuthnLogin = "waLogin"
)

// NewManager builds the session manager. lifetime is the absolute session
// age; idleTimeout, when > 0, adds a sliding inactivity window (each request
// resets it) capped by lifetime — set it to 0 to disable inactivity expiry.
func NewManager(db *sql.DB, driver string, secureCookies bool, lifetime, idleTimeout time.Duration) *scs.SessionManager {
	m := scs.New()
	switch driver {
	case "postgres":
		m.Store = postgresstore.NewWithCleanupInterval(db, 30*time.Minute)
	default:
		m.Store = sqlite3store.NewWithCleanupInterval(db, 30*time.Minute)
	}
	m.Lifetime = lifetime
	m.IdleTimeout = idleTimeout
	m.Cookie.Name = "kivraid_session"
	m.Cookie.HttpOnly = true
	m.Cookie.SameSite = http.SameSiteLaxMode
	m.Cookie.Secure = secureCookies
	return m
}
