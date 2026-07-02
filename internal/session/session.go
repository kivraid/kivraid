// Package session configures the server-side session manager. Sessions
// live in the database (revocable, listable — a portal feature), the
// cookie only carries the session token.
package session

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/alexedwards/scs/sqlite3store"
	"github.com/alexedwards/scs/v2"
)

const (
	// KeyUserID is the session key holding the authenticated user's ID.
	KeyUserID = "userID"
	// KeyCSRF is the session key holding the CSRF token.
	KeyCSRF = "csrf"
)

func NewManager(db *sql.DB, secureCookies bool) *scs.SessionManager {
	m := scs.New()
	m.Store = sqlite3store.NewWithCleanupInterval(db, 30*time.Minute)
	m.Lifetime = 7 * 24 * time.Hour
	m.Cookie.Name = "kivraid_session"
	m.Cookie.HttpOnly = true
	m.Cookie.SameSite = http.SameSiteLaxMode
	m.Cookie.Secure = secureCookies
	return m
}
