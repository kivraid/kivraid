package web

import (
	"net/http"
	"strconv"
	"time"

	"github.com/lporcheron/kivraid/internal/audit"
	"github.com/lporcheron/kivraid/internal/store/sqlcgen"
)

// dashStat is a single headline number on the admin overview.
type dashStat struct {
	Label string
	Value int64
	Sub   string // optional secondary line
	Href  string
}

type adminDashboardData struct {
	Stats       []dashStat
	LoginsToday int64
	FailedToday int64
	Recent      []sqlcgen.AuditLog
}

// handleAdminDashboard renders the admin landing page: a few headline counts
// and the most recent activity. Everything here reuses existing read paths,
// so it stays cheap.
func (s *Server) handleAdminDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	users, err := s.store.CountUsers(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	activeUsers, err := s.store.CountActiveUsers(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	apps, err := s.store.CountApplications(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	groups, err := s.store.CountGroups(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	sources, err := s.store.ListLdapSources(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}

	// Sign-in activity since midnight UTC.
	now := time.Now().UTC()
	midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	loginsToday, err := s.store.CountAuditActionSince(ctx, sqlcgen.CountAuditActionSinceParams{
		Action: audit.ActionLogin, Since: midnight,
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	failedToday, err := s.store.CountAuditActionSince(ctx, sqlcgen.CountAuditActionSinceParams{
		Action: audit.ActionLoginFailed, Since: midnight,
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}

	recent, err := s.store.ListAudit(ctx, 8)
	if err != nil {
		s.serverError(w, r, err)
		return
	}

	deactivated := ""
	if n := users - activeUsers; n > 0 {
		deactivated = plural(n, "deactivated", "deactivated")
	}
	stats := []dashStat{
		{Label: "Users", Value: users, Sub: deactivated, Href: "/admin/users"},
		{Label: "Applications", Value: apps, Href: "/admin/applications"},
		{Label: "Groups", Value: groups, Href: "/admin/groups"},
		{Label: "Directories", Value: int64(len(sources)), Href: "/admin/ldap"},
	}

	s.render(w, r, "admin_dashboard.html", pageData{
		Title: "Overview", Active: "dashboard", CSRF: s.csrfToken(r.Context()),
		User: currentUser(r),
		Data: adminDashboardData{
			Stats: stats, LoginsToday: loginsToday, FailedToday: failedToday, Recent: recent,
		},
	})
}

// plural renders "N word" using the plural form when N != 1.
func plural(n int64, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.FormatInt(n, 10) + " " + many
}
