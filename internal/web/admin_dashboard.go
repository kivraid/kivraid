package web

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/kivraid/kivraid/internal/audit"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
)

// dashStat is a single headline number on the admin overview.
type dashStat struct {
	Label string
	Value int64
	Sub   string // optional secondary line
	Href  string
}

type adminDashboardData struct {
	Stats      []dashStat
	Logins24h  int64
	Failed24h  int64
	Recent     []sqlcgen.AuditLog
	SignInJSON string // hourly sign-in counts for the chart (see signInSeries)
}

// signInSeries is the dashboard chart's data: hourly counts of successful
// and failed sign-ins, oldest first, starting at Start (Unix seconds, on an
// hour boundary). The browser groups the hours into its own local days.
type signInSeries struct {
	Start int64   `json:"start"`
	OK    []int64 `json:"ok"`
	Fail  []int64 `json:"fail"`
}

// signInChartHours covers 7 local days whatever the viewer's offset.
const signInChartHours = 8 * 24

func buildSignInSeries(now time.Time, events []sqlcgen.ListSignInEventsSinceRow) (signInSeries, int64, int64) {
	start := now.Truncate(time.Hour).Add(-(signInChartHours - 1) * time.Hour)
	series := signInSeries{Start: start.Unix(), OK: make([]int64, signInChartHours), Fail: make([]int64, signInChartHours)}
	var ok24, fail24 int64
	for _, e := range events {
		i := int(e.Ts.Sub(start) / time.Hour)
		if i < 0 || i >= signInChartHours {
			continue
		}
		recent := now.Sub(e.Ts) < 24*time.Hour
		if e.Action == audit.ActionLoginFailed {
			series.Fail[i]++
			if recent {
				fail24++
			}
		} else {
			series.OK[i]++
			if recent {
				ok24++
			}
		}
	}
	return series, ok24, fail24
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

	// Sign-in activity over the chart window and the last 24 hours.
	now := time.Now().UTC()
	events, err := s.store.ListSignInEventsSince(ctx, now.Add(-signInChartHours*time.Hour))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	series, logins24h, failed24h := buildSignInSeries(now, events)
	seriesJSON, err := json.Marshal(series)
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
			Stats: stats, Logins24h: logins24h, Failed24h: failed24h, Recent: recent,
			SignInJSON: string(seriesJSON),
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
