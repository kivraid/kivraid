package web

import (
	"encoding/csv"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kivraid/kivraid/internal/audit"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
)

const auditPageSize = 50

type adminAuditData struct {
	Entries    []sqlcgen.AuditLog
	Actions    []string // known actions, for the filter dropdown
	Filter     auditFilterValues
	Filtered   bool   // a filter is applied
	FilterQS   string // encoded filters, for pagination and export links
	Ranges     []auditRange
	Page       int
	Pages      int
	Total      int64
	RangeStart int64
	RangeEnd   int64
	PrevPage   int
	NextPage   int
}

// auditRange is a preset time window for the activity filter. Relative
// windows avoid any server-versus-browser timezone mismatch.
type auditRange struct {
	ID, Label string
	Span      time.Duration
}

var auditRanges = []auditRange{
	{"24h", "Last 24 hours", 24 * time.Hour},
	{"7d", "Last 7 days", 7 * 24 * time.Hour},
	{"30d", "Last 30 days", 30 * 24 * time.Hour},
}

// auditFilterValues are the activity filters as read from the query string.
type auditFilterValues struct {
	Action string // "" = all
	Query  string // actor search
	IP     string
	Range  string // an auditRange ID, "" = all time
}

func (f auditFilterValues) encode() string {
	v := url.Values{}
	for k, val := range map[string]string{"action": f.Action, "q": f.Query, "ip": f.IP, "range": f.Range} {
		if val != "" {
			v.Set(k, val)
		}
	}
	return v.Encode()
}

// auditFilter reads the filters shared by the list and the CSV export, and
// returns them with the actor pattern and time window they translate to.
func auditFilter(r *http.Request) (f auditFilterValues, actorPattern string, since, until time.Time) {
	q := r.URL.Query()
	f = auditFilterValues{
		Action: strings.TrimSpace(q.Get("action")),
		Query:  strings.TrimSpace(q.Get("q")),
		IP:     strings.TrimSpace(q.Get("ip")),
	}
	now := time.Now().UTC()
	since, until = time.Unix(0, 0).UTC(), now.Add(time.Hour)
	for _, rg := range auditRanges {
		if rg.ID == q.Get("range") {
			f.Range, since = rg.ID, now.Add(-rg.Span)
		}
	}
	return f, likePattern(f.Query), since, until
}

func (s *Server) handleAdminAudit(w http.ResponseWriter, r *http.Request) {
	f, pattern, since, until := auditFilter(r)

	total, err := s.store.CountAuditFiltered(r.Context(), sqlcgen.CountAuditFilteredParams{
		Action: f.Action, ActorPattern: pattern, Ip: f.IP, Since: since, Until: until,
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	pages := int((total + auditPageSize - 1) / auditPageSize)
	if pages < 1 {
		pages = 1
	}
	page := 1
	if p, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && p > 1 {
		page = p
	}
	if page > pages {
		page = pages
	}

	entries, err := s.store.ListAuditFilteredPage(r.Context(), sqlcgen.ListAuditFilteredPageParams{
		Action: f.Action, ActorPattern: pattern, Ip: f.IP, Since: since, Until: until,
		PageLimit: auditPageSize, PageOffset: int32(page-1) * auditPageSize,
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}

	data := adminAuditData{
		Entries: entries, Actions: audit.Actions, Filter: f, Ranges: auditRanges,
		Filtered: f != (auditFilterValues{}), FilterQS: f.encode(),
		Page: page, Pages: pages, Total: total,
		RangeStart: int64(page-1)*auditPageSize + 1,
		RangeEnd:   int64(page-1)*auditPageSize + int64(len(entries)),
	}
	if total == 0 {
		data.RangeStart = 0
	}
	if page > 1 {
		data.PrevPage = page - 1
	}
	if page < pages {
		data.NextPage = page + 1
	}

	s.render(w, r, "admin_audit.html", pageData{
		Title: "Activity", Active: "audit", CSRF: s.csrfToken(r.Context()),
		User: currentUser(r), Data: data,
	})
}

// handleAdminAuditExport streams the events matching the current filter as a
// CSV download.
func (s *Server) handleAdminAuditExport(w http.ResponseWriter, r *http.Request) {
	f, pattern, since, until := auditFilter(r)

	entries, err := s.store.ListAuditFiltered(r.Context(), sqlcgen.ListAuditFilteredParams{
		Action: f.Action, ActorPattern: pattern, Ip: f.IP, Since: since, Until: until,
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition",
		"attachment; filename=\"kivraid-activity-"+time.Now().UTC().Format("20060102")+".csv\"")

	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"timestamp", "actor", "action", "object", "detail", "ip"})
	for _, e := range entries {
		_ = cw.Write([]string{
			e.Ts.UTC().Format(time.RFC3339), e.Actor, e.Action, e.Object, e.Detail, e.Ip,
		})
	}
	cw.Flush()
}
