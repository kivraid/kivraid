package web

import (
	"encoding/csv"
	"net/http"
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
	Action     string   // active action filter ("" = all)
	Query      string   // active actor search
	Filtered   bool     // a filter is applied
	Page       int
	Pages      int
	Total      int64
	RangeStart int64
	RangeEnd   int64
	PrevPage   int
	NextPage   int
}

// auditFilter reads the action and actor filters shared by the list and the
// CSV export.
func auditFilter(r *http.Request) (action, query, actorPattern string) {
	action = strings.TrimSpace(r.URL.Query().Get("action"))
	query = strings.TrimSpace(r.URL.Query().Get("q"))
	return action, query, likePattern(query)
}

func (s *Server) handleAdminAudit(w http.ResponseWriter, r *http.Request) {
	action, query, pattern := auditFilter(r)

	total, err := s.store.CountAuditFiltered(r.Context(), sqlcgen.CountAuditFilteredParams{
		Action: action, ActorPattern: pattern,
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
		Action: action, ActorPattern: pattern,
		PageLimit: auditPageSize, PageOffset: int32(page-1) * auditPageSize,
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}

	data := adminAuditData{
		Entries: entries, Actions: audit.Actions,
		Action: action, Query: query, Filtered: action != "" || query != "",
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
	action, _, pattern := auditFilter(r)

	entries, err := s.store.ListAuditFiltered(r.Context(), sqlcgen.ListAuditFilteredParams{
		Action: action, ActorPattern: pattern,
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
