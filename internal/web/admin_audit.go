package web

import (
	"net/http"
	"strconv"

	"github.com/lporcheron/kivraid/internal/store/sqlcgen"
)

const auditPageSize = 50

type adminAuditData struct {
	Entries    []sqlcgen.AuditLog
	Page       int
	Pages      int
	Total      int64
	RangeStart int64
	RangeEnd   int64
	PrevPage   int
	NextPage   int
}

func (s *Server) handleAdminAudit(w http.ResponseWriter, r *http.Request) {
	total, err := s.store.CountAudit(r.Context())
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

	entries, err := s.store.ListAuditPage(r.Context(), sqlcgen.ListAuditPageParams{
		Limit: auditPageSize, Offset: int32(page-1) * auditPageSize,
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}

	data := adminAuditData{
		Entries: entries, Page: page, Pages: pages, Total: total,
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
