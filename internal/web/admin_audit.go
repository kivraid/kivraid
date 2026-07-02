package web

import (
	"net/http"

	"github.com/lporcheron/kivraid/internal/store/sqlcgen"
)

type adminAuditData struct {
	Entries []sqlcgen.AuditLog
}

func (s *Server) handleAdminAudit(w http.ResponseWriter, r *http.Request) {
	entries, err := s.store.ListAudit(r.Context(), 200)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, "admin_audit.html", pageData{
		Title: "Activity", Active: "audit", CSRF: s.csrfToken(r.Context()),
		User: currentUser(r), Data: adminAuditData{Entries: entries},
	})
}
