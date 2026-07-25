package web

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kivraid/kivraid/internal/audit"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
)

// resolveLoginTarget applies the home-realm-discovery rules to an entered
// identifier, most-specific first: exact identifier, then email domain, then
// the default. Returns a provider id, or "local".
func (s *Server) resolveLoginTarget(ctx context.Context, identifier string) string {
	id := strings.ToLower(strings.TrimSpace(identifier))
	if r, err := s.store.GetLoginRoute(ctx, sqlcgen.GetLoginRouteParams{Kind: "identifier", MatchValue: id}); err == nil {
		return r.Target
	}
	if at := strings.LastIndex(id, "@"); at >= 0 && at < len(id)-1 {
		if r, err := s.store.GetLoginRoute(ctx, sqlcgen.GetLoginRouteParams{Kind: "domain", MatchValue: id[at+1:]}); err == nil {
			return r.Target
		}
	}
	if r, err := s.store.GetLoginRoute(ctx, sqlcgen.GetLoginRouteParams{Kind: "default", MatchValue: ""}); err == nil {
		return r.Target
	}
	return "local"
}

type routeRow struct {
	ID         string
	Kind       string
	Match      string
	TargetName string
}

type adminRoutingData struct {
	Rules     []routeRow
	Default   string // target value: "local" or a provider id
	Providers []sqlcgen.UpstreamProvider
	Saved     bool
	Error     string
}

// targetName resolves a route target to a display name.
func targetName(target string, byID map[string]string) string {
	if target == "local" {
		return "Local"
	}
	if n, ok := byID[target]; ok {
		return n
	}
	return "(deleted provider)"
}

func (s *Server) renderRouting(w http.ResponseWriter, r *http.Request, errMsg string) {
	providers, err := s.store.ListUpstreamProviders(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	byID := make(map[string]string, len(providers))
	for _, p := range providers {
		byID[p.ID] = p.Name
	}
	routes, err := s.store.ListLoginRoutes(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	data := adminRoutingData{Default: "local", Providers: providers, Error: errMsg,
		Saved: r.URL.Query().Get("saved") == "1"}
	for _, rt := range routes {
		if rt.Kind == "default" {
			data.Default = rt.Target
			continue
		}
		data.Rules = append(data.Rules, routeRow{
			ID: rt.ID, Kind: rt.Kind, Match: rt.MatchValue, TargetName: targetName(rt.Target, byID),
		})
	}
	s.render(w, r, "admin_routing.html", pageData{
		Title: "Login routing", Active: "routing", CSRF: s.csrfToken(r.Context()),
		User: currentUser(r), Data: data,
	})
}

func (s *Server) handleAdminRouting(w http.ResponseWriter, r *http.Request) {
	s.renderRouting(w, r, "")
}

// validTarget reports whether target is "local" or an existing provider.
func (s *Server) validTarget(ctx context.Context, target string) bool {
	if target == "local" {
		return true
	}
	_, err := s.store.GetUpstreamProvider(ctx, target)
	return err == nil
}

func (s *Server) handleAdminRoutingAdd(w http.ResponseWriter, r *http.Request) {
	kind := r.PostFormValue("kind")
	match := strings.ToLower(strings.TrimSpace(r.PostFormValue("match_value")))
	target := r.PostFormValue("target")

	fail := func(msg string) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.renderRouting(w, r, msg)
	}
	if kind != "identifier" && kind != "domain" {
		fail("Choose whether the rule matches an identifier or a domain.")
		return
	}
	if match == "" {
		fail("Enter the identifier or domain to match.")
		return
	}
	if kind == "domain" && strings.ContainsAny(match, "@ ") {
		fail("A domain rule matches a bare domain, e.g. example.com (no @).")
		return
	}
	if !s.validTarget(r.Context(), target) {
		fail("Pick a valid target.")
		return
	}
	_, err := s.store.CreateLoginRoute(r.Context(), sqlcgen.CreateLoginRouteParams{
		ID: uuid.NewString(), Kind: kind, MatchValue: match, Target: target, CreatedAt: time.Now().UTC(),
	})
	if isUniqueViolation(err) {
		fail("A rule for this " + kind + " already exists.")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionRouteUpdate, kind+":"+match, "add", s.clientIP(r))
	http.Redirect(w, r, "/admin/routing?saved=1", http.StatusSeeOther)
}

func (s *Server) handleAdminRoutingDefault(w http.ResponseWriter, r *http.Request) {
	target := r.PostFormValue("target")
	if !s.validTarget(r.Context(), target) {
		s.renderRouting(w, r, "Pick a valid default target.")
		return
	}
	if err := s.store.SetDefaultRoute(r.Context(), sqlcgen.SetDefaultRouteParams{
		ID: uuid.NewString(), Target: target, CreatedAt: time.Now().UTC(),
	}); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionRouteUpdate, "default", "target="+target, s.clientIP(r))
	http.Redirect(w, r, "/admin/routing?saved=1", http.StatusSeeOther)
}

func (s *Server) handleAdminRoutingDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteLoginRoute(r.Context(), r.PathValue("id")); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionRouteUpdate, "", "delete", s.clientIP(r))
	http.Redirect(w, r, "/admin/routing?saved=1", http.StatusSeeOther)
}
