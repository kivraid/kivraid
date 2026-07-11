package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/lporcheron/kivraid/internal/audit"
	"github.com/lporcheron/kivraid/internal/store/sqlcgen"
)

// loadBranding refreshes the in-memory branding cache from the database.
// Failures leave the defaults in place: branding is cosmetic and must never
// keep the server from starting or a page from rendering.
func (s *Server) loadBranding(ctx context.Context) {
	row, err := s.store.GetInstanceSettings(ctx)
	if err != nil {
		if s.log != nil {
			s.log.Warn("load branding", "err", err)
		}
		return
	}
	mime := ""
	if row.LogoMime != nil {
		mime = *row.LogoMime
	}
	s.brandMu.Lock()
	s.brandName = row.BrandName
	s.brandLogo = row.Logo
	s.brandLogoMime = mime
	s.brandVer = brandVersion(row.Logo)
	s.brandMu.Unlock()
}

// brandVersion is a short content token for cache-busting the logo URL.
func brandVersion(logo []byte) string {
	if len(logo) == 0 {
		return "none"
	}
	sum := sha256.Sum256(logo)
	return hex.EncodeToString(sum[:])[:12]
}

// brandDisplayName is the instance name, falling back to "Kivraid".
func (s *Server) brandDisplayName() string {
	s.brandMu.RLock()
	defer s.brandMu.RUnlock()
	if s.brandName != "" {
		return s.brandName
	}
	return "Kivraid"
}

func (s *Server) brandHasLogo() bool {
	s.brandMu.RLock()
	defer s.brandMu.RUnlock()
	return len(s.brandLogo) > 0
}

func (s *Server) brandVersion() string {
	s.brandMu.RLock()
	defer s.brandMu.RUnlock()
	return s.brandVer
}

// handleBrandLogo serves the custom logo (public: the login page references
// it before authentication). Absent logo yields a 404 so templates fall back
// to the built-in mark.
func (s *Server) handleBrandLogo(w http.ResponseWriter, r *http.Request) {
	s.brandMu.RLock()
	logo, mime := s.brandLogo, s.brandLogoMime
	s.brandMu.RUnlock()
	if len(logo) == 0 || mime == "" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", mime)
	// Versioned URL (?v=<hash>): safe to cache hard, changes with the logo.
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(logo)
}

type adminBrandingData struct {
	Name    string
	HasLogo bool
	Saved   bool
	Error   string
}

func (s *Server) renderBranding(w http.ResponseWriter, r *http.Request, errMsg string, saved bool) {
	s.render(w, r, "admin_branding.html", pageData{
		Title: "Branding", Active: "branding", CSRF: s.csrfToken(r.Context()),
		User: currentUser(r),
		Data: adminBrandingData{
			Name: s.currentBrandName(), HasLogo: s.brandHasLogo(), Saved: saved, Error: errMsg,
		},
	})
}

// currentBrandName returns the stored name verbatim (empty if unset), so the
// form field shows what is actually saved rather than the "Kivraid" default.
func (s *Server) currentBrandName() string {
	s.brandMu.RLock()
	defer s.brandMu.RUnlock()
	return s.brandName
}

func (s *Server) handleAdminBranding(w http.ResponseWriter, r *http.Request) {
	s.renderBranding(w, r, "", r.URL.Query().Get("saved") == "1")
}

func (s *Server) handleAdminBrandingSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(maxUploadPhotoSize); err != nil {
		s.renderError(w, r, http.StatusRequestEntityTooLarge, "Logo too large",
			"The logo must be smaller than 1 MB.")
		return
	}
	name := strings.TrimSpace(r.PostFormValue("brand_name"))
	now := time.Now().UTC()

	if err := s.store.SetBrandName(r.Context(), sqlcgen.SetBrandNameParams{
		BrandName: name, UpdatedAt: now,
	}); err != nil {
		s.serverError(w, r, err)
		return
	}

	// A logo upload is optional; an empty file input leaves the current one.
	if file, _, err := r.FormFile("logo"); err == nil {
		defer file.Close()
		logo, err := io.ReadAll(io.LimitReader(file, maxUploadPhotoSize+1))
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		if len(logo) > 0 {
			mime := http.DetectContentType(logo)
			if len(logo) > maxUploadPhotoSize || !slices.Contains(allowedPhotoTypes, mime) {
				w.WriteHeader(http.StatusUnprocessableEntity)
				s.renderBranding(w, r, "Use a JPEG, PNG, WebP or GIF up to 1 MB.", false)
				return
			}
			if err := s.store.SetBrandLogo(r.Context(), sqlcgen.SetBrandLogoParams{
				Logo: logo, LogoMime: &mime, UpdatedAt: now,
			}); err != nil {
				s.serverError(w, r, err)
				return
			}
		}
	}

	s.loadBranding(r.Context())
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionBrandingUpdate, "", "", s.clientIP(r))
	http.Redirect(w, r, "/admin/branding?saved=1", http.StatusSeeOther)
}

func (s *Server) handleAdminBrandingLogoDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.store.ClearBrandLogo(r.Context(), time.Now().UTC()); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.loadBranding(r.Context())
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionBrandingUpdate, "", "logo removed", s.clientIP(r))
	http.Redirect(w, r, "/admin/branding?saved=1", http.StatusSeeOther)
}
