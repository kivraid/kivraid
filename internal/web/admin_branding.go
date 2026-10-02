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

	"github.com/kivraid/kivraid/internal/audit"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
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
	s.brandMu.Lock()
	s.brandName = row.BrandName
	s.brandLogo = row.Logo
	s.brandLogoMime = deref(row.LogoMime)
	s.brandVer = brandVersion(row.Logo)
	s.brandBg = row.LoginBackground
	s.brandBgMime = deref(row.LoginBackgroundMime)
	s.brandBgVer = brandVersion(row.LoginBackground)
	s.brandMu.Unlock()
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// brandVersion is a short content token for cache-busting an image URL.
func brandVersion(img []byte) string {
	if len(img) == 0 {
		return "none"
	}
	sum := sha256.Sum256(img)
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

func (s *Server) brandHasBackground() bool {
	s.brandMu.RLock()
	defer s.brandMu.RUnlock()
	return len(s.brandBg) > 0
}

func (s *Server) brandBackgroundVersion() string {
	s.brandMu.RLock()
	defer s.brandMu.RUnlock()
	return s.brandBgVer
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

// handleBrandBackground serves the custom sign-in background (public, like
// the logo). Absent image yields a 404; templates then keep the gradient.
func (s *Server) handleBrandBackground(w http.ResponseWriter, r *http.Request) {
	s.brandMu.RLock()
	img, mime := s.brandBg, s.brandBgMime
	s.brandMu.RUnlock()
	if len(img) == 0 || mime == "" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", mime)
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(img)
}

// maxUploadBackgroundSize caps the sign-in background: a full-screen photo
// needs more room than a logo, but it is served on every sign-in page.
const maxUploadBackgroundSize = 4 << 20

var allowedBackgroundTypes = []string{"image/jpeg", "image/png", "image/webp"}

type adminBrandingData struct {
	Name          string
	HasLogo       bool
	HasBackground bool
	Saved         bool
	Error         string
}

func (s *Server) renderBranding(w http.ResponseWriter, r *http.Request, errMsg string, saved bool) {
	s.render(w, r, "admin_branding.html", pageData{
		Title: "Branding", Active: "branding", CSRF: s.csrfToken(r.Context()),
		User: currentUser(r),
		Data: adminBrandingData{
			Name: s.currentBrandName(), HasLogo: s.brandHasLogo(), HasBackground: s.brandHasBackground(),
			Saved: saved, Error: errMsg,
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
		s.renderError(w, r, http.StatusRequestEntityTooLarge, s.t(r, "Upload too large"),
			s.t(r, "The logo must be smaller than 1 MB and the background smaller than 4 MB."))
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
				s.renderBranding(w, r, s.t(r, "Use a JPEG, PNG, WebP or GIF up to 1 MB."), false)
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

	// Same for the sign-in background.
	if file, _, err := r.FormFile("background"); err == nil {
		defer file.Close()
		img, err := io.ReadAll(io.LimitReader(file, maxUploadBackgroundSize+1))
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		if len(img) > 0 {
			mime := http.DetectContentType(img)
			if len(img) > maxUploadBackgroundSize || !slices.Contains(allowedBackgroundTypes, mime) {
				w.WriteHeader(http.StatusUnprocessableEntity)
				s.renderBranding(w, r, s.t(r, "Use a JPEG, PNG or WebP background up to 4 MB."), false)
				return
			}
			if err := s.store.SetLoginBackground(r.Context(), sqlcgen.SetLoginBackgroundParams{
				LoginBackground: img, LoginBackgroundMime: &mime, UpdatedAt: now,
			}); err != nil {
				s.serverError(w, r, err)
				return
			}
		}
	}

	s.loadBranding(r.Context())
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionBrandingUpdate, "", "", s.clientIP(r))
	http.Redirect(w, r, "/admin/settings/branding?saved=1", http.StatusSeeOther)
}

func (s *Server) handleAdminBrandingLogoDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.store.ClearBrandLogo(r.Context(), time.Now().UTC()); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.loadBranding(r.Context())
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionBrandingUpdate, "", "logo removed", s.clientIP(r))
	http.Redirect(w, r, "/admin/settings/branding?saved=1", http.StatusSeeOther)
}

func (s *Server) handleAdminBrandingBackgroundDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.store.ClearLoginBackground(r.Context(), time.Now().UTC()); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.loadBranding(r.Context())
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionBrandingUpdate, "", "background removed", s.clientIP(r))
	http.Redirect(w, r, "/admin/settings/branding?saved=1", http.StatusSeeOther)
}
