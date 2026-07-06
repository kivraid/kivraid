package web

import (
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/lporcheron/kivraid/internal/audit"
	"github.com/lporcheron/kivraid/internal/session"
	"github.com/lporcheron/kivraid/internal/store/sqlcgen"
)

type setupData struct {
	CSRF     string
	Error    string
	Username string
	Email    string
	Name     string
}

// needsSetup reports whether the instance has no users yet — the first
// visitor is then invited to register as the administrator.
func (s *Server) needsSetup(r *http.Request) bool {
	n, err := s.store.CountUsers(r.Context())
	return err == nil && n == 0
}

func (s *Server) handleSetupPage(w http.ResponseWriter, r *http.Request) {
	if !s.needsSetup(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.render(w, r, "setup.html", setupData{CSRF: s.csrfToken(r.Context())})
}

func (s *Server) handleSetupSubmit(w http.ResponseWriter, r *http.Request) {
	// Re-checked at submit time so the window between two concurrent
	// first visitors cannot yield two admins.
	if !s.needsSetup(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	data := setupData{
		CSRF:     s.csrfToken(r.Context()),
		Username: strings.ToLower(strings.TrimSpace(r.PostFormValue("username"))),
		Email:    strings.ToLower(strings.TrimSpace(r.PostFormValue("email"))),
		Name:     strings.TrimSpace(r.PostFormValue("name")),
	}
	password := r.PostFormValue("password")
	confirm := r.PostFormValue("confirm_password")

	fail := func(msg string) {
		data.Error = msg
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.render(w, r, "setup.html", data)
	}
	if data.Username == "" || data.Email == "" {
		fail("Username and email are required.")
		return
	}
	if data.Name == "" {
		data.Name = data.Username
	}
	if len(password) < 8 {
		fail("The password must be at least 8 characters.")
		return
	}
	if password != confirm {
		fail("The passwords do not match.")
		return
	}

	user, err := s.local.CreateUser(r.Context(), data.Username, data.Email, data.Name, password, true)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit.Record(r.Context(), user.Username, audit.ActionUserCreate, user.Username, "first-run setup", s.clientIP(r))

	// Log the new administrator straight in.
	if err := s.sessions.RenewToken(r.Context()); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.sessions.Put(r.Context(), session.KeyUserID, user.ID)
	s.sessions.Put(r.Context(), session.KeyIP, s.clientIP(r))
	s.sessions.Put(r.Context(), session.KeyUserAgent, r.UserAgent())
	s.sessions.Put(r.Context(), session.KeyLoginAt, time.Now().Unix())
	s.log.Info("first administrator registered", "user", user.Username)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// --- Avatars ---------------------------------------------------------------

var allowedPhotoTypes = []string{"image/jpeg", "image/png", "image/webp", "image/gif"}

const maxUploadPhotoSize = 1 << 20

// handleAvatar serves a user's profile photo to authenticated users.
func (s *Server) handleAvatar(w http.ResponseWriter, r *http.Request) {
	row, err := s.store.GetUserPhoto(r.Context(), r.PathValue("id"))
	if err != nil || len(row.Photo) == 0 || row.PhotoMime == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", *row.PhotoMime)
	w.Header().Set("Cache-Control", "private, max-age=300")
	w.Write(row.Photo)
}

// handleProfilePhoto lets local users upload their picture; directory
// users get theirs from the photo attribute sync.
func (s *Server) handleProfilePhoto(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	if user.Source != "local" {
		s.renderError(w, r, http.StatusBadRequest, "Directory-managed photo",
			"Directory users get their photo from the directory, not here.")
		return
	}
	if err := r.ParseMultipartForm(maxUploadPhotoSize); err != nil {
		s.renderProfile(w, r, user, "The photo must be smaller than 1 MB.", false)
		return
	}
	file, _, err := r.FormFile("photo")
	if err != nil {
		s.renderProfile(w, r, user, "Choose an image file first.", false)
		return
	}
	defer file.Close()
	photo, err := io.ReadAll(io.LimitReader(file, maxUploadPhotoSize+1))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if len(photo) > maxUploadPhotoSize {
		s.renderProfile(w, r, user, "The photo must be smaller than 1 MB.", false)
		return
	}
	mime := http.DetectContentType(photo)
	if !slices.Contains(allowedPhotoTypes, mime) {
		s.renderProfile(w, r, user, "Unsupported image format — use JPEG, PNG, WebP or GIF.", false)
		return
	}
	if err := s.store.UpdateUserPhoto(r.Context(), sqlcgen.UpdateUserPhotoParams{
		Photo: photo, PhotoMime: &mime, UpdatedAt: time.Now().UTC(), ID: user.ID,
	}); err != nil {
		s.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, "/profile", http.StatusSeeOther)
}

func (s *Server) handleProfilePhotoDelete(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	if user.Source != "local" {
		s.renderError(w, r, http.StatusBadRequest, "Directory-managed photo",
			"Directory users get their photo from the directory, not here.")
		return
	}
	if err := s.store.UpdateUserPhoto(r.Context(), sqlcgen.UpdateUserPhotoParams{
		Photo: nil, PhotoMime: nil, UpdatedAt: time.Now().UTC(), ID: user.ID,
	}); err != nil {
		s.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, "/profile", http.StatusSeeOther)
}
