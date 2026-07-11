package web

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/lporcheron/kivraid/internal/audit"
	"github.com/lporcheron/kivraid/internal/mailer"
	"github.com/lporcheron/kivraid/internal/store/sqlcgen"
)

type adminSMTPData struct {
	Enabled     bool
	Host        string
	Port        int32
	Username    string
	HasPassword bool
	FromAddress string
	FromName    string
	Encryption  string
	TestTo      string
	Saved       bool
	Tested      bool
	Error       string
}

var smtpEncryptions = []string{mailer.EncStartTLS, mailer.EncTLS, mailer.EncNone}

func (s *Server) renderSMTP(w http.ResponseWriter, r *http.Request, errMsg string) {
	cfg, err := s.store.GetSMTPSettings(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	testTo := currentUser(r).Email
	s.render(w, r, "admin_smtp.html", pageData{
		Title: "Email", Active: "email", CSRF: s.csrfToken(r.Context()),
		User: currentUser(r),
		Data: adminSMTPData{
			Enabled: cfg.Enabled, Host: cfg.Host, Port: cfg.Port, Username: cfg.Username,
			HasPassword: len(cfg.PasswordEnc) > 0, FromAddress: cfg.FromAddress, FromName: cfg.FromName,
			Encryption: cfg.Encryption, TestTo: testTo,
			Saved:  r.URL.Query().Get("saved") == "1",
			Tested: r.URL.Query().Get("tested") == "1",
			Error:  errMsg,
		},
	})
}

func (s *Server) handleAdminSMTP(w http.ResponseWriter, r *http.Request) {
	s.renderSMTP(w, r, "")
}

func (s *Server) handleAdminSMTPSave(w http.ResponseWriter, r *http.Request) {
	enabled := r.PostFormValue("enabled") == "on"
	host := strings.TrimSpace(r.PostFormValue("host"))
	username := strings.TrimSpace(r.PostFormValue("username"))
	fromAddr := strings.TrimSpace(r.PostFormValue("from_address"))
	fromName := strings.TrimSpace(r.PostFormValue("from_name"))
	encryption := r.PostFormValue("encryption")
	if !slices.Contains(smtpEncryptions, encryption) {
		encryption = mailer.EncStartTLS
	}
	port, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue("port")))
	if err != nil || port < 1 || port > 65535 {
		port = 587
	}

	fail := func(msg string) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.renderSMTP(w, r, msg)
	}
	// Only demand a complete configuration when turning delivery on.
	if enabled {
		if host == "" {
			fail("A host is required to enable email.")
			return
		}
		if fromAddr == "" {
			fail("A sender address is required to enable email.")
			return
		}
	}

	now := time.Now().UTC()
	if err := s.store.UpdateSMTPSettings(r.Context(), sqlcgen.UpdateSMTPSettingsParams{
		Enabled: enabled, Host: host, Port: int32(port), Username: username,
		FromAddress: fromAddr, FromName: fromName, Encryption: encryption, UpdatedAt: now,
	}); err != nil {
		s.serverError(w, r, err)
		return
	}

	// The password field is write-only: a submitted value replaces the
	// stored one, an explicit "clear" removes it, and an empty field leaves
	// it untouched.
	switch {
	case r.PostFormValue("clear_password") == "on":
		if err := s.store.UpdateSMTPPassword(r.Context(), sqlcgen.UpdateSMTPPasswordParams{PasswordEnc: nil, UpdatedAt: now}); err != nil {
			s.serverError(w, r, err)
			return
		}
	case r.PostFormValue("password") != "":
		enc, err := s.mailer.SealPassword(r.PostFormValue("password"))
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		if err := s.store.UpdateSMTPPassword(r.Context(), sqlcgen.UpdateSMTPPasswordParams{PasswordEnc: enc, UpdatedAt: now}); err != nil {
			s.serverError(w, r, err)
			return
		}
	}

	s.refreshSMTPCache(r.Context())
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionSMTPUpdate, "",
		"enabled="+strconv.FormatBool(enabled), s.clientIP(r))
	http.Redirect(w, r, "/admin/settings/email?saved=1", http.StatusSeeOther)
}

// handleAdminSMTPTest sends a probe email using the stored settings, even
// when delivery is not yet enabled, so the configuration can be verified.
func (s *Server) handleAdminSMTPTest(w http.ResponseWriter, r *http.Request) {
	to := strings.TrimSpace(r.PostFormValue("test_to"))
	if to == "" {
		to = currentUser(r).Email
	}
	if to == "" {
		s.renderSMTP(w, r, "Enter a recipient address for the test.")
		return
	}
	brand := s.brandDisplayName()
	err := s.mailer.SendTest(r.Context(), mailer.Message{
		To:      to,
		Subject: brand + " — SMTP test",
		Text:    fmt.Sprintf("This is a test email from %s. If you received it, SMTP is working.", brand),
		HTML:    emailHTML(brand, "SMTP test", to, fmt.Sprintf("This is a test email from %s. If you can read this, delivery is working.", brand), "Open "+brand, s.issuer()),
	})
	if errors.Is(err, mailer.ErrNotConfigured) {
		s.renderSMTP(w, r, "Set a host and sender address first, then send a test.")
		return
	}
	if err != nil {
		s.renderSMTP(w, r, "Test failed: "+err.Error())
		return
	}
	http.Redirect(w, r, "/admin/settings/email?tested=1", http.StatusSeeOther)
}
