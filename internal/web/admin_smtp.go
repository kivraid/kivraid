package web

import (
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/kivraid/kivraid/internal/audit"
	"github.com/kivraid/kivraid/internal/mailer"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
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
	Error       string
	Notice      string
}

var smtpEncryptions = []string{mailer.EncStartTLS, mailer.EncTLS, mailer.EncNone}

func (s *Server) renderSMTP(w http.ResponseWriter, r *http.Request, errMsg string) {
	cfg, err := s.store.GetSMTPSettings(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.renderSMTPForm(w, r, cfg, currentUser(r).Email, errMsg, "")
}

// renderSMTPForm shows the email settings page with the given values: the
// stored ones, or what the admin just typed (after a test).
func (s *Server) renderSMTPForm(w http.ResponseWriter, r *http.Request, cfg sqlcgen.SmtpSetting, testTo, errMsg, notice string) {
	s.render(w, r, "admin_smtp.html", pageData{
		Title: "Email", Active: "email", CSRF: s.csrfToken(r.Context()),
		User: currentUser(r),
		Data: adminSMTPData{
			Enabled: cfg.Enabled, Host: cfg.Host, Port: cfg.Port, Username: cfg.Username,
			HasPassword: len(cfg.PasswordEnc) > 0, FromAddress: cfg.FromAddress, FromName: cfg.FromName,
			Encryption: cfg.Encryption, TestTo: testTo,
			Saved:  r.URL.Query().Get("saved") == "1",
			Error:  errMsg,
			Notice: notice,
		},
	})
}

func (s *Server) handleAdminSMTP(w http.ResponseWriter, r *http.Request) {
	s.renderSMTP(w, r, "")
}

// smtpFormSettings reads the settings form over the stored settings. The
// password field is write-only: a submitted value replaces the stored one,
// an explicit "clear" removes it, and an empty field keeps it. passwordSet
// reports whether the stored password changes.
func (s *Server) smtpFormSettings(r *http.Request) (cfg sqlcgen.SmtpSetting, passwordSet bool, err error) {
	cfg, err = s.store.GetSMTPSettings(r.Context())
	if err != nil {
		return cfg, false, err
	}
	cfg.Enabled = r.PostFormValue("enabled") == "on"
	cfg.Host = strings.TrimSpace(r.PostFormValue("host"))
	cfg.Username = strings.TrimSpace(r.PostFormValue("username"))
	cfg.FromAddress = strings.TrimSpace(r.PostFormValue("from_address"))
	cfg.FromName = strings.TrimSpace(r.PostFormValue("from_name"))
	cfg.Encryption = r.PostFormValue("encryption")
	if !slices.Contains(smtpEncryptions, cfg.Encryption) {
		cfg.Encryption = mailer.EncStartTLS
	}
	port, perr := strconv.Atoi(strings.TrimSpace(r.PostFormValue("port")))
	if perr != nil || port < 1 || port > 65535 {
		port = 587
	}
	cfg.Port = int32(port)
	switch {
	case r.PostFormValue("clear_password") == "on":
		cfg.PasswordEnc, passwordSet = nil, true
	case r.PostFormValue("password") != "":
		if cfg.PasswordEnc, err = s.mailer.SealPassword(r.PostFormValue("password")); err != nil {
			return cfg, false, err
		}
		passwordSet = true
	}
	return cfg, passwordSet, nil
}

func (s *Server) handleAdminSMTPSave(w http.ResponseWriter, r *http.Request) {
	cfg, passwordSet, err := s.smtpFormSettings(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	enabled, host, fromAddr := cfg.Enabled, cfg.Host, cfg.FromAddress

	fail := func(msg string) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.renderSMTP(w, r, msg)
	}
	// Only demand a complete configuration when turning delivery on.
	if enabled {
		if host == "" {
			fail(s.t(r, "A host is required to enable email."))
			return
		}
		if fromAddr == "" {
			fail(s.t(r, "A sender address is required to enable email."))
			return
		}
	}

	now := time.Now().UTC()
	if err := s.store.UpdateSMTPSettings(r.Context(), sqlcgen.UpdateSMTPSettingsParams{
		Enabled: cfg.Enabled, Host: cfg.Host, Port: cfg.Port, Username: cfg.Username,
		FromAddress: cfg.FromAddress, FromName: cfg.FromName, Encryption: cfg.Encryption, UpdatedAt: now,
	}); err != nil {
		s.serverError(w, r, err)
		return
	}
	if passwordSet {
		if err := s.store.UpdateSMTPPassword(r.Context(), sqlcgen.UpdateSMTPPasswordParams{
			PasswordEnc: cfg.PasswordEnc, UpdatedAt: now,
		}); err != nil {
			s.serverError(w, r, err)
			return
		}
	}

	s.refreshSMTPCache(r.Context())
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionSMTPUpdate, "",
		"enabled="+strconv.FormatBool(enabled), s.clientIP(r))
	http.Redirect(w, r, "/admin/settings/email?saved=1", http.StatusSeeOther)
}

// handleAdminSMTPTest sends a probe email with the settings as currently
// typed in the form — saved or not, enabled or not — so a configuration can
// be verified before it is saved. Nothing is stored.
func (s *Server) handleAdminSMTPTest(w http.ResponseWriter, r *http.Request) {
	cfg, _, err := s.smtpFormSettings(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	to := strings.TrimSpace(r.PostFormValue("test_to"))
	if to == "" {
		to = currentUser(r).Email
	}
	fail := func(msg string) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.renderSMTPForm(w, r, cfg, to, msg, "")
	}
	if to == "" {
		fail(s.t(r, "Enter a recipient address for the test."))
		return
	}
	brand := s.brandDisplayName()
	err = s.mailer.SendWith(r.Context(), cfg, mailer.Message{
		To:      to,
		Subject: s.t(r, "%s — SMTP test", brand),
		Text:    s.t(r, "This is a test email from %s. If you received it, SMTP is working.", brand),
		HTML:    emailHTML(langOf(r), brand, s.t(r, "SMTP test"), to, s.t(r, "This is a test email from %s. If you can read this, delivery is working.", brand), s.t(r, "Open %s", brand), s.issuer()),
	})
	if errors.Is(err, mailer.ErrNotConfigured) {
		fail(s.t(r, "Set a host and sender address first, then send a test."))
		return
	}
	if err != nil {
		fail(s.t(r, "Test failed: %s", err.Error()))
		return
	}
	notice := s.t(r, "Test email sent to %s. These settings are not saved yet — click Save changes to keep them.", to)
	if r.PostFormValue("password") != "" {
		notice += " " + s.t(r, "Re-enter the password before saving: it is never sent back to the browser.")
	}
	s.renderSMTPForm(w, r, cfg, to, "", notice)
}
