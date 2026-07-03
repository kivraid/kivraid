package web

import (
	"net/http"
	"strings"

	"github.com/lporcheron/kivraid/internal/audit"
	"github.com/lporcheron/kivraid/internal/session"
)

// writeJSONRaw sends an already-marshalled JSON payload.
func writeJSONRaw(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(body)
}

// handlePasskeyRegisterBegin returns the credential-creation options for
// adding a passkey and stashes the ceremony state in the session.
func (s *Server) handlePasskeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	if s.webauthn == nil {
		http.NotFound(w, r)
		return
	}
	user := currentUser(r)
	options, sess, err := s.webauthn.BeginRegistration(r.Context(), user)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.sessions.Put(r.Context(), session.KeyWebAuthnReg, string(sess))
	writeJSONRaw(w, options)
}

// handlePasskeyRegisterFinish verifies the attestation (body) and stores
// the new credential under the name from the ?name query parameter.
func (s *Server) handlePasskeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	if s.webauthn == nil {
		http.NotFound(w, r)
		return
	}
	user := currentUser(r)
	sess := s.sessions.GetString(r.Context(), session.KeyWebAuthnReg)
	if sess == "" {
		http.Error(w, "no registration in progress", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if err := s.webauthn.FinishRegistration(r.Context(), user, []byte(sess), r, name); err != nil {
		s.log.Warn("passkey registration failed", "user", user.Username, "err", err)
		http.Error(w, "registration could not be verified", http.StatusBadRequest)
		return
	}
	s.sessions.Remove(r.Context(), session.KeyWebAuthnReg)
	s.audit.Record(r.Context(), user.Username, audit.ActionPasskeyAdd, "", name, clientIP(r))
	writeJSONRaw(w, []byte(`{"ok":true}`))
}

// handlePasskeyDelete removes one of the current user's passkeys.
func (s *Server) handlePasskeyDelete(w http.ResponseWriter, r *http.Request) {
	if s.webauthn == nil {
		http.NotFound(w, r)
		return
	}
	user := currentUser(r)
	if err := s.webauthn.Delete(r.Context(), user.ID, r.PathValue("id")); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit.Record(r.Context(), user.Username, audit.ActionPasskeyRemove, "", "", clientIP(r))
	http.Redirect(w, r, "/profile", http.StatusSeeOther)
}

// handlePasskeyLoginBegin starts a usernameless passkey assertion.
func (s *Server) handlePasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	if s.webauthn == nil {
		http.NotFound(w, r)
		return
	}
	options, sess, err := s.webauthn.BeginLogin()
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.sessions.Put(r.Context(), session.KeyWebAuthnLogin, string(sess))
	writeJSONRaw(w, options)
}

// handlePasskeyLoginFinish verifies the assertion (body). A passkey is
// phishing-resistant, so a successful assertion completes login outright —
// no password and no second factor.
func (s *Server) handlePasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	if s.webauthn == nil {
		http.NotFound(w, r)
		return
	}
	sess := s.sessions.GetString(r.Context(), session.KeyWebAuthnLogin)
	if sess == "" {
		http.Error(w, "no login in progress", http.StatusBadRequest)
		return
	}
	next := s.safeNext(r.URL.Query().Get("next"), "/")
	userID, err := s.webauthn.FinishLogin(r.Context(), []byte(sess), r)
	if err != nil {
		s.log.Warn("passkey login failed", "err", err)
		s.audit.Record(r.Context(), "", audit.ActionLoginFailed, "", "passkey", clientIP(r))
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}
	s.sessions.Remove(r.Context(), session.KeyWebAuthnLogin)
	user, err := s.store.GetUserByID(r.Context(), userID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.completeLogin(r, user, next)
	s.audit.Record(r.Context(), user.Username, audit.ActionPasskeyLogin, "", "", clientIP(r))
	writeJSONRaw(w, []byte(`{"next":`+jsonString(next)+`}`))
}

// jsonString quotes a string as a JSON literal.
func jsonString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				const hex = "0123456789abcdef"
				b.WriteString(`\u00`)
				b.WriteByte(hex[r>>4])
				b.WriteByte(hex[r&0xf])
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}
