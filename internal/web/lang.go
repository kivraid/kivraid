package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kivraid/kivraid/internal/i18n"
	"github.com/kivraid/kivraid/internal/session"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
)

// The UI language is resolved per request: the language cookie (set by the
// picker, and from the account's saved preference at sign-in), else the
// browser's Accept-Language, else English. A signed-in user's choice is also
// stored on their account so emails reach them in the same language.
const langCookie = "kivraid_lang"

type ctxKeyLangType struct{}

var ctxKeyLang ctxKeyLangType

// withLang resolves the request language once and stores it in the context.
func (s *Server) withLang(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lang := ""
		if c, err := r.Cookie(langCookie); err == nil && i18n.Supported(c.Value) {
			lang = c.Value
		}
		if lang == "" {
			lang = i18n.Negotiate(r.Header.Get("Accept-Language"))
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKeyLang, lang)))
	})
}

// langOf returns the request's UI language.
func langOf(r *http.Request) string {
	if l, ok := r.Context().Value(ctxKeyLang).(string); ok {
		return l
	}
	return i18n.Negotiate(r.Header.Get("Accept-Language"))
}

// t translates a user-facing message into the request's language; args
// fill its fmt verbs. Every message shown to a user goes through it.
func (s *Server) t(r *http.Request, msg string, args ...any) string {
	return i18n.T(langOf(r), msg, args...)
}

// userLang is the language to write to a user outside a request of theirs
// (emails): their saved preference, else the language of the request that
// triggers the message.
func userLang(user sqlcgen.User, r *http.Request) string {
	if i18n.Supported(user.Locale) {
		return user.Locale
	}
	if r != nil {
		return langOf(r)
	}
	return i18n.Default
}

func (s *Server) setLangCookie(w http.ResponseWriter, lang string) {
	http.SetCookie(w, &http.Cookie{
		Name: langCookie, Value: lang, Path: "/", MaxAge: 400 * 24 * 3600,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: strings.HasPrefix(s.cfg.BaseURL, "https://"),
	})
}

// handleSetLang switches the UI language (GET /lang?set=fr&next=...), and
// saves it on the account when signed in.
func (s *Server) handleSetLang(w http.ResponseWriter, r *http.Request) {
	lang := r.URL.Query().Get("set")
	// Back to the page the picker was on: next, else the same-origin referer.
	next := r.URL.Query().Get("next")
	if next == "" {
		if ref, err := url.Parse(r.Referer()); err == nil && ref.Host == r.Host {
			next = ref.RequestURI()
		}
	}
	next = s.safeNext(next, "/")
	if !i18n.Supported(lang) {
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}
	s.setLangCookie(w, lang)
	if userID := s.sessions.GetString(r.Context(), session.KeyUserID); userID != "" {
		if err := s.store.SetUserLocale(r.Context(), sqlcgen.SetUserLocaleParams{Locale: lang, ID: userID}); err != nil {
			s.log.Warn("save language preference", "err", err)
		}
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// --- Localized formatting ----------------------------------------------------

var frMonths = []string{"janv.", "févr.", "mars", "avr.", "mai", "juin", "juil.", "août", "sept.", "oct.", "nov.", "déc."}

// formatDate renders a calendar date in the language's usual short form.
func formatDate(lang string, t time.Time) string {
	if lang == "fr" {
		return fmt.Sprintf("%d %s %d", t.Day(), frMonths[t.Month()-1], t.Year())
	}
	return t.Format("Jan 2, 2006")
}

// sinceIn renders how long ago t was, coarsely: "just now", "5 minutes
// ago", "3 days ago", then a date for anything older than a month.
func sinceIn(lang string, t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return i18n.T(lang, "just now")
	case d < time.Hour:
		return i18n.N(lang, int64(d/time.Minute), "%d minute ago", "%d minutes ago")
	case d < 24*time.Hour:
		return i18n.N(lang, int64(d/time.Hour), "%d hour ago", "%d hours ago")
	case d < 30*24*time.Hour:
		return i18n.N(lang, int64(d/(24*time.Hour)), "%d day ago", "%d days ago")
	}
	return i18n.T(lang, "on %s", formatDate(lang, t))
}

// humanDurationIn renders seconds for reading: "5 minutes", "30 days".
func humanDurationIn(lang string, n int64) string {
	units := []struct {
		secs       int64
		one, other string
	}{
		{86400, "%d day", "%d days"}, {3600, "%d hour", "%d hours"},
		{60, "%d minute", "%d minutes"}, {1, "%d second", "%d seconds"},
	}
	for _, u := range units {
		if n >= u.secs && n%u.secs == 0 {
			return i18n.N(lang, n/u.secs, u.one, u.other)
		}
	}
	return i18n.N(lang, n, "%d second", "%d seconds")
}

// jsMessages are the strings app.js shows; the page hands them over already
// translated (data-i18n on <body>).
var jsMessages = []string{
	"Copied", "Cancel", "Confirm", "Sign-ins", "Failed", "Sign-ins per day, last 7 days", "Day",
	"%s: %d sign-ins, %d failed", "%s · %d sign-ins · %d failed",
	"That file is too large (max %d MB).", "Recovery code", "Authentication code",
	"Use an authenticator code instead", "Lost your device? Use a recovery code",
	"Passkey sign-in failed.", "Passkey added.", "Could not add passkey.",
	"Remove %s", "Show secret", "Hide secret", "This browser does not support passkeys.",
}

func jsI18n(lang string) string {
	m := make(map[string]string, len(jsMessages))
	for _, msg := range jsMessages {
		if tr, ok := i18n.Lookup(lang, msg); ok {
			m[msg] = tr
		}
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// --- Translatable errors and deferred messages --------------------------------

// uiError is a user-facing error whose English message is translated when
// it is shown (see tErr). Error() keeps the English text for logs and tests.
type uiError struct {
	msg  string
	args []any
}

func (e uiError) Error() string {
	if len(e.args) == 0 {
		return e.msg
	}
	return fmt.Sprintf(e.msg, e.args...)
}

// errorf builds a translatable user-facing error; msg is the English message
// with fmt verbs.
func errorf(msg string, args ...any) error { return uiError{msg: msg, args: args} }

// tErr renders an error for the user: translated when it came from errorf,
// verbatim otherwise (e.g. a directory's own error text).
func (s *Server) tErr(r *http.Request, err error) string {
	var ue uiError
	if errors.As(err, &ue) {
		return s.t(r, ue.msg, ue.args...)
	}
	return err.Error()
}

// msgid marks an English message that is stored now and translated later,
// where it is displayed (for instance a label in a table rendered with
// {{t .Label}}). It returns msg unchanged.
func msgid(msg string) string { return msg }
