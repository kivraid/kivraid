package web

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/kivraid/kivraid/internal/secrets"
	"github.com/kivraid/kivraid/internal/session"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
)

// Remembered accounts back the Google-style account chooser: after a
// successful sign-in, the browser keeps an encrypted cookie listing the
// users who signed in on it. The login page then offers those accounts,
// with their name and avatar, instead of a blank identifier field.
//
// This never reveals anything to a stranger: the identifier step still does
// no account lookup, and an avatar is only shown for an account this very
// browser has already authenticated as.
const (
	accountsCookie    = "kivraid_accounts"
	accountsLifetime  = 180 * 24 * time.Hour
	maxRememberedAcct = 5
)

// rememberedAccount is a chooser entry on the login and password pages.
type rememberedAccount struct {
	ID       string
	Name     string
	Login    string // email, or username when there is none
	HasPhoto bool
}

func newRememberedAccount(u sqlcgen.User) rememberedAccount {
	login := u.Email
	if login == "" {
		login = u.Username
	}
	name := u.Name
	if name == "" {
		name = u.Username
	}
	return rememberedAccount{ID: u.ID, Name: name, Login: login, HasPhoto: u.PhotoMime != nil}
}

func (s *Server) accountsKey() [32]byte {
	return secrets.DeriveKey(s.cfg.SecretKey, "remembered-accounts")
}

// rememberedIDs returns the user IDs in the account cookie, most recent
// first. A missing, tampered or stale (rotated key) cookie reads as empty.
func (s *Server) rememberedIDs(r *http.Request) []string {
	c, err := r.Cookie(accountsCookie)
	if err != nil {
		return nil
	}
	sealed, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return nil
	}
	plain, err := secrets.Open(s.accountsKey(), sealed)
	if err != nil {
		return nil
	}
	var ids []string
	if json.Unmarshal(plain, &ids) != nil {
		return nil
	}
	if len(ids) > maxRememberedAcct {
		ids = ids[:maxRememberedAcct]
	}
	return ids
}

// writeRememberedIDs stores ids in the account cookie, or clears it when
// the list is empty.
func (s *Server) writeRememberedIDs(w http.ResponseWriter, ids []string) {
	cookie := &http.Cookie{
		Name: accountsCookie, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Secure: strings.HasPrefix(s.cfg.BaseURL, "https://"),
	}
	if len(ids) == 0 {
		cookie.MaxAge = -1
		http.SetCookie(w, cookie)
		return
	}
	plain, _ := json.Marshal(ids)
	sealed, err := secrets.Seal(s.accountsKey(), plain)
	if err != nil {
		s.log.Warn("seal remembered accounts", "err", err)
		return
	}
	cookie.Value = base64.RawURLEncoding.EncodeToString(sealed)
	cookie.MaxAge = int(accountsLifetime / time.Second)
	http.SetCookie(w, cookie)
}

// rememberAccount moves userID to the front of the account cookie.
func (s *Server) rememberAccount(w http.ResponseWriter, r *http.Request, userID string) {
	ids := slices.DeleteFunc(s.rememberedIDs(r), func(id string) bool { return id == userID })
	ids = append([]string{userID}, ids...)
	if len(ids) > maxRememberedAcct {
		ids = ids[:maxRememberedAcct]
	}
	s.writeRememberedIDs(w, ids)
}

// rememberedAccounts loads the cookie's accounts that still exist and are
// active, in cookie order.
func (s *Server) rememberedAccounts(ctx context.Context, r *http.Request) []sqlcgen.User {
	var out []sqlcgen.User
	for _, id := range s.rememberedIDs(r) {
		if u, err := s.store.GetUserByID(ctx, id); err == nil && u.Active {
			out = append(out, u)
		}
	}
	return out
}

// rememberedAccount returns the remembered, active account with this ID.
func (s *Server) rememberedAccount(ctx context.Context, r *http.Request, id string) (sqlcgen.User, bool) {
	if id == "" || !slices.Contains(s.rememberedIDs(r), id) {
		return sqlcgen.User{}, false
	}
	u, err := s.store.GetUserByID(ctx, id)
	if err != nil || !u.Active {
		return sqlcgen.User{}, false
	}
	return u, true
}

// matchRememberedAccount returns the remembered account whose username or
// email equals the typed identifier, so the password step can greet a known
// user even when they typed it instead of picking it.
func (s *Server) matchRememberedAccount(ctx context.Context, r *http.Request, identifier string) (sqlcgen.User, bool) {
	for _, u := range s.rememberedAccounts(ctx, r) {
		if strings.EqualFold(u.Username, identifier) || (u.Email != "" && strings.EqualFold(u.Email, identifier)) {
			return u, true
		}
	}
	return sqlcgen.User{}, false
}

// handleLoginAccount signs in with an account picked in the chooser: a
// federated account goes straight to its provider, any other one to the
// password step with its identity shown.
func (s *Server) handleLoginAccount(w http.ResponseWriter, r *http.Request) {
	next := s.safeNext(r.PostFormValue("next"), "/")
	user, ok := s.rememberedAccount(r.Context(), r, r.PostFormValue("account"))
	if !ok {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(next), http.StatusSeeOther)
		return
	}
	if user.UpstreamSourceID != nil && s.broker != nil {
		if p, err := s.store.GetUpstreamProvider(r.Context(), *user.UpstreamSourceID); err == nil && p.Enabled {
			http.Redirect(w, r, "/login/upstream/"+p.ID+"/start?next="+url.QueryEscape(next), http.StatusSeeOther)
			return
		}
	}
	s.beginLogin(w, r, user.Username, next)
}

// handleLoginAccountForget removes an account from this browser's chooser.
func (s *Server) handleLoginAccountForget(w http.ResponseWriter, r *http.Request) {
	id := r.PostFormValue("account")
	s.writeRememberedIDs(w, slices.DeleteFunc(s.rememberedIDs(r), func(v string) bool { return v == id }))
	http.Redirect(w, r, "/login?next="+url.QueryEscape(s.safeNext(r.PostFormValue("next"), "")), http.StatusSeeOther)
}

// pendingAccount returns the chooser identity to show on the password step:
// the remembered account matching the pending identifier, if any.
func (s *Server) pendingAccount(r *http.Request, identifier string) *rememberedAccount {
	u, ok := s.rememberedAccount(r.Context(), r, s.sessions.GetString(r.Context(), session.KeyPendingAccount))
	if !ok || (!strings.EqualFold(u.Username, identifier) && !strings.EqualFold(u.Email, identifier)) {
		return nil
	}
	a := newRememberedAccount(u)
	return &a
}
