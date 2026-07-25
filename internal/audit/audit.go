// Package audit records security-relevant events in an append-only log.
// Events are best-effort: a failure to record never blocks the action,
// and credentials are never logged.
package audit

import (
	"context"
	"log/slog"
	"time"

	"github.com/lporcheron/kivraid/internal/store"
	"github.com/lporcheron/kivraid/internal/store/sqlcgen"
)

const (
	ActionLogin          = "login"
	ActionLoginFailed    = "login.failed"
	ActionLoginThrottled = "login.throttled"
	ActionLogout         = "logout"
	ActionPasswordChange = "password.change"
	ActionSessionRevoke  = "session.revoke"
	ActionAppCreate      = "app.create"
	ActionAppUpdate      = "app.update"
	ActionAppDelete      = "app.delete"
	ActionSecretRotate   = "app.secret.rotate"
	ActionLdapCreate     = "ldap.create"
	ActionLdapUpdate     = "ldap.update"
	ActionLdapDelete     = "ldap.delete"
	ActionLdapSync       = "ldap.sync"
	ActionOIDCGrant      = "oidc.grant"
	ActionOIDCDeny       = "oidc.deny"
	ActionUserCreate     = "user.create"
	ActionUserUpdate     = "user.update"
	ActionUserDelete     = "user.delete"
	ActionUserPWReset    = "user.password.reset"
	ActionImpersonate    = "user.impersonate"
	ActionImpersonateEnd = "user.impersonate.end"
	ActionMFAEnable      = "mfa.enable"
	ActionMFADisable     = "mfa.disable"
	ActionMFARecovery    = "mfa.recovery"
	ActionPasskeyAdd     = "passkey.add"
	ActionPasskeyRemove  = "passkey.remove"
	ActionPasskeyLogin   = "passkey.login"
	ActionGroupCreate    = "group.create"
	ActionGroupUpdate    = "group.update"
	ActionGroupDelete    = "group.delete"
	ActionKeyRotate      = "oidc.key.rotate"
	ActionBrandingUpdate = "branding.update"
	ActionProviderCreate = "provider.create"
	ActionProviderUpdate = "provider.update"
	ActionProviderDelete = "provider.delete"
	ActionRouteUpdate    = "route.update"
	ActionPasswordReset  = "password.reset.request"
	ActionEmailVerify    = "email.verify"
	ActionEmailVerifySnt = "email.verify.sent"
	ActionSMTPUpdate     = "smtp.update"
)

// Actions lists every action the recorder emits, grouped roughly by area.
// It backs the action filter on the activity view; keep it in sync with the
// constants above.
var Actions = []string{
	ActionLogin, ActionLoginFailed, ActionLoginThrottled, ActionLogout,
	ActionPasswordChange, ActionSessionRevoke,
	ActionMFAEnable, ActionMFADisable, ActionMFARecovery,
	ActionPasskeyAdd, ActionPasskeyRemove, ActionPasskeyLogin,
	ActionOIDCGrant, ActionOIDCDeny,
	ActionAppCreate, ActionAppUpdate, ActionAppDelete, ActionSecretRotate,
	ActionLdapCreate, ActionLdapUpdate, ActionLdapDelete, ActionLdapSync,
	ActionUserCreate, ActionUserUpdate, ActionUserDelete, ActionUserPWReset,
	ActionImpersonate, ActionImpersonateEnd,
	ActionPasswordReset, ActionEmailVerify, ActionEmailVerifySnt,
	ActionGroupCreate, ActionGroupUpdate, ActionGroupDelete,
	ActionProviderCreate, ActionProviderUpdate, ActionProviderDelete, ActionRouteUpdate,
	ActionKeyRotate, ActionBrandingUpdate, ActionSMTPUpdate,
}

type Recorder struct {
	store *store.Store
	log   *slog.Logger
}

func NewRecorder(st *store.Store, log *slog.Logger) *Recorder {
	return &Recorder{store: st, log: log}
}

// Record appends an event. actor is a username (empty for anonymous),
// object names the thing acted on, detail carries free-form context.
func (r *Recorder) Record(ctx context.Context, actor, action, object, detail, ip string) {
	err := r.store.InsertAudit(ctx, sqlcgen.InsertAuditParams{
		Ts:     time.Now().UTC(),
		Actor:  actor,
		Action: action,
		Object: object,
		Detail: detail,
		Ip:     ip,
	})
	if err != nil {
		r.log.Warn("audit record failed", "action", action, "err", err)
	}
}
