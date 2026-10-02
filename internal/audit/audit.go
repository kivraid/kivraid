// Package audit records security-relevant events in an append-only log.
// Events are best-effort: a failure to record never blocks the action,
// and credentials are never logged.
package audit

import (
	"context"
	"log/slog"
	"time"

	"github.com/kivraid/kivraid/internal/store"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
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
	ActionKeyRetire      = "oidc.key.retire"
	ActionBrandingUpdate = "branding.update"
	ActionProviderCreate = "provider.create"
	ActionProviderUpdate = "provider.update"
	ActionProviderDelete = "provider.delete"
	ActionRouteUpdate    = "route.update"
	ActionPasswordReset  = "password.reset.request"
	ActionEmailVerify    = "email.verify"
	ActionEmailVerifySnt = "email.verify.sent"
	ActionSMTPUpdate     = "smtp.update"
	ActionSecurityUpdate = "security.update"
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
	ActionKeyRotate, ActionKeyRetire, ActionBrandingUpdate, ActionSMTPUpdate, ActionSecurityUpdate,
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

// labels are the human-readable names shown in the activity views.
var labels = map[string]string{
	ActionLogin: "Signed in", ActionLoginFailed: "Sign-in failed", ActionLoginThrottled: "Sign-in throttled",
	ActionLogout: "Signed out", ActionPasswordChange: "Password changed", ActionSessionRevoke: "Session revoked",
	ActionAppCreate: "Application created", ActionAppUpdate: "Application updated", ActionAppDelete: "Application deleted",
	ActionSecretRotate: "Client secret rotated",
	ActionLdapCreate:   "Directory added", ActionLdapUpdate: "Directory updated", ActionLdapDelete: "Directory deleted",
	ActionLdapSync: "Directory synced", ActionOIDCGrant: "Application access granted", ActionOIDCDeny: "Application access denied",
	ActionUserCreate: "User created", ActionUserUpdate: "User updated", ActionUserDelete: "User deleted",
	ActionUserPWReset: "Password reset by admin", ActionImpersonate: "Impersonation started",
	ActionImpersonateEnd: "Impersonation ended", ActionMFAEnable: "Two-factor enabled", ActionMFADisable: "Two-factor disabled",
	ActionMFARecovery: "Recovery codes regenerated", ActionPasskeyAdd: "Passkey added", ActionPasskeyRemove: "Passkey removed",
	ActionPasskeyLogin: "Signed in with a passkey", ActionGroupCreate: "Group created", ActionGroupUpdate: "Group updated",
	ActionGroupDelete: "Group deleted", ActionKeyRotate: "Signing key rotated", ActionKeyRetire: "Old signing keys retired", ActionBrandingUpdate: "Branding updated",
	ActionProviderCreate: "Provider added", ActionProviderUpdate: "Provider updated", ActionProviderDelete: "Provider deleted",
	ActionRouteUpdate: "Routing updated", ActionPasswordReset: "Password reset link sent", ActionEmailVerify: "Email verified",
	ActionEmailVerifySnt: "Verification email sent", ActionSMTPUpdate: "Email settings updated",
	ActionSecurityUpdate: "Security settings updated",
}

// Label returns the human-readable name of an action, or the raw action
// for an unknown one (e.g. recorded by a newer version).
func Label(action string) string {
	if l, ok := labels[action]; ok {
		return l
	}
	return action
}

// Tone classifies an action for display: "danger" for failures and denials,
// "warn" for destructive or sensitive changes, "" otherwise.
func Tone(action string) string {
	switch action {
	case ActionLoginFailed, ActionLoginThrottled, ActionOIDCDeny:
		return "danger"
	case ActionAppDelete, ActionLdapDelete, ActionUserDelete, ActionGroupDelete, ActionProviderDelete,
		ActionMFADisable, ActionPasskeyRemove, ActionImpersonate, ActionSecretRotate, ActionKeyRotate,
		ActionUserPWReset, ActionSessionRevoke:
		return "warn"
	}
	return ""
}
