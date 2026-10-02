package web

import (
	"context"
	"fmt"
	"html"
	"time"

	"github.com/kivraid/kivraid/internal/mailer"
	"github.com/kivraid/kivraid/internal/oidcserver"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
)

const (
	purposePasswordReset = "password_reset"
	purposeEmailVerify   = "email_verify"

	resetTokenTTL  = time.Hour
	verifyTokenTTL = 24 * time.Hour
	// inviteTokenTTL leaves a new user a few days to accept an invitation.
	inviteTokenTTL = 72 * time.Hour
)

// refreshSMTPCache updates the cached "is email configured" flag that
// templates read to show or hide email-dependent affordances.
func (s *Server) refreshSMTPCache(ctx context.Context) {
	s.smtpEnabled.Store(s.mailer != nil && s.mailer.Enabled(ctx))
}

// issueEmailToken mints a single-use token for a purpose, replacing any
// earlier token of that purpose for the user, and returns the raw value to
// embed in the link. Only the hash is stored.
func (s *Server) issueEmailToken(ctx context.Context, purpose, userID, email string, ttl time.Duration) (string, error) {
	if err := s.store.DeleteEmailTokensByUserPurpose(ctx, sqlcgen.DeleteEmailTokensByUserPurposeParams{
		UserID: userID, Purpose: purpose,
	}); err != nil {
		return "", err
	}
	raw := randomHex(32)
	now := time.Now().UTC()
	if err := s.store.CreateEmailToken(ctx, sqlcgen.CreateEmailTokenParams{
		TokenHash: oidcserver.HashToken(raw), Purpose: purpose, UserID: userID,
		Email: email, ExpiresAt: now.Add(ttl), CreatedAt: now,
	}); err != nil {
		return "", err
	}
	return raw, nil
}

// lookupEmailToken returns a token row if it exists, matches the purpose and
// has not expired. It does not delete it (used by the reset GET, which only
// displays the form).
func (s *Server) lookupEmailToken(ctx context.Context, purpose, raw string) (sqlcgen.EmailToken, bool) {
	if raw == "" {
		return sqlcgen.EmailToken{}, false
	}
	row, err := s.store.GetEmailToken(ctx, oidcserver.HashToken(raw))
	if err != nil || row.Purpose != purpose || time.Now().UTC().After(row.ExpiresAt) {
		return sqlcgen.EmailToken{}, false
	}
	return row, true
}

// consumeEmailToken validates a token and deletes it (single use), returning
// the row on success.
func (s *Server) consumeEmailToken(ctx context.Context, purpose, raw string) (sqlcgen.EmailToken, bool) {
	row, ok := s.lookupEmailToken(ctx, purpose, raw)
	if !ok {
		return sqlcgen.EmailToken{}, false
	}
	_ = s.store.DeleteEmailToken(ctx, row.TokenHash)
	return row, true
}

// sendPasswordResetEmail delivers the reset link to the user.
func (s *Server) sendPasswordResetEmail(ctx context.Context, user sqlcgen.User, rawToken string) error {
	brand := s.brandDisplayName()
	link := s.issuer() + "/reset?token=" + rawToken
	subject := "Reset your " + brand + " password"
	intro := fmt.Sprintf("We received a request to reset the password for your %s account. "+
		"This link is valid for one hour. If you didn't request it, you can ignore this email.", brand)
	text := fmt.Sprintf("Hi %s,\n\n%s\n\n%s\n", user.Name, intro, link)
	return s.mailer.Send(ctx, mailer.Message{
		To: user.Email, Subject: subject, Text: text,
		HTML: emailHTML(brand, "Reset your password", user.Name, intro, "Choose a new password", link),
	})
}

// sendInvitationEmail mails a new user a link to choose their password. The
// link is a password-reset token with a longer lifetime; following it also
// verifies the address.
func (s *Server) sendInvitationEmail(ctx context.Context, user sqlcgen.User) error {
	raw, err := s.issueEmailToken(ctx, purposePasswordReset, user.ID, user.Email, inviteTokenTTL)
	if err != nil {
		return err
	}
	brand := s.brandDisplayName()
	link := s.issuer() + "/reset?token=" + raw
	subject := "You're invited to " + brand
	intro := fmt.Sprintf("An account was created for you on %s (username: %s). "+
		"Choose a password to start using it. This link is valid for 3 days.", brand, user.Username)
	text := fmt.Sprintf("Hi %s,\n\n%s\n\n%s\n", user.Name, intro, link)
	return s.mailer.Send(ctx, mailer.Message{
		To: user.Email, Subject: subject, Text: text,
		HTML: emailHTML(brand, "Welcome to "+brand, user.Name, intro, "Choose my password", link),
	})
}

// sendNewDeviceAlert emails the user that their account was just used from
// a browser it had never signed in on. It runs in the background so a slow
// or failing mail server never delays the sign-in.
func (s *Server) sendNewDeviceAlert(user sqlcgen.User, userAgent, ip, method string) {
	if !s.smtpEnabled.Load() {
		return
	}
	brand := s.brandDisplayName()
	when := time.Now().UTC().Format("Monday, January 2, 2006 at 15:04 UTC")
	how := map[string]string{
		loginPassword: "password", loginPasswordTOTP: "password and authenticator code",
		loginPasskey: "passkey", loginFederated: "your identity provider",
	}[method]
	intro := fmt.Sprintf("Your %s account was used to sign in from a new device: %s, from %s, on %s, with %s. "+
		"If this was you, there is nothing to do. If not, change your password now and sign out the sessions you don't recognize.",
		brand, summarizeUA(userAgent), ip, when, how)
	link := s.issuer() + "/sessions"
	text := fmt.Sprintf("Hi %s,\n\n%s\n\nReview your sessions: %s\n", user.Name, intro, link)
	msg := mailer.Message{
		To: user.Email, Subject: "New sign-in to your " + brand + " account", Text: text,
		HTML: emailHTML(brand, "New sign-in", user.Name, intro, "Review my sessions", link),
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := s.mailer.Send(ctx, msg); err != nil {
			s.log.Warn("send new-device alert", "user", user.Username, "err", err)
		}
	}()
}

// sendVerificationEmail issues a verification token and mails the link.
func (s *Server) sendVerificationEmail(ctx context.Context, user sqlcgen.User) error {
	raw, err := s.issueEmailToken(ctx, purposeEmailVerify, user.ID, user.Email, verifyTokenTTL)
	if err != nil {
		return err
	}
	brand := s.brandDisplayName()
	link := s.issuer() + "/verify-email?token=" + raw
	subject := "Verify your email for " + brand
	intro := fmt.Sprintf("Confirm that this address belongs to your %s account. "+
		"This link is valid for 24 hours.", brand)
	text := fmt.Sprintf("Hi %s,\n\n%s\n\n%s\n", user.Name, intro, link)
	return s.mailer.Send(ctx, mailer.Message{
		To: user.Email, Subject: subject, Text: text,
		HTML: emailHTML(brand, "Verify your email", user.Name, intro, "Verify email", link),
	})
}

// emailHTML renders a minimal, inline-styled HTML email with a single call
// to action. Everything is inline because mail clients strip <style> and CSP
// does not apply to email.
func emailHTML(brand, heading, name, body, buttonLabel, link string) string {
	e := html.EscapeString
	return fmt.Sprintf(`<!doctype html><html><body style="margin:0;background:#f4f4f5;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#18181b">
<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="padding:32px 16px"><tr><td align="center">
<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="max-width:480px;background:#ffffff;border:1px solid #e4e4e7;border-radius:14px;overflow:hidden">
<tr><td style="padding:28px 32px 8px"><div style="font-size:13px;font-weight:600;letter-spacing:.02em;color:#71717a;text-transform:uppercase">%s</div>
<h1 style="margin:12px 0 0;font-size:20px;font-weight:600;color:#18181b">%s</h1></td></tr>
<tr><td style="padding:8px 32px 0;font-size:15px;line-height:1.55;color:#3f3f46">Hi %s,</td></tr>
<tr><td style="padding:12px 32px 0;font-size:15px;line-height:1.55;color:#3f3f46">%s</td></tr>
<tr><td style="padding:24px 32px 8px"><a href="%s" style="display:inline-block;background:#6d28d9;color:#ffffff;text-decoration:none;font-size:15px;font-weight:600;padding:11px 20px;border-radius:9px">%s</a></td></tr>
<tr><td style="padding:16px 32px 28px;font-size:12px;line-height:1.5;color:#a1a1aa">Or paste this link into your browser:<br><span style="color:#6d28d9;word-break:break-all">%s</span></td></tr>
</table></td></tr></table></body></html>`,
		e(brand), e(heading), e(name), e(body), e(link), e(buttonLabel), e(link))
}
