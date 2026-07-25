// Package mailer sends transactional email (password reset, address
// verification) over SMTP. Connection settings live in the database and are
// read on each send, so an admin change takes effect without a restart.
package mailer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/wneessen/go-mail"

	"github.com/kivraid/kivraid/internal/secrets"
	"github.com/kivraid/kivraid/internal/store"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
)

// ErrNotConfigured is returned when SMTP is disabled or has no host, so
// callers can surface a clear "email is not set up" message.
var ErrNotConfigured = errors.New("email delivery is not configured")

// Encryption modes stored in smtp_settings.encryption.
const (
	EncNone     = "none"
	EncStartTLS = "starttls"
	EncTLS      = "tls"
)

type Mailer struct {
	store   *store.Store
	sealKey [32]byte
	log     *slog.Logger
}

func New(st *store.Store, sealKey [32]byte, log *slog.Logger) *Mailer {
	return &Mailer{store: st, sealKey: sealKey, log: log}
}

// Message is a single email to deliver. Text is the plain-text body; HTML,
// when set, is added as the preferred alternative.
type Message struct {
	To      string
	Subject string
	Text    string
	HTML    string
}

// Enabled reports whether SMTP is turned on and has a host configured.
func (m *Mailer) Enabled(ctx context.Context) bool {
	cfg, err := m.store.GetSMTPSettings(ctx)
	return err == nil && cfg.Enabled && cfg.Host != ""
}

// Send delivers one message using the current SMTP settings. It is a no-op
// error (ErrNotConfigured) when email is disabled.
func (m *Mailer) Send(ctx context.Context, msg Message) error {
	cfg, err := m.store.GetSMTPSettings(ctx)
	if err != nil {
		return err
	}
	if !cfg.Enabled {
		return ErrNotConfigured
	}
	return m.send(ctx, cfg, msg)
}

// SendTest delivers a message using the stored settings even when email is
// not yet enabled, so an admin can verify the configuration before flipping
// it on.
func (m *Mailer) SendTest(ctx context.Context, msg Message) error {
	cfg, err := m.store.GetSMTPSettings(ctx)
	if err != nil {
		return err
	}
	return m.send(ctx, cfg, msg)
}

// SealPassword encrypts an SMTP password for storage at rest.
func (m *Mailer) SealPassword(password string) ([]byte, error) {
	return secrets.Seal(m.sealKey, []byte(password))
}

func (m *Mailer) send(ctx context.Context, cfg sqlcgen.SmtpSetting, msg Message) error {
	if cfg.Host == "" {
		return ErrNotConfigured
	}
	from := cfg.FromAddress
	if from == "" {
		return fmt.Errorf("no sender address configured")
	}

	client, err := m.client(cfg)
	if err != nil {
		return err
	}

	gm := mail.NewMsg()
	if cfg.FromName != "" {
		err = gm.FromFormat(cfg.FromName, from)
	} else {
		err = gm.From(from)
	}
	if err != nil {
		return fmt.Errorf("sender address %q: %w", from, err)
	}
	if err := gm.To(msg.To); err != nil {
		return fmt.Errorf("recipient %q: %w", msg.To, err)
	}
	gm.Subject(msg.Subject)
	gm.SetBodyString(mail.TypeTextPlain, msg.Text)
	if msg.HTML != "" {
		gm.AddAlternativeString(mail.TypeTextHTML, msg.HTML)
	}

	if err := client.DialAndSendWithContext(ctx, gm); err != nil {
		return fmt.Errorf("send email: %w", err)
	}
	return nil
}

// client builds a go-mail client from the stored settings, decrypting the
// password and mapping the encryption mode.
func (m *Mailer) client(cfg sqlcgen.SmtpSetting) (*mail.Client, error) {
	opts := []mail.Option{
		mail.WithPort(int(cfg.Port)),
		mail.WithTimeout(15 * time.Second),
	}
	switch cfg.Encryption {
	case EncNone:
		opts = append(opts, mail.WithTLSPolicy(mail.NoTLS))
	case EncTLS:
		opts = append(opts, mail.WithSSL())
	default: // starttls
		opts = append(opts, mail.WithTLSPolicy(mail.TLSMandatory))
	}
	if cfg.Username != "" {
		password := ""
		if len(cfg.PasswordEnc) > 0 {
			plain, err := secrets.Open(m.sealKey, cfg.PasswordEnc)
			if err != nil {
				return nil, fmt.Errorf("decrypt smtp password (was secret_key changed?): %w", err)
			}
			password = string(plain)
		}
		opts = append(opts,
			mail.WithSMTPAuth(mail.SMTPAuthAutoDiscover),
			mail.WithUsername(cfg.Username),
			mail.WithPassword(password),
		)
	}
	return mail.NewClient(cfg.Host, opts...)
}
