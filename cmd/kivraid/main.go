// Command kivraid runs the Kivraid identity provider.
//
//	kivraid serve    --config kivraid.yaml
//	kivraid user add --config kivraid.yaml --username admin --email a@b.c [--name "..."] [--admin]
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/KimMachineGun/automemlimit/memlimit"
	"golang.org/x/term"

	"github.com/kivraid/kivraid/internal/audit"
	"github.com/kivraid/kivraid/internal/broker"
	"github.com/kivraid/kivraid/internal/config"
	"github.com/kivraid/kivraid/internal/mailer"
	"github.com/kivraid/kivraid/internal/mfa"
	"github.com/kivraid/kivraid/internal/oidcserver"
	"github.com/kivraid/kivraid/internal/secrets"
	"github.com/kivraid/kivraid/internal/session"
	"github.com/kivraid/kivraid/internal/sources/ldap"
	"github.com/kivraid/kivraid/internal/sources/local"
	"github.com/kivraid/kivraid/internal/store"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
	"github.com/kivraid/kivraid/internal/web"
	"github.com/kivraid/kivraid/internal/webauthn"
)

// version is stamped at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "user":
		if len(os.Args) < 3 || os.Args[2] != "add" {
			usage()
			os.Exit(2)
		}
		err = userAdd(os.Args[3:])
	case "config":
		if len(os.Args) < 3 || os.Args[2] != "init" {
			usage()
			os.Exit(2)
		}
		err = configInit(os.Args[3:])
	case "healthcheck":
		err = healthcheck(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Println("kivraid", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `Kivraid — lightweight identity provider

Usage:
  kivraid config init [--config kivraid.yaml]   generate an initial configuration
  kivraid serve       [--config kivraid.yaml]   run the server
  kivraid user add    [--config kivraid.yaml] --username U --email E
                      [--name N] [--admin] [--password P]
  kivraid healthcheck [--url http://127.0.0.1:9000/healthz]
  kivraid version
`)
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", "kivraid.yaml", "path to the configuration file")
	fs.Parse(args)

	cfg, err := loadOrCreateConfig(*cfgPath)
	if err != nil {
		return err
	}
	log := newLogger(cfg.LogLevel)

	// Set GOMEMLIMIT from the cgroup memory limit so the GC respects the
	// container's budget. Where there is no cgroup limit (bare metal) the
	// limit is left effectively unbounded, which is expected, not an error.
	if lim, err := memlimit.Set(); err == nil && lim != math.MaxInt64 {
		log.Debug("GOMEMLIMIT set from cgroup", "bytes", lim)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, cfg.Database.Driver, cfg.Database.DSN)
	if err != nil {
		return err
	}
	defer st.Close()

	oidcProvider, oidcStorage, err := oidcserver.New(ctx, cfg, st, log)
	if err != nil {
		return err
	}

	recorder := audit.NewRecorder(st, log)

	// Signing-key upkeep: automatic rotation when enabled, and retirement
	// of superseded keys once the grace period is over. Run at startup and
	// with the periodic maintenance below.
	maintainKeys := func() {
		days := int32(0)
		if settings, err := st.GetInstanceSettings(ctx); err == nil {
			days = settings.KeyRotationDays
		}
		rotated, retired, err := oidcStorage.MaintainSigningKeys(ctx, time.Duration(days)*24*time.Hour, time.Now().UTC())
		if err != nil {
			log.Warn("signing key maintenance", "err", err)
			return
		}
		if rotated {
			log.Info("signing key rotated automatically", "every_days", days)
			recorder.Record(ctx, "", audit.ActionKeyRotate, "", "automatic", "")
		}
		if retired > 0 {
			log.Info("previous signing keys retired", "count", retired)
			recorder.Record(ctx, "", audit.ActionKeyRetire, "", strconv.FormatInt(retired, 10)+" key(s)", "")
		}
	}
	maintainKeys()

	// Periodic garbage collection of expired tokens and auth requests.
	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				maintainKeys()
				if err := oidcStorage.CleanupExpired(ctx); err != nil {
					log.Warn("token cleanup", "err", err)
				}
				// Audit retention, set under Settings → Security (0 keeps
				// every event).
				if settings, err := st.GetInstanceSettings(ctx); err == nil && settings.AuditRetentionDays > 0 {
					cutoff := time.Now().UTC().AddDate(0, 0, -int(settings.AuditRetentionDays))
					if err := st.DeleteAuditBefore(ctx, cutoff); err != nil {
						log.Warn("audit cleanup", "err", err)
					}
				}
				// Expired password-reset / verification tokens.
				if err := st.DeleteExpiredEmailTokens(ctx, time.Now().UTC()); err != nil {
					log.Warn("email token cleanup", "err", err)
				}
				// Return heap freed since the last tick (e.g. after a
				// login burst) to the OS instead of waiting for the lazy
				// scavenger, keeping idle RSS low.
				debug.FreeOSMemory()
			}
		}
	}()

	sessions := session.NewManager(st.DB, st.Driver, strings.HasPrefix(cfg.BaseURL, "https://"),
		time.Duration(cfg.Session.Lifetime), time.Duration(cfg.Session.IdleTimeout))
	ldapManager := ldap.NewManager(st, secrets.DeriveKey(cfg.SecretKey, "ldap-bind-passwords"), log)
	mfaManager := mfa.NewManager(st, secrets.DeriveKey(cfg.SecretKey, "totp-secrets"))
	webauthnManager, err := webauthn.New(st, cfg.BaseURL)
	if err != nil {
		return err
	}
	mailManager := mailer.New(st, secrets.DeriveKey(cfg.SecretKey, "smtp-password"), log)
	brokerManager := broker.NewManager(st,
		secrets.DeriveKey(cfg.SecretKey, "upstream-secrets"),
		secrets.DeriveKey(cfg.SecretKey, "upstream-cookie-hash"),
		secrets.DeriveKey(cfg.SecretKey, "upstream-cookie-enc"),
		cfg.BaseURL)
	srv, err := web.NewServer(web.Deps{
		Config:    cfg,
		Version:   version,
		Store:     st,
		Sessions:  sessions,
		OIDC:      oidcProvider,
		OIDCStore: oidcStorage,
		Audit:     recorder,
		LDAP:      ldapManager,
		MFA:       mfaManager,
		WebAuthn:  webauthnManager,
		Mailer:    mailManager,
		Broker:    brokerManager,
		Log:       log,
	})
	if err != nil {
		return err
	}

	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	// On a fresh instance, tell the operator what to do next.
	firstRun := false
	if n, err := st.CountUsers(ctx); err == nil && n == 0 {
		firstRun = true
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("kivraid listening", "version", version, "addr", cfg.Listen, "base_url", cfg.BaseURL)
		if firstRun {
			log.Info("first run: open the web UI to create the administrator account", "url", cfg.BaseURL)
		}
		errCh <- httpSrv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return httpSrv.Shutdown(shutdownCtx)
	}
}

func userAdd(args []string) error {
	fs := flag.NewFlagSet("user add", flag.ExitOnError)
	cfgPath := fs.String("config", "kivraid.yaml", "path to the configuration file")
	username := fs.String("username", "", "login name (required)")
	email := fs.String("email", "", "email address (required)")
	name := fs.String("name", "", "display name")
	admin := fs.Bool("admin", false, "grant administrator rights")
	password := fs.String("password", "", "password (omit to be prompted; prefer the prompt)")
	fs.Parse(args)

	if *username == "" || *email == "" {
		return errors.New("--username and --email are required")
	}
	if *name == "" {
		*name = *username
	}

	// Load the config before prompting: a missing file should fail fast,
	// not after the password has been typed twice.
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}

	pw := *password
	if pw == "" {
		pw, err = promptPassword()
		if err != nil {
			return err
		}
	}
	if len(pw) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	ctx := context.Background()
	st, err := store.Open(ctx, cfg.Database.Driver, cfg.Database.DSN)
	if err != nil {
		return err
	}
	defer st.Close()

	user, err := local.NewSource(st).CreateUser(ctx, *username, *email, *name, pw, *admin)
	if err != nil {
		return err
	}
	// An operator-created account has an operator-attested email.
	if err := st.SetEmailVerified(ctx, sqlcgen.SetEmailVerifiedParams{
		EmailVerified: true, UpdatedAt: time.Now().UTC(), ID: user.ID,
	}); err != nil {
		return err
	}
	audit.NewRecorder(st, newLogger(cfg.LogLevel)).
		Record(ctx, "cli", audit.ActionUserCreate, user.Username, "", "")
	fmt.Printf("created user %s (%s)\n", user.Username, user.ID)
	return nil
}

// healthcheck probes the local /healthz endpoint and exits non-zero when
// the instance is unreachable or unhealthy. The Docker HEALTHCHECK uses
// it: the scratch image has no shell or curl.
func healthcheck(args []string) error {
	fs := flag.NewFlagSet("healthcheck", flag.ExitOnError)
	def := "http://127.0.0.1:9000/healthz"
	if l := os.Getenv("KIVRAID_LISTEN"); l != "" {
		if _, port, err := net.SplitHostPort(l); err == nil {
			def = "http://127.0.0.1:" + port + "/healthz"
		}
	}
	url := fs.String("url", def, "health endpoint to probe")
	fs.Parse(args)

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(*url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unhealthy: %s returned %s", *url, resp.Status)
	}
	return nil
}

func configInit(args []string) error {
	fs := flag.NewFlagSet("config init", flag.ExitOnError)
	cfgPath := fs.String("config", "kivraid.yaml", "path to write the configuration file")
	fs.Parse(args)

	if _, err := os.Stat(*cfgPath); err == nil {
		return fmt.Errorf("%s already exists, refusing to overwrite", *cfgPath)
	}
	if err := writeDefaultConfig(*cfgPath); err != nil {
		return err
	}
	fmt.Printf("wrote %s\n", *cfgPath)
	return nil
}

// writeDefaultConfig writes a fresh configuration (with a random
// secret_key) to path.
func writeDefaultConfig(path string) error {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	content := fmt.Sprintf(`listen: "127.0.0.1:9000"

# Public URL of this instance; also the OIDC issuer. Use https:// in
# production (behind a TLS-terminating reverse proxy).
base_url: "http://localhost:9000"

# Protects secrets at rest. Changing it invalidates encrypted data.
secret_key: "%s"

database:
  driver: sqlite
  dsn: "kivraid.db"

# Hosts allowed for forward-auth post-login redirects; entries starting
# with a dot match subdomains. See docs/forward-auth.md.
# forward_auth:
#   domains: [".home.example.com"]

# Reverse proxies (IPs or CIDRs) whose X-Forwarded-For header is trusted
# for client IP attribution (rate limiting, audit log). Leave unset when
# Kivraid is directly reachable.
# trusted_proxies: ["10.0.0.0/8"]

# OIDC ID token signing algorithm: "es256" (default) or "rs256". Switch to
# rs256 for apps that reject ES256 (e.g. BookStack). See docs/integrations.
# oidc:
#   signing_algorithm: es256

# Session expiry. lifetime is the absolute maximum age (from login);
# idle_timeout, when set, logs users out after that much inactivity
# (sliding window, capped by lifetime). "0s" disables the idle timeout.
session:
  lifetime: 168h
  idle_timeout: 0s

log_level: info
`, hex.EncodeToString(secret))
	return os.WriteFile(path, []byte(content), 0o600)
}

// loadOrCreateConfig loads the config, generating one on first run so no
// separate "config init" step is required. When a config file is absent
// but KIVRAID_SECRET_KEY is set (typical container setup), it runs from
// environment overrides alone without writing a file.
func loadOrCreateConfig(path string) (config.Config, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if os.Getenv("KIVRAID_SECRET_KEY") != "" {
			return config.Load("")
		}
		if err := writeDefaultConfig(path); err != nil {
			return config.Config{}, fmt.Errorf("generate config: %w", err)
		}
		fmt.Fprintf(os.Stderr, "no config found; generated %s with a fresh secret_key\n", path)
	}
	return config.Load(path)
}

func promptPassword() (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("stdin is not a terminal; use --password")
	}
	fmt.Fprint(os.Stderr, "Password: ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	fmt.Fprint(os.Stderr, "Confirm:  ")
	confirm, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if string(pw) != string(confirm) {
		return "", errors.New("passwords do not match")
	}
	return string(pw), nil
}
