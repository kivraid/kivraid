// Package config loads the Kivraid configuration from a YAML file with
// KIVRAID_* environment variable overrides.
package config

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration is a time.Duration that unmarshals from a YAML string such as
// "168h" or "30m" (yaml.v3 has no native duration support).
type Duration time.Duration

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	if s == "" {
		return nil
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

type Database struct {
	// Driver is the database engine: "sqlite" (default) or "postgres".
	Driver string `yaml:"driver"`
	DSN    string `yaml:"dsn"`
}

type ForwardAuth struct {
	// Domains that forward-auth protected applications live on. Entries
	// starting with a dot match any subdomain (".home.example.com");
	// others match exactly. Post-login redirects are only allowed to
	// these hosts.
	Domains []string `yaml:"domains"`
}

type OIDC struct {
	// SigningAlgorithm signs OIDC ID tokens: "es256" (default) or "rs256".
	// ES256 is modern and compact; RS256 is the universally supported
	// baseline — switch to it for apps that reject ES256 (e.g. BookStack).
	SigningAlgorithm string `yaml:"signing_algorithm"`
}

type Session struct {
	// Lifetime is the absolute maximum age of a session, measured from
	// login. A session expires after this no matter how active the user is.
	Lifetime Duration `yaml:"lifetime"`
	// IdleTimeout, when > 0, expires a session after this much inactivity.
	// It is a sliding window (each request resets it), capped by Lifetime.
	// Zero disables the inactivity timeout.
	IdleTimeout Duration `yaml:"idle_timeout"`
}

type Config struct {
	// Listen is the address the HTTP server binds to.
	Listen string `yaml:"listen"`
	// BaseURL is the externally visible URL of this instance, used to
	// build absolute links (and later, OIDC issuer identity).
	BaseURL string `yaml:"base_url"`
	// SecretKey protects secrets at rest and must be at least 32 bytes.
	SecretKey   string      `yaml:"secret_key"`
	Database    Database    `yaml:"database"`
	ForwardAuth ForwardAuth `yaml:"forward_auth"`
	OIDC        OIDC        `yaml:"oidc"`
	Session     Session     `yaml:"session"`
	// TrustedProxies lists reverse proxies (IPs or CIDRs) whose
	// X-Forwarded-For header is honored when attributing a client IP
	// (rate limiting, audit log, session list). Empty means the header
	// is ignored and the direct peer address is used — the safe default
	// when Kivraid is directly reachable.
	TrustedProxies []string `yaml:"trusted_proxies"`
	LogLevel       string   `yaml:"log_level"`
}

// ParseTrustedProxies parses trusted_proxies entries into prefixes; a
// bare IP is treated as a single-address prefix.
func ParseTrustedProxies(entries []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(entries))
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if strings.Contains(e, "/") {
			p, err := netip.ParsePrefix(e)
			if err != nil {
				return nil, fmt.Errorf("trusted_proxies: invalid CIDR %q", e)
			}
			out = append(out, p)
			continue
		}
		a, err := netip.ParseAddr(e)
		if err != nil {
			return nil, fmt.Errorf("trusted_proxies: invalid IP %q (use an address or CIDR like \"10.0.0.0/8\")", e)
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

func defaults() Config {
	return Config{
		Listen:   "127.0.0.1:9000",
		BaseURL:  "http://localhost:9000",
		Database: Database{Driver: "sqlite", DSN: "kivraid.db"},
		OIDC:     OIDC{SigningAlgorithm: "es256"},
		Session:  Session{Lifetime: Duration(7 * 24 * time.Hour), IdleTimeout: 0},
		LogLevel: "info",
	}
}

// Load reads the config file at path (optional: empty path skips the file),
// applies environment overrides, and validates the result.
func Load(path string) (Config, error) {
	cfg := defaults()

	if path != "" {
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			return cfg, fmt.Errorf("config file %s not found; generate one with: kivraid config init", path)
		}
		if err != nil {
			return cfg, fmt.Errorf("read config: %w", err)
		}
		dec := yaml.NewDecoder(strings.NewReader(string(data)))
		dec.KnownFields(true)
		if err := dec.Decode(&cfg); err != nil {
			return cfg, fmt.Errorf("parse config %s: %w", path, err)
		}
	}

	if err := applyEnv(&cfg); err != nil {
		return cfg, err
	}

	if err := cfg.validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func applyEnv(cfg *Config) error {
	set := func(key string, dst *string) {
		if v, ok := os.LookupEnv("KIVRAID_" + key); ok {
			*dst = v
		}
	}
	set("LISTEN", &cfg.Listen)
	set("BASE_URL", &cfg.BaseURL)
	set("SECRET_KEY", &cfg.SecretKey)
	set("DB_DRIVER", &cfg.Database.Driver)
	set("DB_DSN", &cfg.Database.DSN)
	set("OIDC_SIGNING_ALGORITHM", &cfg.OIDC.SigningAlgorithm)
	set("LOG_LEVEL", &cfg.LogLevel)
	setDur := func(key string, dst *Duration) error {
		v, ok := os.LookupEnv("KIVRAID_" + key)
		if !ok || v == "" {
			return nil
		}
		parsed, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("KIVRAID_%s: invalid duration %q: %w", key, v, err)
		}
		*dst = Duration(parsed)
		return nil
	}
	if err := setDur("SESSION_LIFETIME", &cfg.Session.Lifetime); err != nil {
		return err
	}
	if err := setDur("SESSION_IDLE_TIMEOUT", &cfg.Session.IdleTimeout); err != nil {
		return err
	}
	if v, ok := os.LookupEnv("KIVRAID_FORWARD_AUTH_DOMAINS"); ok {
		cfg.ForwardAuth.Domains = nil
		for _, d := range strings.Split(v, ",") {
			if d = strings.TrimSpace(d); d != "" {
				cfg.ForwardAuth.Domains = append(cfg.ForwardAuth.Domains, d)
			}
		}
	}
	if v, ok := os.LookupEnv("KIVRAID_TRUSTED_PROXIES"); ok {
		cfg.TrustedProxies = nil
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				cfg.TrustedProxies = append(cfg.TrustedProxies, p)
			}
		}
	}
	return nil
}

func (c Config) validate() error {
	if len(c.SecretKey) < 32 {
		return fmt.Errorf("secret_key must be at least 32 characters (got %d); generate one with: openssl rand -hex 32", len(c.SecretKey))
	}
	if c.Database.Driver != "sqlite" && c.Database.Driver != "postgres" {
		return fmt.Errorf("unsupported database driver %q (want \"sqlite\" or \"postgres\")", c.Database.Driver)
	}
	if !strings.HasPrefix(c.BaseURL, "http://") && !strings.HasPrefix(c.BaseURL, "https://") {
		return fmt.Errorf("base_url must start with http:// or https://")
	}
	if c.Session.Lifetime <= 0 {
		return fmt.Errorf("session.lifetime must be a positive duration (e.g. \"168h\")")
	}
	if c.Session.IdleTimeout < 0 {
		return fmt.Errorf("session.idle_timeout must not be negative")
	}
	if c.Session.IdleTimeout > c.Session.Lifetime {
		return fmt.Errorf("session.idle_timeout (%s) must not exceed session.lifetime (%s)",
			time.Duration(c.Session.IdleTimeout), time.Duration(c.Session.Lifetime))
	}
	if _, err := ParseTrustedProxies(c.TrustedProxies); err != nil {
		return err
	}
	switch strings.ToLower(c.OIDC.SigningAlgorithm) {
	case "es256", "rs256":
	default:
		return fmt.Errorf("oidc.signing_algorithm must be \"es256\" or \"rs256\" (got %q)", c.OIDC.SigningAlgorithm)
	}
	return nil
}
