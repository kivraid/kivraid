// Package config loads the Kivraid configuration from a YAML file with
// KIVRAID_* environment variable overrides.
package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Database struct {
	// Driver is the database engine: "sqlite" (default). "postgres" is
	// planned but not implemented yet.
	Driver string `yaml:"driver"`
	DSN    string `yaml:"dsn"`
}

type Config struct {
	// Listen is the address the HTTP server binds to.
	Listen string `yaml:"listen"`
	// BaseURL is the externally visible URL of this instance, used to
	// build absolute links (and later, OIDC issuer identity).
	BaseURL string `yaml:"base_url"`
	// SecretKey protects secrets at rest and must be at least 32 bytes.
	SecretKey string   `yaml:"secret_key"`
	Database  Database `yaml:"database"`
	LogLevel  string   `yaml:"log_level"`
}

func defaults() Config {
	return Config{
		Listen:   "127.0.0.1:9000",
		BaseURL:  "http://localhost:9000",
		Database: Database{Driver: "sqlite", DSN: "kivraid.db"},
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

	applyEnv(&cfg)

	if err := cfg.validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func applyEnv(cfg *Config) {
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
	set("LOG_LEVEL", &cfg.LogLevel)
}

func (c Config) validate() error {
	if len(c.SecretKey) < 32 {
		return fmt.Errorf("secret_key must be at least 32 characters (got %d); generate one with: openssl rand -hex 32", len(c.SecretKey))
	}
	if c.Database.Driver != "sqlite" {
		return fmt.Errorf("unsupported database driver %q (only \"sqlite\" for now)", c.Database.Driver)
	}
	if !strings.HasPrefix(c.BaseURL, "http://") && !strings.HasPrefix(c.BaseURL, "https://") {
		return fmt.Errorf("base_url must start with http:// or https://")
	}
	return nil
}
