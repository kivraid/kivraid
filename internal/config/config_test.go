package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTemp(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "kivraid.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const validSecret = "0123456789abcdef0123456789abcdef"

func TestSigningAlgorithm(t *testing.T) {
	cfg, err := Load(writeTemp(t, "secret_key: \""+validSecret+"\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OIDC.SigningAlgorithm != "es256" {
		t.Fatalf("default signing_algorithm: want es256, got %q", cfg.OIDC.SigningAlgorithm)
	}

	cfg, err = Load(writeTemp(t, "secret_key: \""+validSecret+"\"\noidc:\n  signing_algorithm: rs256\n"))
	if err != nil {
		t.Fatalf("rs256 should be valid: %v", err)
	}
	if cfg.OIDC.SigningAlgorithm != "rs256" {
		t.Fatalf("want rs256, got %q", cfg.OIDC.SigningAlgorithm)
	}

	if _, err := Load(writeTemp(t, "secret_key: \""+validSecret+"\"\noidc:\n  signing_algorithm: hs256\n")); err == nil {
		t.Fatal("hs256 should be rejected")
	}
}

func TestSessionDefaults(t *testing.T) {
	cfg, err := Load(writeTemp(t, "secret_key: \""+validSecret+"\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if time.Duration(cfg.Session.Lifetime) != 7*24*time.Hour {
		t.Fatalf("default lifetime: got %s", time.Duration(cfg.Session.Lifetime))
	}
	if cfg.Session.IdleTimeout != 0 {
		t.Fatalf("default idle_timeout should be 0, got %s", time.Duration(cfg.Session.IdleTimeout))
	}
}

func TestSessionFromYAML(t *testing.T) {
	cfg, err := Load(writeTemp(t, "secret_key: \""+validSecret+"\"\nsession:\n  lifetime: 48h\n  idle_timeout: 30m\n"))
	if err != nil {
		t.Fatal(err)
	}
	if time.Duration(cfg.Session.Lifetime) != 48*time.Hour {
		t.Fatalf("lifetime: got %s", time.Duration(cfg.Session.Lifetime))
	}
	if time.Duration(cfg.Session.IdleTimeout) != 30*time.Minute {
		t.Fatalf("idle_timeout: got %s", time.Duration(cfg.Session.IdleTimeout))
	}
}

func TestSessionEnvOverride(t *testing.T) {
	t.Setenv("KIVRAID_SESSION_LIFETIME", "12h")
	t.Setenv("KIVRAID_SESSION_IDLE_TIMEOUT", "15m")
	cfg, err := Load(writeTemp(t, "secret_key: \""+validSecret+"\"\nsession:\n  lifetime: 48h\n"))
	if err != nil {
		t.Fatal(err)
	}
	if time.Duration(cfg.Session.Lifetime) != 12*time.Hour {
		t.Fatalf("env lifetime override: got %s", time.Duration(cfg.Session.Lifetime))
	}
	if time.Duration(cfg.Session.IdleTimeout) != 15*time.Minute {
		t.Fatalf("env idle_timeout override: got %s", time.Duration(cfg.Session.IdleTimeout))
	}
}

func TestSessionValidation(t *testing.T) {
	cases := map[string]string{
		"idle exceeds lifetime": "secret_key: \"" + validSecret + "\"\nsession:\n  lifetime: 1h\n  idle_timeout: 2h\n",
		"zero lifetime":         "secret_key: \"" + validSecret + "\"\nsession:\n  lifetime: 0s\n",
		"bad duration string":   "secret_key: \"" + validSecret + "\"\nsession:\n  lifetime: \"nope\"\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeTemp(t, body)); err == nil {
				t.Fatal("expected an error, got nil")
			}
		})
	}
}

func TestBadEnvDuration(t *testing.T) {
	t.Setenv("KIVRAID_SESSION_IDLE_TIMEOUT", "notaduration")
	if _, err := Load(writeTemp(t, "secret_key: \""+validSecret+"\"\n")); err == nil {
		t.Fatal("expected error for bad env duration")
	}
}
