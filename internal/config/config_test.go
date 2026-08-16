package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaults(t *testing.T) {
	c := Default()
	if c.Server.Listen != ":8443" {
		t.Errorf("listen = %q", c.Server.Listen)
	}
	if !c.Server.TLS.AutoSelfSigned {
		t.Error("auto_self_signed must default to true")
	}
	if c.Issuance.MaxValidityDays != 397 {
		t.Errorf("max validity = %d, want 397", c.Issuance.MaxValidityDays)
	}
	if c.Issuance.CRLValidityHours != 168 {
		t.Errorf("CRL validity = %d, want 168", c.Issuance.CRLValidityHours)
	}
	if err := c.Validate(); err != nil {
		t.Errorf("defaults must validate: %v", err)
	}
}

func TestLoadYAMLOverridesDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := `
server:
  listen: "127.0.0.1:9443"
  tls:
    auto_self_signed: false
    cert_file: /tmp/cert.pem
    key_file: /tmp/key.pem
database:
  path: /tmp/pqtrust.db
keystore:
  dir: /tmp/keys
issuance:
  max_validity_days: 90
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.Listen != "127.0.0.1:9443" {
		t.Errorf("listen = %q", c.Server.Listen)
	}
	if c.Server.TLS.AutoSelfSigned {
		t.Error("auto_self_signed must be false")
	}
	if c.Database.Path != "/tmp/pqtrust.db" || c.Keystore.Dir != "/tmp/keys" {
		t.Errorf("paths = %q / %q", c.Database.Path, c.Keystore.Dir)
	}
	if c.Issuance.MaxValidityDays != 90 {
		t.Errorf("max validity = %d", c.Issuance.MaxValidityDays)
	}
	if c.Issuance.CRLValidityHours != 168 {
		t.Errorf("CRL validity = %d, want the default 168", c.Issuance.CRLValidityHours)
	}
}

func TestEnvOverridesYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("server:\n  listen: \":1111\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PQTRUST_LISTEN", ":2222")
	t.Setenv("PQTRUST_DB_PATH", "/env/db.sqlite")
	t.Setenv("PQTRUST_MAX_VALIDITY_DAYS", "30")
	t.Setenv("PQTRUST_TLS_AUTO_SELF_SIGNED", "false")
	t.Setenv("PQTRUST_TLS_CERT_FILE", "/env/cert.pem")
	t.Setenv("PQTRUST_TLS_KEY_FILE", "/env/key.pem")

	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.Listen != ":2222" {
		t.Errorf("listen = %q, want :2222", c.Server.Listen)
	}
	if c.Database.Path != "/env/db.sqlite" {
		t.Errorf("db path = %q", c.Database.Path)
	}
	if c.Issuance.MaxValidityDays != 30 {
		t.Errorf("max validity = %d", c.Issuance.MaxValidityDays)
	}
	if c.Server.TLS.AutoSelfSigned {
		t.Error("auto_self_signed must be false from the environment")
	}
}

func TestLoadMissingFileIsAnError(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Error("an explicitly requested missing config file must be an error")
	}
}

func TestLoadEmptyPathUsesDefaults(t *testing.T) {
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.Listen != ":8443" {
		t.Errorf("listen = %q", c.Server.Listen)
	}
}

func TestValidate(t *testing.T) {
	t.Run("bad max validity", func(t *testing.T) {
		c := Default()
		c.Issuance.MaxValidityDays = 0
		if err := c.Validate(); err == nil {
			t.Error("max_validity_days must be positive")
		}
	})
	t.Run("tls files required when not self-signing", func(t *testing.T) {
		c := Default()
		c.Server.TLS.AutoSelfSigned = false
		if err := c.Validate(); err == nil {
			t.Error("cert_file and key_file are required when auto_self_signed is false")
		}
	})
	t.Run("empty listen", func(t *testing.T) {
		c := Default()
		c.Server.Listen = ""
		if err := c.Validate(); err == nil {
			t.Error("listen must not be empty")
		}
	})
	t.Run("bad env integer", func(t *testing.T) {
		t.Setenv("PQTRUST_MAX_VALIDITY_DAYS", "not-a-number")
		if _, err := Load(""); err == nil {
			t.Error("a non-numeric integer override must be an error")
		}
	})
}

func TestLoadRejectsUnknownYAMLKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("server:\n  lissten: \":1\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("a typo'd config key must be rejected, not silently ignored")
	}
}
