// Package config loads pqtrust configuration from YAML with environment overrides.
package config

import (
	"bytes"
	"fmt"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

// TLSConfig configures the API server's transport certificate.
type TLSConfig struct {
	CertFile       string `yaml:"cert_file"`
	KeyFile        string `yaml:"key_file"`
	AutoSelfSigned bool   `yaml:"auto_self_signed"`
	Hostname       string `yaml:"hostname"`
}

// ServerConfig configures the HTTP listener.
type ServerConfig struct {
	Listen string    `yaml:"listen"`
	TLS    TLSConfig `yaml:"tls"`
}

// DatabaseConfig configures SQLite storage.
type DatabaseConfig struct {
	Path string `yaml:"path"`
}

// KeystoreConfig configures sealed key storage.
type KeystoreConfig struct {
	Dir string `yaml:"dir"`
}

// IssuanceConfig configures issuance and CRL policy.
type IssuanceConfig struct {
	MaxValidityDays  int `yaml:"max_validity_days"`
	CRLValidityHours int `yaml:"crl_validity_hours"`
}

// Config is the complete pqtrust configuration.
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Database DatabaseConfig `yaml:"database"`
	Keystore KeystoreConfig `yaml:"keystore"`
	Issuance IssuanceConfig `yaml:"issuance"`
}

// Default returns the built-in configuration.
func Default() Config {
	var c Config
	c.Server.Listen = ":8443"
	c.Server.TLS.AutoSelfSigned = true
	c.Server.TLS.Hostname = "localhost"
	c.Database.Path = "/var/lib/pqtrust/pqtrust.db"
	c.Keystore.Dir = "/var/lib/pqtrust/keys"
	c.Issuance.MaxValidityDays = 397
	c.Issuance.CRLValidityHours = 168
	return c
}

// Load reads path (when non-empty) over the defaults, applies environment
// overrides and validates the result.
func Load(path string) (Config, error) {
	c := Default()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return Config{}, fmt.Errorf("config: reading %s: %w", path, err)
		}
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		if err := dec.Decode(&c); err != nil {
			return Config{}, fmt.Errorf("config: parsing %s: %w", path, err)
		}
	}
	if err := c.applyEnv(); err != nil {
		return Config{}, err
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

func (c *Config) applyEnv() error {
	str := func(env string, dst *string) {
		if v, ok := os.LookupEnv(env); ok {
			*dst = v
		}
	}
	str("PQTRUST_LISTEN", &c.Server.Listen)
	str("PQTRUST_TLS_CERT_FILE", &c.Server.TLS.CertFile)
	str("PQTRUST_TLS_KEY_FILE", &c.Server.TLS.KeyFile)
	str("PQTRUST_TLS_HOSTNAME", &c.Server.TLS.Hostname)
	str("PQTRUST_DB_PATH", &c.Database.Path)
	str("PQTRUST_KEYSTORE_DIR", &c.Keystore.Dir)

	if v, ok := os.LookupEnv("PQTRUST_TLS_AUTO_SELF_SIGNED"); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("config: PQTRUST_TLS_AUTO_SELF_SIGNED=%q is not a boolean: %w", v, err)
		}
		c.Server.TLS.AutoSelfSigned = b
	}
	for _, e := range []struct {
		env string
		dst *int
	}{
		{"PQTRUST_MAX_VALIDITY_DAYS", &c.Issuance.MaxValidityDays},
		{"PQTRUST_CRL_VALIDITY_HOURS", &c.Issuance.CRLValidityHours},
	} {
		if v, ok := os.LookupEnv(e.env); ok {
			n, err := strconv.Atoi(v)
			if err != nil {
				return fmt.Errorf("config: %s=%q is not an integer: %w", e.env, v, err)
			}
			*e.dst = n
		}
	}
	return nil
}

// Validate reports configuration that cannot produce a working server.
func (c Config) Validate() error {
	if c.Server.Listen == "" {
		return fmt.Errorf("config: server.listen must not be empty")
	}
	if !c.Server.TLS.AutoSelfSigned && (c.Server.TLS.CertFile == "" || c.Server.TLS.KeyFile == "") {
		return fmt.Errorf("config: server.tls.cert_file and key_file are required when auto_self_signed is false")
	}
	if c.Database.Path == "" {
		return fmt.Errorf("config: database.path must not be empty")
	}
	if c.Keystore.Dir == "" {
		return fmt.Errorf("config: keystore.dir must not be empty")
	}
	if c.Issuance.MaxValidityDays <= 0 {
		return fmt.Errorf("config: issuance.max_validity_days must be positive, got %d", c.Issuance.MaxValidityDays)
	}
	if c.Issuance.CRLValidityHours <= 0 {
		return fmt.Errorf("config: issuance.crl_validity_hours must be positive, got %d", c.Issuance.CRLValidityHours)
	}
	return nil
}
