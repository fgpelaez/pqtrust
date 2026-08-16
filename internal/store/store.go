// Package store persists pqtrust state in SQLite. It holds no domain logic and
// no pqx509 types, so a future multi-tenant schema can be introduced here alone.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var (
	// ErrNotFound reports a missing row.
	ErrNotFound = errors.New("store: not found")
	// ErrConflict reports a uniqueness or state conflict.
	ErrConflict = errors.New("store: conflict")
)

// Store is a SQLite-backed pqtrust datastore.
type Store struct {
	db *sql.DB
}

// CA is a certificate authority record.
type CA struct {
	ID        string
	Name      string
	ParentID  string
	Algorithm string
	CertPEM   string
	KeyID     string
	Status    string
	CreatedAt time.Time
}

// Certificate is an issued end-entity certificate record.
type Certificate struct {
	Serial           string
	CAID             string
	SubjectDN        string
	SANs             string
	Algorithm        string
	CertPEM          string
	KeyID            string
	Status           string
	NotBefore        time.Time
	NotAfter         time.Time
	RevokedAt        *time.Time
	RevocationReason *int
}

// Token is an API bearer token record; only its SHA-256 hash is stored.
type Token struct {
	ID        string
	Name      string
	TokenHash string
	CreatedAt time.Time
}

// Certificate and CA status values.
const (
	StatusValid   = "valid"
	StatusRevoked = "revoked"
	StatusActive  = "active"
)

// Open opens (creating if needed) the SQLite database at path and applies migrations.
func Open(path string) (*Store, error) {
	if path == "" {
		return nil, fmt.Errorf("store: database path must not be empty")
	}
	dsn := path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: opening database: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: pinging database: %w", err)
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the database handle.
func (s *Store) Close() error {
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("store: closing database: %w", err)
	}
	return nil
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") ||
		strings.Contains(msg, "PRIMARY KEY must be unique")
}
