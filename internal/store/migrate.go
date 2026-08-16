package store

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// migrate applies every embedded migration that has not been applied yet.
func (s *Store) migrate() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		name TEXT PRIMARY KEY,
		applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		return fmt.Errorf("store: creating migration table: %w", err)
	}

	entries, err := fs.Glob(migrationFS, "migrations/*.sql")
	if err != nil {
		return fmt.Errorf("store: listing migrations: %w", err)
	}
	sort.Strings(entries)

	for _, name := range entries {
		var count int
		if err := s.db.QueryRow(`SELECT COUNT(1) FROM schema_migrations WHERE name = ?`, name).Scan(&count); err != nil {
			return fmt.Errorf("store: checking migration %s: %w", name, err)
		}
		if count > 0 {
			continue
		}
		sqlBytes, err := migrationFS.ReadFile(name)
		if err != nil {
			return fmt.Errorf("store: reading migration %s: %w", name, err)
		}
		tx, err := s.db.Begin()
		if err != nil {
			return fmt.Errorf("store: beginning migration %s: %w", name, err)
		}
		if _, err := tx.Exec(string(sqlBytes)); err != nil {
			tx.Rollback()
			return fmt.Errorf("store: applying migration %s: %w", name, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations(name) VALUES (?)`, name); err != nil {
			tx.Rollback()
			return fmt.Errorf("store: recording migration %s: %w", name, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("store: committing migration %s: %w", name, err)
		}
	}
	return nil
}
