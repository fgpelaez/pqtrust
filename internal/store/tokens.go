package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// CreateToken stores an API token's hash.
func (s *Store) CreateToken(ctx context.Context, t Token) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO tokens (id, name, token_hash, created_at) VALUES (?, ?, ?, ?)`,
		t.ID, t.Name, t.TokenHash, t.CreatedAt.UTC())
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: token already exists", ErrConflict)
		}
		return fmt.Errorf("store: inserting token: %w", err)
	}
	return nil
}

// TokenByHash looks a token up by its hex SHA-256 hash.
func (s *Store) TokenByHash(ctx context.Context, hash string) (Token, error) {
	var t Token
	var createdAt time.Time
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, token_hash, created_at FROM tokens WHERE token_hash = ?`, hash).
		Scan(&t.ID, &t.Name, &t.TokenHash, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Token{}, fmt.Errorf("%w: token", ErrNotFound)
	}
	if err != nil {
		return Token{}, fmt.Errorf("store: querying token: %w", err)
	}
	t.CreatedAt = createdAt.UTC()
	return t, nil
}
