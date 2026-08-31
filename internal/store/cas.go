package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// CreateCA inserts a CA record.
func (s *Store) CreateCA(ctx context.Context, ca CA) error {
	var parent any
	if ca.ParentID != "" {
		parent = ca.ParentID
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO cas (id, name, parent_id, algorithm, cert_pem, key_id, status, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		ca.ID, ca.Name, parent, ca.Algorithm, ca.CertPEM, ca.KeyID, ca.Status, ca.CreatedAt.UTC())
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: CA %q already exists", ErrConflict, ca.ID)
		}
		return fmt.Errorf("store: inserting CA: %w", err)
	}
	return nil
}

func scanCA(row interface{ Scan(...any) error }) (CA, error) {
	var ca CA
	var parent sql.NullString
	var createdAt time.Time
	if err := row.Scan(&ca.ID, &ca.Name, &parent, &ca.Algorithm, &ca.CertPEM, &ca.KeyID, &ca.Status, &createdAt); err != nil {
		return CA{}, err
	}
	ca.ParentID = parent.String
	ca.CreatedAt = createdAt.UTC()
	return ca, nil
}

const caColumns = `id, name, parent_id, algorithm, cert_pem, key_id, status, created_at`

// GetCA fetches one CA by ID.
func (s *Store) GetCA(ctx context.Context, id string) (CA, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+caColumns+` FROM cas WHERE id = ?`, id)
	ca, err := scanCA(row)
	if errors.Is(err, sql.ErrNoRows) {
		return CA{}, fmt.Errorf("%w: CA %q", ErrNotFound, id)
	}
	if err != nil {
		return CA{}, fmt.Errorf("store: querying CA: %w", err)
	}
	return ca, nil
}

// ListCAs returns all CAs, oldest first.
func (s *Store) ListCAs(ctx context.Context) ([]CA, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+caColumns+` FROM cas ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("store: listing CAs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []CA
	for rows.Next() {
		ca, err := scanCA(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scanning CA: %w", err)
		}
		out = append(out, ca)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterating CAs: %w", err)
	}
	return out, nil
}
