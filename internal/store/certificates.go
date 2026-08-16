package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

const certColumns = `serial, ca_id, subject_dn, sans, algorithm, cert_pem, key_id, status,
	not_before, not_after, revoked_at, revocation_reason`

// InsertCertificate stores a newly issued certificate.
func (s *Store) InsertCertificate(ctx context.Context, c Certificate) error {
	var keyID any
	if c.KeyID != "" {
		keyID = c.KeyID
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO certificates (serial, ca_id, subject_dn, sans, algorithm, cert_pem, key_id, status, not_before, not_after)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.Serial, c.CAID, c.SubjectDN, c.SANs, c.Algorithm, c.CertPEM, keyID, c.Status, c.NotBefore.UTC(), c.NotAfter.UTC())
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: certificate %q already exists", ErrConflict, c.Serial)
		}
		return fmt.Errorf("store: inserting certificate: %w", err)
	}
	return nil
}

func scanCertificate(row interface{ Scan(...any) error }) (Certificate, error) {
	var c Certificate
	var keyID sql.NullString
	var revokedAt sql.NullTime
	var reason sql.NullInt64
	var notBefore, notAfter time.Time
	if err := row.Scan(&c.Serial, &c.CAID, &c.SubjectDN, &c.SANs, &c.Algorithm, &c.CertPEM,
		&keyID, &c.Status, &notBefore, &notAfter, &revokedAt, &reason); err != nil {
		return Certificate{}, err
	}
	c.KeyID = keyID.String
	c.NotBefore, c.NotAfter = notBefore.UTC(), notAfter.UTC()
	if revokedAt.Valid {
		t := revokedAt.Time.UTC()
		c.RevokedAt = &t
	}
	if reason.Valid {
		r := int(reason.Int64)
		c.RevocationReason = &r
	}
	return c, nil
}

// GetCertificate fetches one certificate by serial.
func (s *Store) GetCertificate(ctx context.Context, serial string) (Certificate, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+certColumns+` FROM certificates WHERE serial = ?`, serial)
	c, err := scanCertificate(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Certificate{}, fmt.Errorf("%w: certificate %q", ErrNotFound, serial)
	}
	if err != nil {
		return Certificate{}, fmt.Errorf("store: querying certificate: %w", err)
	}
	return c, nil
}

func (s *Store) listCertificates(ctx context.Context, query string, args ...any) ([]Certificate, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: listing certificates: %w", err)
	}
	defer rows.Close()
	var out []Certificate
	for rows.Next() {
		c, err := scanCertificate(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scanning certificate: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterating certificates: %w", err)
	}
	return out, nil
}

// ListCertificatesByCA returns every certificate issued by caID.
func (s *Store) ListCertificatesByCA(ctx context.Context, caID string) ([]Certificate, error) {
	return s.listCertificates(ctx,
		`SELECT `+certColumns+` FROM certificates WHERE ca_id = ? ORDER BY not_before, serial`, caID)
}

// ListRevoked returns every revoked certificate issued by caID.
func (s *Store) ListRevoked(ctx context.Context, caID string) ([]Certificate, error) {
	return s.listCertificates(ctx,
		`SELECT `+certColumns+` FROM certificates WHERE ca_id = ? AND status = ? ORDER BY revoked_at, serial`,
		caID, StatusRevoked)
}

// RevokeCertificate marks a certificate revoked in a single transaction.
// Revoking an already-revoked certificate is a conflict.
func (s *Store) RevokeCertificate(ctx context.Context, serial string, at time.Time, reason int) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: beginning revocation: %w", err)
	}
	defer tx.Rollback()

	var status string
	err = tx.QueryRowContext(ctx, `SELECT status FROM certificates WHERE serial = ?`, serial).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: certificate %q", ErrNotFound, serial)
	}
	if err != nil {
		return fmt.Errorf("store: reading certificate status: %w", err)
	}
	if status == StatusRevoked {
		return fmt.Errorf("%w: certificate %q is already revoked", ErrConflict, serial)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE certificates SET status = ?, revoked_at = ?, revocation_reason = ? WHERE serial = ?`,
		StatusRevoked, at.UTC(), reason, serial); err != nil {
		return fmt.Errorf("store: updating certificate: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: committing revocation: %w", err)
	}
	return nil
}
