package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return s
}

func TestOpenAppliesMigrationsIdempotently(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopening an existing database must succeed: %v", err)
	}
	if err := s2.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCALifecycle(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	root := CA{ID: "ca-root", Name: "Root", Algorithm: "ML-DSA-87", CertPEM: "PEM-ROOT", KeyID: "k1", Status: "active", CreatedAt: now}
	if err := s.CreateCA(ctx, root); err != nil {
		t.Fatal(err)
	}
	inter := CA{ID: "ca-int", Name: "Intermediate", ParentID: "ca-root", Algorithm: "ML-DSA-65", CertPEM: "PEM-INT", KeyID: "k2", Status: "active", CreatedAt: now}
	if err := s.CreateCA(ctx, inter); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetCA(ctx, "ca-int")
	if err != nil {
		t.Fatal(err)
	}
	if got.ParentID != "ca-root" || got.Algorithm != "ML-DSA-65" || got.CertPEM != "PEM-INT" {
		t.Errorf("GetCA = %+v", got)
	}
	if !got.CreatedAt.Equal(now) {
		t.Errorf("CreatedAt = %v, want %v", got.CreatedAt, now)
	}

	list, err := s.ListCAs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Errorf("ListCAs returned %d CAs, want 2", len(list))
	}
}

func TestCreateCADuplicateAndMissingParent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	ca := CA{ID: "dup", Name: "A", Algorithm: "ML-DSA-87", CertPEM: "P", KeyID: "k", Status: "active", CreatedAt: now}
	if err := s.CreateCA(ctx, ca); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateCA(ctx, ca); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate CA: want ErrConflict, got %v", err)
	}
	orphan := CA{ID: "orphan", Name: "B", ParentID: "nope", Algorithm: "ML-DSA-65", CertPEM: "P", KeyID: "k", Status: "active", CreatedAt: now}
	if err := s.CreateCA(ctx, orphan); err == nil {
		t.Error("a CA with an unknown parent must be rejected by the foreign key")
	}
}

func TestGetCANotFound(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.GetCA(context.Background(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}
}

func TestCertificateLifecycle(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	if err := s.CreateCA(ctx, CA{ID: "ca1", Name: "CA", Algorithm: "ML-DSA-65", CertPEM: "P", KeyID: "k", Status: "active", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	cert := Certificate{
		Serial:    "0a1b2c",
		CAID:      "ca1",
		SubjectDN: "CN=api.example.com",
		SANs:      "api.example.com,192.0.2.10",
		Algorithm: "ML-DSA-44",
		CertPEM:   "PEM-LEAF",
		Status:    "valid",
		NotBefore: now,
		NotAfter:  now.Add(397 * 24 * time.Hour),
	}
	if err := s.InsertCertificate(ctx, cert); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertCertificate(ctx, cert); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate serial: want ErrConflict, got %v", err)
	}

	got, err := s.GetCertificate(ctx, "0a1b2c")
	if err != nil {
		t.Fatal(err)
	}
	if got.SubjectDN != cert.SubjectDN || got.SANs != cert.SANs || got.Status != "valid" {
		t.Errorf("GetCertificate = %+v", got)
	}
	if got.RevokedAt != nil || got.RevocationReason != nil {
		t.Error("a fresh certificate must have no revocation fields")
	}
	if !got.NotAfter.Equal(cert.NotAfter) {
		t.Errorf("NotAfter = %v, want %v", got.NotAfter, cert.NotAfter)
	}

	list, err := s.ListCertificatesByCA(ctx, "ca1")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("ListCertificatesByCA returned %d, want 1", len(list))
	}
}

func TestRevokeCertificate(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	if err := s.CreateCA(ctx, CA{ID: "ca1", Name: "CA", Algorithm: "ML-DSA-65", CertPEM: "P", KeyID: "k", Status: "active", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertCertificate(ctx, Certificate{
		Serial: "ff", CAID: "ca1", SubjectDN: "CN=x", Algorithm: "ML-DSA-44", CertPEM: "P",
		Status: "valid", NotBefore: now, NotAfter: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	if err := s.RevokeCertificate(ctx, "ff", now, 1); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetCertificate(ctx, "ff")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "revoked" {
		t.Errorf("status = %q, want revoked", got.Status)
	}
	if got.RevokedAt == nil || !got.RevokedAt.Equal(now) {
		t.Errorf("RevokedAt = %v, want %v", got.RevokedAt, now)
	}
	if got.RevocationReason == nil || *got.RevocationReason != 1 {
		t.Errorf("RevocationReason = %v, want 1", got.RevocationReason)
	}

	if err := s.RevokeCertificate(ctx, "ff", now, 1); !errors.Is(err, ErrConflict) {
		t.Errorf("second revoke: want ErrConflict, got %v", err)
	}
	if err := s.RevokeCertificate(ctx, "nope", now, 1); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoking a missing serial: want ErrNotFound, got %v", err)
	}

	revoked, err := s.ListRevoked(ctx, "ca1")
	if err != nil {
		t.Fatal(err)
	}
	if len(revoked) != 1 || revoked[0].Serial != "ff" {
		t.Errorf("ListRevoked = %+v", revoked)
	}
}

func TestTokens(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	tok := Token{ID: "t1", Name: "ci", TokenHash: "abc123", CreatedAt: now}
	if err := s.CreateToken(ctx, tok); err != nil {
		t.Fatal(err)
	}
	got, err := s.TokenByHash(ctx, "abc123")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "t1" || got.Name != "ci" {
		t.Errorf("TokenByHash = %+v", got)
	}
	if _, err := s.TokenByHash(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}
	if err := s.CreateToken(ctx, tok); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate token: want ErrConflict, got %v", err)
	}
}

func TestListCertificatesByCAIsScoped(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	for _, id := range []string{"ca1", "ca2"} {
		if err := s.CreateCA(ctx, CA{ID: id, Name: id, Algorithm: "ML-DSA-65", CertPEM: "P", KeyID: "k-" + id, Status: "active", CreatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.InsertCertificate(ctx, Certificate{Serial: "01", CAID: "ca1", SubjectDN: "CN=a", Algorithm: "ML-DSA-44", CertPEM: "P", Status: "valid", NotBefore: now, NotAfter: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertCertificate(ctx, Certificate{Serial: "02", CAID: "ca2", SubjectDN: "CN=b", Algorithm: "ML-DSA-44", CertPEM: "P", Status: "valid", NotBefore: now, NotAfter: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListCertificatesByCA(ctx, "ca1")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Serial != "01" {
		t.Errorf("ListCertificatesByCA(ca1) = %+v", list)
	}
}
