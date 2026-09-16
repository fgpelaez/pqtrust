package ca

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fgpelaez/pqtrust/internal/keystore"
	"github.com/fgpelaez/pqtrust/internal/pqx509"
	"github.com/fgpelaez/pqtrust/internal/store"
)

func newEngine(t *testing.T) *Engine {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "pqtrust.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ks, err := keystore.NewFileBackend(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	e, err := New(st, ks, Options{})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

var pass = []byte("test-passphrase")

func createRoot(t *testing.T, e *Engine) CAResult {
	t.Helper()
	root, err := e.CreateCA(context.Background(), CreateCARequest{
		Name:       "pqtrust Root",
		Algorithm:  pqx509.MLDSA87,
		Subject:    pqx509.Name{CommonName: "pqtrust Root CA", Organization: []string{"pqtrust"}},
		Passphrase: pass,
	})
	if err != nil {
		t.Fatalf("CreateCA(root): %v", err)
	}
	return root
}

func createIntermediate(t *testing.T, e *Engine, rootID string) CAResult {
	t.Helper()
	inter, err := e.CreateCA(context.Background(), CreateCARequest{
		Name:             "pqtrust Issuing",
		ParentID:         rootID,
		Algorithm:        pqx509.MLDSA65,
		Subject:          pqx509.Name{CommonName: "pqtrust Issuing CA", Organization: []string{"pqtrust"}},
		Passphrase:       pass,
		ParentPassphrase: pass,
	})
	if err != nil {
		t.Fatalf("CreateCA(intermediate): %v", err)
	}
	return inter
}

func TestCreateRootCA(t *testing.T) {
	e := newEngine(t)
	root := createRoot(t, e)

	if root.ID == "" {
		t.Error("root CA must get an ID")
	}
	cert := root.Certificate
	if !cert.IsSelfSigned() {
		t.Error("root must be self-signed")
	}
	if cert.SignatureAlgorithm != pqx509.MLDSA87 {
		t.Errorf("algorithm = %v, want ML-DSA-87", cert.SignatureAlgorithm)
	}
	if !cert.BasicConstraints.IsCA || cert.BasicConstraints.MaxPathLen != 1 {
		t.Errorf("basic constraints = %+v, want cA=TRUE pathlen=1", cert.BasicConstraints)
	}
	if cert.KeyUsage != pqx509.KeyUsageKeyCertSign|pqx509.KeyUsageCRLSign {
		t.Errorf("key usage = %b", cert.KeyUsage)
	}
	years := cert.NotAfter.Sub(cert.NotBefore).Hours() / 24 / 365
	if years < 9.9 || years > 10.1 {
		t.Errorf("root validity = %.2f years, want ~10", years)
	}
	if !strings.Contains(root.CertPEM, "BEGIN CERTIFICATE") {
		t.Error("CertPEM must be PEM")
	}
	if root.ChainPEM != root.CertPEM {
		t.Error("a root's chain is just itself")
	}
}

func TestCreateIntermediateCA(t *testing.T) {
	e := newEngine(t)
	root := createRoot(t, e)
	inter := createIntermediate(t, e, root.ID)

	cert := inter.Certificate
	if cert.IsSelfSigned() {
		t.Error("intermediate must not be self-signed")
	}
	if cert.SignatureAlgorithm != pqx509.MLDSA87 {
		t.Errorf("intermediate must be signed by the root's ML-DSA-87 key, got %v", cert.SignatureAlgorithm)
	}
	if cert.PublicKey.Algorithm != pqx509.MLDSA65 {
		t.Errorf("intermediate key algorithm = %v, want ML-DSA-65", cert.PublicKey.Algorithm)
	}
	if !cert.BasicConstraints.IsCA || cert.BasicConstraints.MaxPathLen != 0 {
		t.Errorf("basic constraints = %+v, want cA=TRUE pathlen=0", cert.BasicConstraints)
	}
	if err := cert.VerifySignatureFrom(root.Certificate); err != nil {
		t.Errorf("intermediate must verify under the root: %v", err)
	}
	if strings.Count(inter.ChainPEM, "BEGIN CERTIFICATE") != 2 {
		t.Errorf("chain must contain 2 certificates:\n%s", inter.ChainPEM)
	}
}

func TestCreateCAConstraints(t *testing.T) {
	e := newEngine(t)
	ctx := context.Background()
	root := createRoot(t, e)

	t.Run("root with wrong algorithm", func(t *testing.T) {
		_, err := e.CreateCA(ctx, CreateCARequest{Name: "bad", Algorithm: pqx509.MLDSA44, Subject: pqx509.Name{CommonName: "bad"}, Passphrase: pass})
		if !errors.Is(err, ErrConstraintViolation) {
			t.Errorf("want ErrConstraintViolation, got %v", err)
		}
	})
	t.Run("intermediate with wrong algorithm", func(t *testing.T) {
		_, err := e.CreateCA(ctx, CreateCARequest{Name: "bad", ParentID: root.ID, Algorithm: pqx509.MLDSA87,
			Subject: pqx509.Name{CommonName: "bad"}, Passphrase: pass, ParentPassphrase: pass})
		if !errors.Is(err, ErrConstraintViolation) {
			t.Errorf("want ErrConstraintViolation, got %v", err)
		}
	})
	t.Run("three levels rejected", func(t *testing.T) {
		inter := createIntermediate(t, e, root.ID)
		_, err := e.CreateCA(ctx, CreateCARequest{Name: "third", ParentID: inter.ID, Algorithm: pqx509.MLDSA65,
			Subject: pqx509.Name{CommonName: "third"}, Passphrase: pass, ParentPassphrase: pass})
		if !errors.Is(err, ErrConstraintViolation) {
			t.Errorf("a third hierarchy level must be rejected, got %v", err)
		}
	})
	t.Run("unknown parent", func(t *testing.T) {
		_, err := e.CreateCA(ctx, CreateCARequest{Name: "orphan", ParentID: "nope", Algorithm: pqx509.MLDSA65,
			Subject: pqx509.Name{CommonName: "orphan"}, Passphrase: pass, ParentPassphrase: pass})
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("want ErrNotFound, got %v", err)
		}
	})
	t.Run("wrong parent passphrase", func(t *testing.T) {
		_, err := e.CreateCA(ctx, CreateCARequest{Name: "x", ParentID: root.ID, Algorithm: pqx509.MLDSA65,
			Subject: pqx509.Name{CommonName: "x"}, Passphrase: pass, ParentPassphrase: []byte("wrong")})
		if !errors.Is(err, keystore.ErrWrongPassphrase) {
			t.Errorf("want keystore.ErrWrongPassphrase, got %v", err)
		}
	})
	t.Run("validity beyond the maximum", func(t *testing.T) {
		_, err := e.CreateCA(ctx, CreateCARequest{Name: "long", Algorithm: pqx509.MLDSA87,
			Subject: pqx509.Name{CommonName: "long"}, ValidityDays: 20000, Passphrase: pass})
		if !errors.Is(err, ErrConstraintViolation) {
			t.Errorf("want ErrConstraintViolation, got %v", err)
		}
	})
}

func TestIssueCertificate(t *testing.T) {
	e := newEngine(t)
	ctx := context.Background()
	root := createRoot(t, e)
	inter := createIntermediate(t, e, root.ID)

	res, err := e.IssueCertificate(ctx, IssueRequest{
		CAID:         inter.ID,
		CAPassphrase: pass,
		Subject:      pqx509.Name{CommonName: "api.example.com"},
		SANs:         pqx509.SANs{DNSNames: []string{"api.example.com"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Serial == "" {
		t.Error("serial must be set")
	}
	if res.PrivateKeyPEM == "" {
		t.Error("the private key must be returned when StoreKey is false")
	}
	if !strings.Contains(res.PrivateKeyPEM, "-----BEGIN PRIVATE KEY-----") {
		t.Errorf("unexpected private key PEM: %q", res.PrivateKeyPEM[:40])
	}
	privKey, err := pqx509.DecodePrivateKeyPEM([]byte(res.PrivateKeyPEM))
	if err != nil {
		t.Fatalf("decoding private key PEM: %v", err)
	}
	if privKey.Algorithm != pqx509.MLDSA44 {
		t.Errorf("private key algorithm = %v, want ML-DSA-44", privKey.Algorithm)
	}
	leaf := res.Certificate
	if leaf.PublicKey.Algorithm != pqx509.MLDSA44 {
		t.Errorf("default end-entity algorithm = %v, want ML-DSA-44", leaf.PublicKey.Algorithm)
	}
	if leaf.KeyUsage != pqx509.KeyUsageDigitalSignature {
		t.Errorf("key usage = %b", leaf.KeyUsage)
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != pqx509.ExtKeyUsageServerAuth {
		t.Errorf("default EKU = %v, want [serverAuth]", leaf.ExtKeyUsage)
	}
	if leaf.BasicConstraints.IsCA {
		t.Error("end-entity must not be a CA")
	}
	days := leaf.NotAfter.Sub(leaf.NotBefore).Hours() / 24
	if days < 89 || days > 91 {
		t.Errorf("default validity = %.1f days, want ~90", days)
	}
	chains, err := leaf.Verify(pqx509.VerifyOptions{
		Roots:         []*pqx509.Certificate{root.Certificate},
		Intermediates: []*pqx509.Certificate{inter.Certificate},
	})
	if err != nil {
		t.Fatalf("issued certificate must chain to the root: %v", err)
	}
	if len(chains[0]) != 3 {
		t.Errorf("chain length = %d, want 3", len(chains[0]))
	}
	if strings.Count(res.ChainPEM, "BEGIN CERTIFICATE") != 3 {
		t.Errorf("ChainPEM must hold leaf + intermediate + root:\n%s", res.ChainPEM)
	}

	rec, err := e.GetCertificate(ctx, res.Serial)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != store.StatusValid || rec.CAID != inter.ID {
		t.Errorf("record = %+v", rec)
	}
	if rec.KeyID != "" {
		t.Error("the key must not be stored when StoreKey is false")
	}
	if rec.SANs != "api.example.com" {
		t.Errorf("stored SANs = %q", rec.SANs)
	}
}

func TestIssueCertificateStoreKey(t *testing.T) {
	e := newEngine(t)
	ctx := context.Background()
	root := createRoot(t, e)
	inter := createIntermediate(t, e, root.ID)

	res, err := e.IssueCertificate(ctx, IssueRequest{
		CAID: inter.ID, CAPassphrase: pass,
		Subject:  pqx509.Name{CommonName: "stored.example.com"},
		SANs:     pqx509.SANs{DNSNames: []string{"stored.example.com"}},
		StoreKey: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.PrivateKeyPEM != "" {
		t.Error("the private key must not be returned when StoreKey is true")
	}
	rec, err := e.GetCertificate(ctx, res.Serial)
	if err != nil {
		t.Fatal(err)
	}
	if rec.KeyID == "" {
		t.Error("a stored key must be recorded")
	}
}

func TestIssueCertificateConstraints(t *testing.T) {
	e := newEngine(t)
	ctx := context.Background()
	root := createRoot(t, e)
	inter := createIntermediate(t, e, root.ID)

	t.Run("root may not issue end-entity certificates", func(t *testing.T) {
		_, err := e.IssueCertificate(ctx, IssueRequest{CAID: root.ID, CAPassphrase: pass,
			Subject: pqx509.Name{CommonName: "x"}, SANs: pqx509.SANs{DNSNames: []string{"x"}}})
		if !errors.Is(err, ErrConstraintViolation) {
			t.Errorf("want ErrConstraintViolation, got %v", err)
		}
	})
	t.Run("validity beyond the maximum", func(t *testing.T) {
		_, err := e.IssueCertificate(ctx, IssueRequest{CAID: inter.ID, CAPassphrase: pass,
			Subject: pqx509.Name{CommonName: "x"}, SANs: pqx509.SANs{DNSNames: []string{"x"}}, ValidityDays: 500})
		if !errors.Is(err, ErrConstraintViolation) {
			t.Errorf("want ErrConstraintViolation, got %v", err)
		}
	})
	t.Run("unsupported algorithm", func(t *testing.T) {
		_, err := e.IssueCertificate(ctx, IssueRequest{CAID: inter.ID, CAPassphrase: pass, Algorithm: pqx509.MLDSA87,
			Subject: pqx509.Name{CommonName: "x"}, SANs: pqx509.SANs{DNSNames: []string{"x"}}})
		if !errors.Is(err, ErrConstraintViolation) {
			t.Errorf("ML-DSA-87 end-entity certificates are not offered: %v", err)
		}
	})
	t.Run("no subject and no SANs", func(t *testing.T) {
		_, err := e.IssueCertificate(ctx, IssueRequest{CAID: inter.ID, CAPassphrase: pass})
		if !errors.Is(err, ErrConstraintViolation) {
			t.Errorf("want ErrConstraintViolation, got %v", err)
		}
	})
	t.Run("unknown CA", func(t *testing.T) {
		_, err := e.IssueCertificate(ctx, IssueRequest{CAID: "nope", CAPassphrase: pass,
			Subject: pqx509.Name{CommonName: "x"}, SANs: pqx509.SANs{DNSNames: []string{"x"}}})
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("want ErrNotFound, got %v", err)
		}
	})
	t.Run("wrong CA passphrase", func(t *testing.T) {
		_, err := e.IssueCertificate(ctx, IssueRequest{CAID: inter.ID, CAPassphrase: []byte("wrong"),
			Subject: pqx509.Name{CommonName: "x"}, SANs: pqx509.SANs{DNSNames: []string{"x"}}})
		if !errors.Is(err, keystore.ErrWrongPassphrase) {
			t.Errorf("want keystore.ErrWrongPassphrase, got %v", err)
		}
	})
}

func TestRevoke(t *testing.T) {
	e := newEngine(t)
	ctx := context.Background()
	root := createRoot(t, e)
	inter := createIntermediate(t, e, root.ID)
	res, err := e.IssueCertificate(ctx, IssueRequest{CAID: inter.ID, CAPassphrase: pass,
		Subject: pqx509.Name{CommonName: "revoke.example.com"}, SANs: pqx509.SANs{DNSNames: []string{"revoke.example.com"}}})
	if err != nil {
		t.Fatal(err)
	}

	if err := e.Revoke(ctx, res.Serial, 1); err != nil {
		t.Fatal(err)
	}
	rec, err := e.GetCertificate(ctx, res.Serial)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != store.StatusRevoked || rec.RevocationReason == nil || *rec.RevocationReason != 1 {
		t.Errorf("record after revoke = %+v", rec)
	}
	if err := e.Revoke(ctx, res.Serial, 1); !errors.Is(err, ErrAlreadyRevoked) {
		t.Errorf("second revoke: want ErrAlreadyRevoked, got %v", err)
	}
	if err := e.Revoke(ctx, "deadbeef", 1); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoking an unknown serial: want ErrNotFound, got %v", err)
	}
}

func TestInjectedClockGovernsValidity(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ks, err := keystore.NewFileBackend(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	fixed := time.Date(2030, 5, 4, 3, 2, 1, 0, time.UTC)
	e, err := New(st, ks, Options{Now: func() time.Time { return fixed }})
	if err != nil {
		t.Fatal(err)
	}
	root, err := e.CreateCA(context.Background(), CreateCARequest{Name: "R", Algorithm: pqx509.MLDSA87,
		Subject: pqx509.Name{CommonName: "R"}, Passphrase: pass})
	if err != nil {
		t.Fatal(err)
	}
	if root.Certificate.NotBefore.After(fixed) {
		t.Errorf("NotBefore %v must not be after the injected now %v", root.Certificate.NotBefore, fixed)
	}
	if root.Certificate.NotAfter.Year() != 2040 {
		t.Errorf("NotAfter year = %d, want 2040", root.Certificate.NotAfter.Year())
	}
}

func makeTestCSR(t *testing.T, subj pqx509.Name, sans pqx509.SANs, alg pqx509.Algorithm) *pqx509.CertificateRequest {
	t.Helper()
	pub, priv, err := pqx509.GenerateKey(rand.Reader, alg)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := priv.Signer()
	if err != nil {
		t.Fatal(err)
	}
	der, err := pqx509.CreateCertificateRequest(rand.Reader, subj, pub, signer, sans)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pqx509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

func TestIssueFromCSR(t *testing.T) {
	e := newEngine(t)
	root := createRoot(t, e)
	inter := createIntermediate(t, e, root.ID)

	csr := makeTestCSR(t,
		pqx509.Name{CommonName: "csr.example.com", Organization: []string{"pqtrust"}},
		pqx509.SANs{DNSNames: []string{"csr.example.com"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}},
		pqx509.MLDSA44)

	res, err := e.IssueCertificate(context.Background(), IssueRequest{
		CAID:         inter.ID,
		CAPassphrase: []byte(pass),
		CSR:          csr,
		ExtKeyUsage:  []pqx509.ExtKeyUsage{pqx509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		t.Fatalf("IssueCertificate from CSR: %v", err)
	}
	if res.PrivateKeyPEM != "" {
		t.Error("CSR issuance must not return a private key")
	}
	if res.Certificate.Subject.CommonName != "csr.example.com" {
		t.Errorf("CN = %q", res.Certificate.Subject.CommonName)
	}
	if len(res.Certificate.SANs.DNSNames) != 1 || res.Certificate.SANs.DNSNames[0] != "csr.example.com" {
		t.Errorf("DNSNames = %v", res.Certificate.SANs.DNSNames)
	}
	if len(res.Certificate.SANs.IPAddresses) != 1 {
		t.Errorf("IPAddresses = %v", res.Certificate.SANs.IPAddresses)
	}
	if !bytes.Equal(res.Certificate.PublicKey.Bytes, csr.PublicKey.Bytes) {
		t.Error("certificate public key must be the CSR public key")
	}
	if res.Certificate.ExtKeyUsage[0] != pqx509.ExtKeyUsageClientAuth {
		t.Errorf("EKU = %v, want clientAuth from the request", res.Certificate.ExtKeyUsage)
	}
	rec, err := e.GetCertificate(context.Background(), res.Serial)
	if err != nil {
		t.Fatal(err)
	}
	if rec.SubjectDN != "CN=csr.example.com,O=pqtrust" {
		t.Errorf("stored SubjectDN = %q", rec.SubjectDN)
	}
	if rec.KeyID != "" {
		t.Error("CSR issuance must not store a key")
	}
}

func TestIssueFromCSRConstraints(t *testing.T) {
	e := newEngine(t)
	root := createRoot(t, e)
	inter := createIntermediate(t, e, root.ID)

	// End-entity profile forbids ML-DSA-87.
	csr87 := makeTestCSR(t, pqx509.Name{CommonName: "x"}, pqx509.SANs{DNSNames: []string{"x.example.com"}}, pqx509.MLDSA87)
	if _, err := e.IssueCertificate(context.Background(), IssueRequest{
		CAID: inter.ID, CAPassphrase: []byte(pass), CSR: csr87,
	}); !errors.Is(err, ErrConstraintViolation) {
		t.Errorf("ML-DSA-87 CSR: want ErrConstraintViolation, got %v", err)
	}

	// store_key is meaningless when the server never sees the key.
	csr := makeTestCSR(t, pqx509.Name{CommonName: "x"}, pqx509.SANs{DNSNames: []string{"x.example.com"}}, pqx509.MLDSA44)
	if _, err := e.IssueCertificate(context.Background(), IssueRequest{
		CAID: inter.ID, CAPassphrase: []byte(pass), CSR: csr, StoreKey: true,
	}); !errors.Is(err, ErrConstraintViolation) {
		t.Errorf("store_key with CSR: want ErrConstraintViolation, got %v", err)
	}

	// A CSR whose signature does not verify must never reach issuance.
	tampered := *csr
	tampered.Signature = bytes.Clone(csr.Signature)
	tampered.Signature[0] ^= 0xFF
	if _, err := e.IssueCertificate(context.Background(), IssueRequest{
		CAID: inter.ID, CAPassphrase: []byte(pass), CSR: &tampered,
	}); !errors.Is(err, pqx509.ErrCSRSignature) {
		t.Errorf("tampered CSR: want ErrCSRSignature, got %v", err)
	}
}

func TestCreateCAAlgorithmAllowList(t *testing.T) {
	e := newEngine(t)
	ctx := context.Background()
	pass := []byte("pass")

	cases := []struct {
		name    string
		parent  string // "" = root
		alg     pqx509.Algorithm
		wantErr bool
	}{
		{"root ML-DSA-87 ok", "", pqx509.MLDSA87, false},
		{"root SLH-DSA-SHA2-256s ok", "", pqx509.SLHDSA_SHA2_256s, false},
		{"root SLH-DSA-SHAKE-256s ok", "", pqx509.SLHDSA_SHAKE_256s, false},
		{"root SLH-DSA-SHA2-256f rejected", "", pqx509.SLHDSA_SHA2_256f, true},
		{"root ML-DSA-44 still rejected", "", pqx509.MLDSA44, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := CreateCARequest{Name: "X", Algorithm: tc.alg,
				Subject: pqx509.Name{CommonName: "X"}, Passphrase: pass}
			_, err := e.CreateCA(ctx, req)
			if tc.wantErr && !errors.Is(err, ErrConstraintViolation) {
				t.Errorf("want ErrConstraintViolation, got %v", err)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}

	// Intermediate level against an SLH-DSA root.
	root, err := e.CreateCA(ctx, CreateCARequest{Name: "R", Algorithm: pqx509.SLHDSA_SHA2_256s,
		Subject: pqx509.Name{CommonName: "R"}, Passphrase: pass})
	if err != nil {
		t.Fatal(err)
	}
	interCases := []struct {
		name    string
		alg     pqx509.Algorithm
		wantErr bool
	}{
		{"intermediate SLH-DSA-SHA2-192s ok", pqx509.SLHDSA_SHA2_192s, false},
		{"intermediate SLH-DSA-SHAKE-192s ok", pqx509.SLHDSA_SHAKE_192s, false},
		{"intermediate SLH-DSA-SHA2-128s rejected", pqx509.SLHDSA_SHA2_128s, true},
		{"intermediate SLH-DSA-SHA2-192f rejected", pqx509.SLHDSA_SHA2_192f, true},
		{"intermediate ML-DSA-65 ok", pqx509.MLDSA65, false},
	}
	for _, tc := range interCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := e.CreateCA(ctx, CreateCARequest{Name: "I", ParentID: root.ID, Algorithm: tc.alg,
				Subject: pqx509.Name{CommonName: "I"}, Passphrase: pass, ParentPassphrase: pass})
			if tc.wantErr && !errors.Is(err, ErrConstraintViolation) {
				t.Errorf("want ErrConstraintViolation, got %v", err)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestSLHDSAHierarchyEndEntityAndCSR(t *testing.T) {
	e := newEngine(t)
	ctx := context.Background()
	pass := []byte("pass")

	root, err := e.CreateCA(ctx, CreateCARequest{Name: "R", Algorithm: pqx509.SLHDSA_SHA2_256s,
		Subject: pqx509.Name{CommonName: "R"}, Passphrase: pass})
	if err != nil {
		t.Fatal(err)
	}
	inter, err := e.CreateCA(ctx, CreateCARequest{Name: "I", ParentID: root.ID, Algorithm: pqx509.SLHDSA_SHA2_192s,
		Subject: pqx509.Name{CommonName: "I"}, Passphrase: pass, ParentPassphrase: pass})
	if err != nil {
		t.Fatal(err)
	}
	if inter.Certificate.SignatureAlgorithm != pqx509.SLHDSA_SHA2_256s {
		t.Errorf("intermediate signed with %v, want the root's SLH-DSA-SHA2-256s", inter.Certificate.SignatureAlgorithm)
	}

	// End-entity: every allowed set issues; 192f is rejected.
	for _, alg := range []pqx509.Algorithm{
		pqx509.SLHDSA_SHA2_128s, pqx509.SLHDSA_SHA2_128f,
		pqx509.SLHDSA_SHAKE_128s, pqx509.SLHDSA_SHAKE_128f,
	} {
		res, err := e.IssueCertificate(ctx, IssueRequest{CAID: inter.ID, CAPassphrase: pass,
			Algorithm: alg, Subject: pqx509.Name{CommonName: alg.String()}})
		if err != nil {
			t.Fatalf("%s: issue: %v", alg, err)
		}
		if res.Certificate.PublicKey.Algorithm != alg {
			t.Errorf("%s: issued with %v", alg, res.Certificate.PublicKey.Algorithm)
		}
		if res.Certificate.SignatureAlgorithm != pqx509.SLHDSA_SHA2_192s {
			t.Errorf("%s: signed with %v, want the intermediate's SLH-DSA-SHA2-192s", alg, res.Certificate.SignatureAlgorithm)
		}
	}
	_, err = e.IssueCertificate(ctx, IssueRequest{CAID: inter.ID, CAPassphrase: pass,
		Algorithm: pqx509.SLHDSA_SHA2_192f, Subject: pqx509.Name{CommonName: "no"}})
	if !errors.Is(err, ErrConstraintViolation) {
		t.Errorf("192f end-entity: want ErrConstraintViolation, got %v", err)
	}

	// CSR path: an allowed SLH-DSA SPKI issues; 192f is a constraint violation.
	csrOK := makeTestCSR(t, pqx509.Name{CommonName: "slh-csr.example.com"},
		pqx509.SANs{DNSNames: []string{"slh-csr.example.com"}}, pqx509.SLHDSA_SHA2_128s)
	res, err := e.IssueCertificate(ctx, IssueRequest{CAID: inter.ID, CAPassphrase: pass, CSR: csrOK})
	if err != nil {
		t.Fatalf("SLH-DSA CSR issue: %v", err)
	}
	if res.Certificate.PublicKey.Algorithm != pqx509.SLHDSA_SHA2_128s {
		t.Errorf("CSR-issued algorithm = %v", res.Certificate.PublicKey.Algorithm)
	}
	if res.PrivateKeyPEM != "" {
		t.Error("CSR issuance must not return a private key")
	}
	csrBad := makeTestCSR(t, pqx509.Name{CommonName: "no.example.com"},
		pqx509.SANs{DNSNames: []string{"no.example.com"}}, pqx509.SLHDSA_SHA2_192f)
	_, err = e.IssueCertificate(ctx, IssueRequest{CAID: inter.ID, CAPassphrase: pass, CSR: csrBad})
	if !errors.Is(err, ErrConstraintViolation) {
		t.Errorf("192f CSR: want ErrConstraintViolation, got %v", err)
	}
}
