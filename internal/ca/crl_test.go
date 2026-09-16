package ca

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/fgpelaez/pqtrust/internal/pqx509"
)

func TestCRLEmptyThenRevoked(t *testing.T) {
	e := newEngine(t)
	ctx := context.Background()
	root := createRoot(t, e)
	inter := createIntermediate(t, e, root.ID)

	der, err := e.CRL(ctx, inter.ID, pass)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := pqx509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(crl.Entries) != 0 {
		t.Errorf("fresh CRL has %d entries, want 0", len(crl.Entries))
	}
	if err := crl.VerifySignatureFrom(inter.Certificate); err != nil {
		t.Errorf("CRL must verify under the issuing CA: %v", err)
	}

	res, err := e.IssueCertificate(ctx, IssueRequest{CAID: inter.ID, CAPassphrase: pass,
		Subject: pqx509.Name{CommonName: "crl.example.com"}, SANs: pqx509.SANs{DNSNames: []string{"crl.example.com"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Revoke(ctx, res.Serial, 4); err != nil {
		t.Fatal(err)
	}

	der2, err := e.CRL(ctx, inter.ID, pass)
	if err != nil {
		t.Fatal(err)
	}
	crl2, err := pqx509.ParseRevocationList(der2)
	if err != nil {
		t.Fatal(err)
	}
	if len(crl2.Entries) != 1 {
		t.Fatalf("CRL has %d entries, want 1", len(crl2.Entries))
	}
	serial, ok := new(big.Int).SetString(res.Serial, 16)
	if !ok {
		t.Fatalf("serial %q is not hex", res.Serial)
	}
	entry, found := crl2.IsRevoked(serial)
	if !found {
		t.Fatal("the revoked serial must appear on the CRL")
	}
	if entry.ReasonCode != 4 {
		t.Errorf("reason = %d, want 4", entry.ReasonCode)
	}
	if crl2.Number.Cmp(crl.Number) <= 0 {
		t.Errorf("CRL number must increase: %v then %v", crl.Number, crl2.Number)
	}
}

func TestCRLIsCachedUntilRevocationChanges(t *testing.T) {
	e := newEngine(t)
	ctx := context.Background()
	root := createRoot(t, e)
	inter := createIntermediate(t, e, root.ID)

	a, err := e.CRL(ctx, inter.ID, pass)
	if err != nil {
		t.Fatal(err)
	}
	b, err := e.CRL(ctx, inter.ID, nil)
	if err != nil {
		t.Fatalf("a cached CRL must not require the passphrase: %v", err)
	}
	if string(a) != string(b) {
		t.Error("an unchanged CRL must be served from cache")
	}

	res, err := e.IssueCertificate(ctx, IssueRequest{CAID: inter.ID, CAPassphrase: pass,
		Subject: pqx509.Name{CommonName: "x.example.com"}, SANs: pqx509.SANs{DNSNames: []string{"x.example.com"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Revoke(ctx, res.Serial, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := e.CRL(ctx, inter.ID, nil); err == nil {
		t.Error("rebuilding the CRL after a revocation requires the passphrase")
	}
	c, err := e.CRL(ctx, inter.ID, pass)
	if err != nil {
		t.Fatal(err)
	}
	if string(c) == string(a) {
		t.Error("the CRL must change after a revocation")
	}
}

func TestCRLUnknownCA(t *testing.T) {
	e := newEngine(t)
	if _, err := e.CRL(context.Background(), "nope", pass); !errors.Is(err, ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}
}

func TestCRLFromSLHDSACA(t *testing.T) {
	e := newEngine(t)
	ctx := context.Background()

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

	res, err := e.IssueCertificate(ctx, IssueRequest{CAID: inter.ID, CAPassphrase: pass,
		Algorithm: pqx509.SLHDSA_SHA2_128s, Subject: pqx509.Name{CommonName: "slh-crl.example.com"},
		SANs: pqx509.SANs{DNSNames: []string{"slh-crl.example.com"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Revoke(ctx, res.Serial, 1); err != nil {
		t.Fatal(err)
	}

	der, err := e.CRL(ctx, inter.ID, pass)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := pqx509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	if crl.SignatureAlgorithm != pqx509.SLHDSA_SHA2_192s {
		t.Errorf("CRL signature algorithm = %v, want the intermediate's SLH-DSA-SHA2-192s", crl.SignatureAlgorithm)
	}
	serial, ok := new(big.Int).SetString(res.Serial, 16)
	if !ok {
		t.Fatalf("serial %q is not hex", res.Serial)
	}
	if entry, found := crl.IsRevoked(serial); !found {
		t.Fatal("the revoked serial must appear on the SLH-DSA CRL")
	} else if entry.ReasonCode != 1 {
		t.Errorf("reason = %d, want 1", entry.ReasonCode)
	}
	if err := crl.VerifySignatureFrom(inter.Certificate); err != nil {
		t.Errorf("CRL must verify under the SLH-DSA intermediate: %v", err)
	}
}
