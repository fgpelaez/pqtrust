package pqx509

import (
	"bytes"
	"crypto/rand"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestCertificatePEMRoundTrip(t *testing.T) {
	ca, _ := testCA(t, MLDSA44, 0)
	pemBytes := EncodeCertificatePEM(ca.Raw)
	if !strings.HasPrefix(string(pemBytes), "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("unexpected PEM header: %q", string(pemBytes[:40]))
	}
	der, err := DecodeCertificatePEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(der, ca.Raw) {
		t.Error("PEM round-trip changed the DER")
	}
}

func TestDecodeCertificatePEMRejectsWrongType(t *testing.T) {
	if _, err := DecodeCertificatePEM([]byte("-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n")); err == nil {
		t.Error("wrong PEM type must be rejected")
	}
	if _, err := DecodeCertificatePEM([]byte("not pem at all")); err == nil {
		t.Error("non-PEM input must be rejected")
	}
}

func TestEncodeCRLPEM(t *testing.T) {
	ca, signer := testCA(t, MLDSA65, 0)
	now := time.Now().UTC().Truncate(time.Second)
	der, err := CreateRevocationList(rand.Reader, ca, signer, big.NewInt(1), nil, now, now.Add(7*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := EncodeCRLPEM(der)
	if !strings.HasPrefix(string(pemBytes), "-----BEGIN X509 CRL-----") {
		t.Fatalf("unexpected PEM header: %q", string(pemBytes[:40]))
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "X509 CRL" {
		t.Fatalf("unexpected PEM block: %+v", block)
	}
	if _, err := ParseRevocationList(block.Bytes); err != nil {
		t.Fatalf("PEM-wrapped CRL did not parse: %v", err)
	}
}
