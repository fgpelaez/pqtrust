package pqx509

import (
	"bytes"
	"strings"
	"testing"
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
