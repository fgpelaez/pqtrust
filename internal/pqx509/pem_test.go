package pqx509

import (
	"bytes"
	"crypto/rand"
	"encoding/asn1"
	"encoding/pem"
	"errors"
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

func TestPKCS8RoundTrip(t *testing.T) {
	for _, alg := range []Algorithm{MLDSA44, MLDSA65, MLDSA87} {
		pub, priv, err := GenerateKey(rand.Reader, alg)
		if err != nil {
			t.Fatal(err)
		}
		der, err := MarshalPKCS8PrivateKey(priv)
		if err != nil {
			t.Fatalf("%v: marshal: %v", alg, err)
		}
		back, err := ParsePKCS8PrivateKey(der)
		if err != nil {
			t.Fatalf("%v: parse: %v", alg, err)
		}
		if back.Algorithm != priv.Algorithm || !bytes.Equal(back.Seed, priv.Seed) {
			t.Fatalf("%v: round-trip mismatch", alg)
		}
		signer, err := back.Signer()
		if err != nil {
			t.Fatalf("%v: signer: %v", alg, err)
		}
		if !bytes.Equal(signer.Public().Bytes, pub.Bytes) {
			t.Errorf("%v: seed expands to a different public key", alg)
		}
	}
}

func TestParsePKCS8Rejects(t *testing.T) {
	_, priv, err := GenerateKey(rand.Reader, MLDSA44)
	if err != nil {
		t.Fatal(err)
	}
	good, err := MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	var k oneAsymmetricKey
	if _, err := asn1.Unmarshal(good, &k); err != nil {
		t.Fatal(err)
	}

	k1 := k
	k1.Version = 1
	badVersion, _ := asn1.Marshal(k1)
	if _, err := ParsePKCS8PrivateKey(badVersion); !errors.Is(err, ErrMalformedDER) {
		t.Errorf("version 1: want ErrMalformedDER, got %v", err)
	}

	k2 := k
	k2.Algorithm.Parameters = asn1.RawValue{FullBytes: []byte{0x05, 0x00}}
	badParams, _ := asn1.Marshal(k2)
	if _, err := ParsePKCS8PrivateKey(badParams); !errors.Is(err, ErrMalformedDER) {
		t.Errorf("NULL parameters: want ErrMalformedDER, got %v", err)
	}

	k3 := k
	k3.PrivateKey = k3.PrivateKey[:31]
	badSeed, _ := asn1.Marshal(k3)
	if _, err := ParsePKCS8PrivateKey(badSeed); !errors.Is(err, ErrInvalidKeySize) {
		t.Errorf("31-byte seed: want ErrInvalidKeySize, got %v", err)
	}

	if _, err := ParsePKCS8PrivateKey(append(good, 0x00)); !errors.Is(err, ErrTrailingData) {
		t.Errorf("trailing byte: want ErrTrailingData, got %v", err)
	}
}

func TestPrivateKeyPEM(t *testing.T) {
	_, priv, err := GenerateKey(rand.Reader, MLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := EncodePrivateKeyPEM(priv)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(pemBytes), "-----BEGIN PRIVATE KEY-----") {
		t.Fatalf("unexpected PEM: %q", pemBytes[:40])
	}
	back, err := DecodePrivateKeyPEM(pemBytes)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if back.Algorithm != MLDSA65 || !bytes.Equal(back.Seed, priv.Seed) {
		t.Error("PEM round-trip mismatch")
	}

	legacy := pem.EncodeToMemory(&pem.Block{
		Type:    "PQTRUST ML-DSA PRIVATE KEY",
		Headers: map[string]string{"Algorithm": "ML-DSA-65"},
		Bytes:   priv.Seed,
	})
	back, err = DecodePrivateKeyPEM(legacy)
	if err != nil {
		t.Fatalf("legacy decode: %v", err)
	}
	if back.Algorithm != MLDSA65 || !bytes.Equal(back.Seed, priv.Seed) {
		t.Error("legacy PEM round-trip mismatch")
	}

	certStyle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pemBytes})
	if _, err := DecodePrivateKeyPEM(certStyle); err == nil {
		t.Error("CERTIFICATE-typed block must be rejected")
	}
}
