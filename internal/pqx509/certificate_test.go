package pqx509

import (
	"bytes"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"
)

func testCA(t *testing.T, alg Algorithm, pathLen int) (*Certificate, Signer) {
	t.Helper()
	pub, priv, err := GenerateKey(rand.Reader, alg)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := priv.Signer()
	if err != nil {
		t.Fatal(err)
	}
	serial, err := GenerateSerialNumber(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &Certificate{
		SerialNumber:          serial,
		SignatureAlgorithm:    alg,
		Subject:               Name{CommonName: "pqtrust Test Root", Organization: []string{"pqtrust"}},
		NotBefore:             time.Now().Add(-time.Hour).UTC().Truncate(time.Second),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour).UTC().Truncate(time.Second),
		BasicConstraints:      BasicConstraints{IsCA: true, MaxPathLen: pathLen, MaxPathLenSet: true},
		BasicConstraintsValid: true,
		KeyUsage:              KeyUsageKeyCertSign | KeyUsageCRLSign,
	}
	der, err := CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, signer
}

func TestCreateParseSelfSignedRoundTrip(t *testing.T) {
	cert, _ := testCA(t, MLDSA87, 1)

	if cert.Version != 3 {
		t.Errorf("Version = %d, want 3", cert.Version)
	}
	if cert.SignatureAlgorithm != MLDSA87 {
		t.Errorf("SignatureAlgorithm = %v, want ML-DSA-87", cert.SignatureAlgorithm)
	}
	if len(cert.Signature) != MLDSA87.SignatureSize() {
		t.Errorf("signature length = %d, want %d", len(cert.Signature), MLDSA87.SignatureSize())
	}
	if cert.Subject.CommonName != "pqtrust Test Root" || cert.Issuer.CommonName != "pqtrust Test Root" {
		t.Errorf("self-signed issuer/subject mismatch: %+v / %+v", cert.Issuer, cert.Subject)
	}
	if !cert.IsSelfSigned() {
		t.Error("IsSelfSigned must be true")
	}
	if !cert.BasicConstraints.IsCA || !cert.BasicConstraints.MaxPathLenSet || cert.BasicConstraints.MaxPathLen != 1 {
		t.Errorf("basic constraints = %+v", cert.BasicConstraints)
	}
	if cert.KeyUsage != KeyUsageKeyCertSign|KeyUsageCRLSign {
		t.Errorf("key usage = %b", cert.KeyUsage)
	}
	if len(cert.SubjectKeyID) != 20 {
		t.Errorf("SKID length = %d, want 20", len(cert.SubjectKeyID))
	}
	if !bytes.Equal(cert.SubjectKeyID, cert.AuthorityKeyID) {
		t.Error("self-signed certificate must have AKID == SKID")
	}
	if err := Verify(cert.PublicKey, cert.RawTBSCertificate, cert.Signature); err != nil {
		t.Errorf("self-signature does not verify: %v", err)
	}
	again, err := ParseCertificate(cert.Raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again.Raw, cert.Raw) || !bytes.Equal(again.RawTBSCertificate, cert.RawTBSCertificate) {
		t.Error("re-parse is not byte-stable")
	}
}

func TestCreateEndEntityUnderCA(t *testing.T) {
	ca, caSigner := testCA(t, MLDSA65, 0)
	pub, _, err := GenerateKey(rand.Reader, MLDSA44)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := GenerateSerialNumber(rand.Reader)
	tmpl := &Certificate{
		SerialNumber:          serial,
		SignatureAlgorithm:    MLDSA65,
		Subject:               Name{CommonName: "api.example.com"},
		NotBefore:             time.Now().Add(-time.Minute).UTC().Truncate(time.Second),
		NotAfter:              time.Now().Add(397 * 24 * time.Hour).UTC().Truncate(time.Second),
		BasicConstraints:      BasicConstraints{IsCA: false},
		BasicConstraintsValid: true,
		KeyUsage:              KeyUsageDigitalSignature,
		ExtKeyUsage:           []ExtKeyUsage{ExtKeyUsageServerAuth},
		SANs:                  SANs{DNSNames: []string{"api.example.com"}, IPAddresses: []net.IP{net.ParseIP("192.0.2.10").To4()}},
	}
	der, err := CreateCertificate(rand.Reader, tmpl, ca, pub, caSigner)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(leaf.RawIssuer, ca.RawSubject) {
		t.Error("leaf issuer bytes must equal the CA subject bytes")
	}
	if leaf.PublicKey.Algorithm != MLDSA44 {
		t.Errorf("subject key algorithm = %v, want ML-DSA-44", leaf.PublicKey.Algorithm)
	}
	if leaf.SignatureAlgorithm != MLDSA65 {
		t.Errorf("signature algorithm = %v, want ML-DSA-65", leaf.SignatureAlgorithm)
	}
	if !bytes.Equal(leaf.AuthorityKeyID, ca.SubjectKeyID) {
		t.Error("leaf AKID must equal CA SKID")
	}
	if leaf.BasicConstraints.IsCA {
		t.Error("leaf must not be a CA")
	}
	if len(leaf.SANs.DNSNames) != 1 || leaf.SANs.DNSNames[0] != "api.example.com" {
		t.Errorf("SAN DNS names = %v", leaf.SANs.DNSNames)
	}
	if err := Verify(ca.PublicKey, leaf.RawTBSCertificate, leaf.Signature); err != nil {
		t.Errorf("leaf signature does not verify under the CA key: %v", err)
	}
}

func TestCreateCertificateValidation(t *testing.T) {
	ca, signer := testCA(t, MLDSA65, 0)
	pub, _, _ := GenerateKey(rand.Reader, MLDSA44)
	now := time.Now().UTC().Truncate(time.Second)
	serial, _ := GenerateSerialNumber(rand.Reader)

	t.Run("nil serial", func(t *testing.T) {
		tmpl := &Certificate{SignatureAlgorithm: MLDSA65, NotBefore: now, NotAfter: now.Add(time.Hour), Subject: Name{CommonName: "x"}}
		if _, err := CreateCertificate(rand.Reader, tmpl, ca, pub, signer); err == nil {
			t.Error("missing serial number must be an error")
		}
	})
	t.Run("inverted validity", func(t *testing.T) {
		tmpl := &Certificate{SerialNumber: serial, SignatureAlgorithm: MLDSA65, NotBefore: now, NotAfter: now.Add(-time.Hour), Subject: Name{CommonName: "x"}}
		if _, err := CreateCertificate(rand.Reader, tmpl, ca, pub, signer); err == nil {
			t.Error("NotAfter before NotBefore must be an error")
		}
	})
	t.Run("algorithm mismatch with signer", func(t *testing.T) {
		tmpl := &Certificate{SerialNumber: serial, SignatureAlgorithm: MLDSA87, NotBefore: now, NotAfter: now.Add(time.Hour), Subject: Name{CommonName: "x"}}
		if _, err := CreateCertificate(rand.Reader, tmpl, ca, pub, signer); err == nil {
			t.Error("template signature algorithm must match the signer's algorithm")
		}
	})
	t.Run("empty subject without SANs", func(t *testing.T) {
		tmpl := &Certificate{SerialNumber: serial, SignatureAlgorithm: MLDSA65, NotBefore: now, NotAfter: now.Add(time.Hour)}
		if _, err := CreateCertificate(rand.Reader, tmpl, ca, pub, signer); err == nil {
			t.Error("an empty subject requires subjectAltName")
		}
	})
}

func TestParseCertificateRejectsBadInput(t *testing.T) {
	ca, _ := testCA(t, MLDSA44, 0)

	t.Run("trailing data", func(t *testing.T) {
		if _, err := ParseCertificate(append(bytes.Clone(ca.Raw), 0x00)); err == nil {
			t.Error("trailing data must be rejected")
		}
	})
	t.Run("truncated", func(t *testing.T) {
		if _, err := ParseCertificate(ca.Raw[:len(ca.Raw)/2]); err == nil {
			t.Error("truncated DER must be rejected")
		}
	})
	t.Run("empty", func(t *testing.T) {
		if _, err := ParseCertificate(nil); err == nil {
			t.Error("empty input must be rejected")
		}
	})
}

func TestParseCertificateRejectsUnknownCriticalExtension(t *testing.T) {
	ca, signer := testCA(t, MLDSA44, 0)
	pub, _, _ := GenerateKey(rand.Reader, MLDSA44)
	serial, _ := GenerateSerialNumber(rand.Reader)
	tmpl := &Certificate{
		SerialNumber:       serial,
		SignatureAlgorithm: MLDSA44,
		Subject:            Name{CommonName: "leaf"},
		NotBefore:          time.Now().Add(-time.Minute).UTC().Truncate(time.Second),
		NotAfter:           time.Now().Add(time.Hour).UTC().Truncate(time.Second),
		KeyUsage:           KeyUsageDigitalSignature,
		UnhandledExtensions: []Extension{
			{ID: asn1.ObjectIdentifier{2, 5, 29, 30}, Critical: true, Value: []byte{0x30, 0x00}},
		},
	}
	der, err := CreateCertificate(rand.Reader, tmpl, ca, pub, signer)
	if err != nil {
		t.Fatalf("CreateCertificate with injected extension: %v", err)
	}
	if _, err := ParseCertificate(der); err == nil {
		t.Fatal("a critical unknown extension must make parsing fail")
	}
}

func TestParsePreservesNonCriticalUnknownExtension(t *testing.T) {
	ca, signer := testCA(t, MLDSA44, 0)
	pub, _, _ := GenerateKey(rand.Reader, MLDSA44)
	serial, _ := GenerateSerialNumber(rand.Reader)
	oid := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}
	tmpl := &Certificate{
		SerialNumber:        serial,
		SignatureAlgorithm:  MLDSA44,
		Subject:             Name{CommonName: "leaf"},
		NotBefore:           time.Now().Add(-time.Minute).UTC().Truncate(time.Second),
		NotAfter:            time.Now().Add(time.Hour).UTC().Truncate(time.Second),
		KeyUsage:            KeyUsageDigitalSignature,
		UnhandledExtensions: []Extension{{ID: oid, Critical: false, Value: []byte{0x04, 0x01, 0x2a}}},
	}
	der, err := CreateCertificate(rand.Reader, tmpl, ca, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.UnhandledExtensions) != 1 || !cert.UnhandledExtensions[0].ID.Equal(oid) {
		t.Errorf("non-critical unknown extension not preserved: %+v", cert.UnhandledExtensions)
	}
}

func TestGenerateSerialNumberIsPositiveAnd128Bit(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		s, err := GenerateSerialNumber(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if s.Sign() <= 0 {
			t.Fatalf("serial must be positive, got %s", s)
		}
		if s.BitLen() > 128 {
			t.Fatalf("serial has %d bits, want <= 128", s.BitLen())
		}
		if len(s.Bytes()) > 20 {
			t.Fatalf("serial encodes to %d octets, want <= 20", len(s.Bytes()))
		}
		if seen[s.String()] {
			t.Fatal("duplicate serial number")
		}
		seen[s.String()] = true
	}
	_ = big.NewInt(0)
}

func TestValidityTimesSurviveRoundTrip(t *testing.T) {
	ca, _ := testCA(t, MLDSA44, 0)
	reparsed, err := ParseCertificate(ca.Raw)
	if err != nil {
		t.Fatal(err)
	}
	if !reparsed.NotBefore.Equal(ca.NotBefore) || !reparsed.NotAfter.Equal(ca.NotAfter) {
		t.Errorf("validity mismatch: %v/%v vs %v/%v", reparsed.NotBefore, reparsed.NotAfter, ca.NotBefore, ca.NotAfter)
	}
}

func TestParseCertificateRejectsTBSAlgorithmIdentifierParameters(t *testing.T) {
	ca, _ := testCA(t, MLDSA44, 0)

	var outer certificateDER
	if _, err := asn1.Unmarshal(ca.Raw, &outer); err != nil {
		t.Fatalf("unmarshal outer: %v", err)
	}
	var tbs tbsCertificate
	if _, err := asn1.Unmarshal(outer.TBSCertificate.FullBytes, &tbs); err != nil {
		t.Fatalf("unmarshal TBS: %v", err)
	}
	if len(tbs.SignatureAlgorithm.Parameters.FullBytes) != 0 {
		t.Fatalf("baseline TLS cert must have absent parameters, got %x", tbs.SignatureAlgorithm.Parameters.FullBytes)
	}

	tbs.SignatureAlgorithm.Parameters = asn1.RawValue{FullBytes: []byte{0x05, 0x00}}
	newTBS, err := asn1.Marshal(tbs)
	if err != nil {
		t.Fatalf("re-marshal TBS: %v", err)
	}

	outer.TBSCertificate.FullBytes = newTBS
	crafted, err := asn1.Marshal(outer)
	if err != nil {
		t.Fatalf("re-marshal outer: %v", err)
	}

	_, err = ParseCertificate(crafted)
	if err == nil {
		t.Fatal("ParseCertificate must reject a TBS signature AlgorithmIdentifier carrying parameters")
	}
	if !errors.Is(err, ErrMalformedDER) {
		t.Errorf("err = %v, want one wrapping ErrMalformedDER", err)
	}
}

// TestParseCertificateOpenSSLMinimalShape parses a v3 certificate carrying only
// a critical basicConstraints extension — exactly what
// `openssl req -x509 -config /dev/null -addext "basicConstraints=critical,CA:TRUE"`
// produces (no SKID/AKID). The interop script feeds such a certificate to our parser.
func TestParseCertificateOpenSSLMinimalShape(t *testing.T) {
	pub, priv, err := GenerateKey(rand.Reader, MLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := priv.Signer()
	if err != nil {
		t.Fatal(err)
	}
	nameDER, err := Name{CommonName: "openssl-generated"}.ToRDNSequence()
	if err != nil {
		t.Fatal(err)
	}
	serial, err := GenerateSerialNumber(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nb, err := marshalTime(time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	na, err := marshalTime(time.Now().Add(30 * 24 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	spki, err := MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	var spkiStruct subjectPublicKeyInfo
	if _, err := asn1.Unmarshal(spki, &spkiStruct); err != nil {
		t.Fatal(err)
	}
	bc, err := marshalBasicConstraints(BasicConstraints{IsCA: true})
	if err != nil {
		t.Fatal(err)
	}
	tbs := tbsCertificate{
		Version:            2,
		SerialNumber:       serial,
		SignatureAlgorithm: algorithmIdentifier{Algorithm: MLDSA65.OID()},
		Issuer:             asn1.RawValue{FullBytes: nameDER},
		Validity:           validity{NotBefore: nb, NotAfter: na},
		Subject:            asn1.RawValue{FullBytes: nameDER},
		PublicKey:          spkiStruct,
		Extensions:         []extension{{ID: oidExtBasicConstraints, Critical: true, Value: bc}},
	}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signer.Sign(rand.Reader, tbsDER)
	if err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(certificateDER{
		TBSCertificate:     asn1.RawValue{FullBytes: tbsDER},
		SignatureAlgorithm: algorithmIdentifier{Algorithm: MLDSA65.OID()},
		SignatureValue:     asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate must accept an OpenSSL-style cert without SKID/AKID: %v", err)
	}
	if cert.Subject.CommonName != "openssl-generated" {
		t.Errorf("subject CN = %q", cert.Subject.CommonName)
	}
	if !cert.BasicConstraints.IsCA {
		t.Error("basicConstraints cA=TRUE not parsed")
	}
	if err := cert.VerifySignatureFrom(cert); err != nil {
		t.Errorf("self-signature: %v", err)
	}
}
