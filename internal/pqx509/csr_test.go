package pqx509

import (
	"bytes"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"net"
	"testing"
)

func makeCSR(t *testing.T, subj Name, sans SANs) ([]byte, PublicKey) {
	t.Helper()
	pub, priv, err := GenerateKey(rand.Reader, MLDSA44)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := priv.Signer()
	if err != nil {
		t.Fatal(err)
	}
	der, err := CreateCertificateRequest(rand.Reader, subj, pub, signer, sans)
	if err != nil {
		t.Fatal(err)
	}
	return der, pub
}

func TestCSRCreateParseRoundTrip(t *testing.T) {
	subj := Name{CommonName: "csr.example.com", Organization: []string{"pqtrust"}}
	sans := SANs{
		DNSNames:       []string{"csr.example.com", "alt.example.com"},
		IPAddresses:    []net.IP{net.ParseIP("127.0.0.1")},
		EmailAddresses: []string{"ops@example.com"},
	}
	der, pub := makeCSR(t, subj, sans)

	csr, err := ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}
	if !bytes.Equal(csr.Raw, der) {
		t.Error("Raw must be the input DER")
	}
	if csr.Subject.CommonName != subj.CommonName || len(csr.Subject.Organization) != 1 {
		t.Errorf("Subject = %+v", csr.Subject)
	}
	if csr.PublicKey.Algorithm != MLDSA44 || !bytes.Equal(csr.PublicKey.Bytes, pub.Bytes) {
		t.Error("PublicKey mismatch")
	}
	if csr.SignatureAlgorithm != MLDSA44 {
		t.Errorf("SignatureAlgorithm = %v", csr.SignatureAlgorithm)
	}
	if len(csr.DNSNames) != 2 || csr.DNSNames[0] != "csr.example.com" {
		t.Errorf("DNSNames = %v", csr.DNSNames)
	}
	if len(csr.IPAddresses) != 1 || !csr.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("IPAddresses = %v", csr.IPAddresses)
	}
	if len(csr.EmailAddresses) != 1 || csr.EmailAddresses[0] != "ops@example.com" {
		t.Errorf("EmailAddresses = %v", csr.EmailAddresses)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Errorf("CheckSignature: %v", err)
	}
}

func TestCSRCheckSignatureNegatives(t *testing.T) {
	der, _ := makeCSR(t, Name{CommonName: "x.example.com"}, SANs{DNSNames: []string{"x.example.com"}})

	csr, err := ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}

	badSig := *csr
	badSig.Signature = bytes.Clone(csr.Signature)
	badSig.Signature[0] ^= 0xFF
	if err := badSig.CheckSignature(); !errorsIs(err, ErrCSRSignature) {
		t.Errorf("flipped signature bit: want ErrCSRSignature, got %v", err)
	}

	badTBS := *csr
	badTBS.RawTBSCSR = bytes.Clone(csr.RawTBSCSR)
	badTBS.RawTBSCSR[len(badTBS.RawTBSCSR)-1] ^= 0xFF
	if err := badTBS.CheckSignature(); !errorsIs(err, ErrCSRSignature) {
		t.Errorf("tampered CRI: want ErrCSRSignature, got %v", err)
	}
}

func TestCSRParseRejects(t *testing.T) {
	der, _ := makeCSR(t, Name{CommonName: "x.example.com"}, SANs{DNSNames: []string{"x.example.com"}})
	csr, err := ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := ParseCertificateRequest(append(der, 0x00)); !errorsIs(err, ErrTrailingData) {
		t.Errorf("trailing byte: want ErrTrailingData, got %v", err)
	}

	// NULL signature parameters.
	badParams, err := asn1.Marshal(certificationRequestDER{
		CRI:                asn1.RawValue{FullBytes: csr.RawTBSCSR},
		SignatureAlgorithm: algorithmIdentifier{Algorithm: MLDSA44.OID(), Parameters: asn1.RawValue{FullBytes: []byte{0x05, 0x00}}},
		SignatureValue:     asn1.BitString{Bytes: csr.Signature, BitLength: len(csr.Signature) * 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseCertificateRequest(badParams); !errorsIs(err, ErrInvalidCSR) {
		t.Errorf("NULL parameters: want ErrInvalidCSR, got %v", err)
	}

	// Version 1: re-marshal the CRI struct with a bumped version. This also
	// proves the struct-based marshal is byte-compatible with CreateCertificateRequest.
	var cri certificationRequestInfoDER
	if _, err := asn1.Unmarshal(csr.RawTBSCSR, &cri); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mustReMarshalCRI(t, cri), csr.RawTBSCSR) {
		t.Fatal("CRI struct re-marshal must be byte-identical to CreateCertificateRequest output")
	}
	cri.Version = 1
	badVersion, err := asn1.Marshal(certificationRequestDER{
		CRI:                asn1.RawValue{FullBytes: mustReMarshalCRI(t, cri)},
		SignatureAlgorithm: algorithmIdentifier{Algorithm: MLDSA44.OID()},
		SignatureValue:     asn1.BitString{Bytes: csr.Signature, BitLength: len(csr.Signature) * 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseCertificateRequest(badVersion); !errorsIs(err, ErrInvalidCSR) {
		t.Errorf("version 1: want ErrInvalidCSR, got %v", err)
	}

	// Wrong signature size (ML-DSA-65 sig attached to an ML-DSA-44 CSR).
	bigSig := make([]byte, MLDSA65.SignatureSize())
	bigSig[0] = csr.Signature[0]
	badSize, err := asn1.Marshal(certificationRequestDER{
		CRI:                asn1.RawValue{FullBytes: csr.RawTBSCSR},
		SignatureAlgorithm: algorithmIdentifier{Algorithm: MLDSA44.OID()},
		SignatureValue:     asn1.BitString{Bytes: bigSig, BitLength: len(bigSig) * 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseCertificateRequest(badSize); !errorsIs(err, ErrInvalidCSR) {
		t.Errorf("wrong sig size: want ErrInvalidCSR, got %v", err)
	}

	// Signature algorithm OID not matching the SPKI algorithm.
	badAlg, err := asn1.Marshal(certificationRequestDER{
		CRI:                asn1.RawValue{FullBytes: csr.RawTBSCSR},
		SignatureAlgorithm: algorithmIdentifier{Algorithm: MLDSA65.OID()},
		SignatureValue:     asn1.BitString{Bytes: bigSig, BitLength: len(bigSig) * 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseCertificateRequest(badAlg); !errorsIs(err, ErrInvalidCSR) {
		t.Errorf("algorithm mismatch: want ErrInvalidCSR, got %v", err)
	}
}

func TestCSRExtensionRequestPolicy(t *testing.T) {
	// Build a CSR whose extensionRequest carries SANs + EKU; only SANs may surface.
	pub, priv, err := GenerateKey(rand.Reader, MLDSA44)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := priv.Signer()
	if err != nil {
		t.Fatal(err)
	}

	sanDER, err := marshalSANs(SANs{DNSNames: []string{"policy.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	ekuDER, err := marshalExtKeyUsage([]ExtKeyUsage{ExtKeyUsageClientAuth})
	if err != nil {
		t.Fatal(err)
	}
	extsDER, err := asn1.Marshal([]extension{
		{ID: oidExtSubjectAltName, Value: sanDER},
		{ID: oidExtExtendedKeyUsage, Value: ekuDER},
	})
	if err != nil {
		t.Fatal(err)
	}
	attrDER, err := asn1.Marshal(csrAttributeDER{
		Type:   oidExtensionRequest,
		Values: []asn1.RawValue{{FullBytes: extsDER}},
	})
	if err != nil {
		t.Fatal(err)
	}
	attrs := append([]byte{0xA0}, append(marshalLength(len(attrDER)), attrDER...)...)

	subjectDER, err := (Name{CommonName: "policy.example.com"}).ToRDNSequence()
	if err != nil {
		t.Fatal(err)
	}
	spkiDER, err := MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	zero, err := asn1.Marshal(0)
	if err != nil {
		t.Fatal(err)
	}
	cri := marshalSequence(concatDER(zero, subjectDER, spkiDER, attrs))
	sig, err := signer.Sign(rand.Reader, cri)
	if err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(certificationRequestDER{
		CRI:                asn1.RawValue{FullBytes: cri},
		SignatureAlgorithm: algorithmIdentifier{Algorithm: MLDSA44.OID()},
		SignatureValue:     asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	})
	if err != nil {
		t.Fatal(err)
	}

	csr, err := ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(csr.DNSNames) != 1 || csr.DNSNames[0] != "policy.example.com" {
		t.Errorf("DNSNames = %v, want [policy.example.com]", csr.DNSNames)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Errorf("CheckSignature: %v", err)
	}
	// EKU requested in the CSR must not leak anywhere: CertificateRequest has no EKU field by design.

	// A second extensionRequest attribute is a hard error.
	dupAttrs := append([]byte{0xA0}, append(marshalLength(2*len(attrDER)), append(append([]byte{}, attrDER...), attrDER...)...)...)
	cri2 := marshalSequence(concatDER(zero, subjectDER, spkiDER, dupAttrs))
	sig2, err := signer.Sign(rand.Reader, cri2)
	if err != nil {
		t.Fatal(err)
	}
	der2, err := asn1.Marshal(certificationRequestDER{
		CRI:                asn1.RawValue{FullBytes: cri2},
		SignatureAlgorithm: algorithmIdentifier{Algorithm: MLDSA44.OID()},
		SignatureValue:     asn1.BitString{Bytes: sig2, BitLength: len(sig2) * 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseCertificateRequest(der2); !errorsIs(err, ErrInvalidCSR) {
		t.Errorf("duplicate extensionRequest: want ErrInvalidCSR, got %v", err)
	}
}

func TestCSRCreateRejectsMismatchedSigner(t *testing.T) {
	pub, _, err := GenerateKey(rand.Reader, MLDSA44)
	if err != nil {
		t.Fatal(err)
	}
	_, otherPriv, err := GenerateKey(rand.Reader, MLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	otherSigner, err := otherPriv.Signer()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreateCertificateRequest(rand.Reader, Name{CommonName: "x"}, pub, otherSigner, SANs{}); err == nil {
		t.Error("signer holding a different key must be rejected")
	}
}

func TestCSRCreateEmptySubjectNeedsSANs(t *testing.T) {
	pub, priv, err := GenerateKey(rand.Reader, MLDSA44)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := priv.Signer()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreateCertificateRequest(rand.Reader, Name{}, pub, signer, SANs{}); err == nil {
		t.Error("empty subject with no SANs must be rejected")
	}
	if _, err := CreateCertificateRequest(rand.Reader, Name{}, pub, signer, SANs{DNSNames: []string{"san.example.com"}}); err != nil {
		t.Errorf("empty subject with SANs must be accepted: %v", err)
	}
}

func errorsIs(err error, target error) bool { return errors.Is(err, target) }

func mustReMarshalCRI(t *testing.T, cri certificationRequestInfoDER) []byte {
	t.Helper()
	der, err := asn1.Marshal(cri)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func concatDER(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
