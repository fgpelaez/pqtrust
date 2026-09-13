package pqx509

import (
	"bytes"
	"encoding/asn1"
	"fmt"
	"io"
	"net"
)

// oidExtensionRequest is the PKCS#9 extensionRequest attribute (RFC 2985).
var oidExtensionRequest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}

// CertificateRequest is a parsed or to-be-created PKCS#10 certification
// request carrying a post-quantum signature algorithm. Only subjectAltName
// requested via extensionRequest is honored; every other requested extension
// is ignored.
type CertificateRequest struct {
	Raw       []byte // complete CertificationRequest DER
	RawTBSCSR []byte // DER of CertificationRequestInfo (the signed portion)

	Subject            Name
	PublicKey          PublicKey
	SignatureAlgorithm Algorithm
	Signature          []byte

	DNSNames       []string
	IPAddresses    []net.IP
	EmailAddresses []string
}

type csrAttributeDER struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

type certificationRequestInfoDER struct {
	Version    int
	Subject    asn1.RawValue
	PublicKey  subjectPublicKeyInfo
	Attributes []csrAttributeDER `asn1:"tag:0"`
}

type certificationRequestDER struct {
	CRI                asn1.RawValue
	SignatureAlgorithm algorithmIdentifier
	SignatureValue     asn1.BitString
}

// CreateCertificateRequest builds and self-signs a PKCS#10 CSR. signer must be
// the private key matching pub. The signature is pure-mode ML-DSA with an
// empty context, identical to certificate signing.
func CreateCertificateRequest(r io.Reader, subj Name, pub PublicKey, signer Signer, sans SANs) ([]byte, error) {
	if signer == nil {
		return nil, fmt.Errorf("pqx509: signer is required")
	}
	if pub.Algorithm != signer.Algorithm() || !bytes.Equal(pub.Bytes, signer.Public().Bytes) {
		return nil, fmt.Errorf("pqx509: the CSR signer must hold the subject public key")
	}
	subjectDER, err := subj.ToRDNSequence()
	if err != nil {
		return nil, err
	}
	if bytes.Equal(subjectDER, []byte{0x30, 0x00}) && sans.Empty() {
		return nil, fmt.Errorf("pqx509: a CSR with an empty subject must carry subjectAltName")
	}
	spkiDER, err := MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	attrsDER, err := marshalCSRAttributes(sans)
	if err != nil {
		return nil, err
	}
	zero, err := asn1.Marshal(0) // INTEGER v1(0)
	if err != nil {
		return nil, fmt.Errorf("pqx509: marshaling CSR version: %w", err)
	}
	content := append(append(zero, subjectDER...), spkiDER...)
	content = append(content, attrsDER...)
	cri := marshalSequence(content)

	sig, err := signer.Sign(r, cri)
	if err != nil {
		return nil, fmt.Errorf("pqx509: signing CSR: %w", err)
	}
	der, err := asn1.Marshal(certificationRequestDER{
		CRI:                asn1.RawValue{FullBytes: cri},
		SignatureAlgorithm: algorithmIdentifier{Algorithm: pub.Algorithm.OID()},
		SignatureValue:     asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	})
	if err != nil {
		return nil, fmt.Errorf("pqx509: marshaling CSR: %w", err)
	}
	return der, nil
}

// marshalCSRAttributes encodes the [0] IMPLICIT SET OF attributes. With SANs
// present it emits a single extensionRequest attribute carrying a
// subjectAltName extension; without SANs it emits the empty set.
func marshalCSRAttributes(sans SANs) ([]byte, error) {
	var content []byte
	if !sans.Empty() {
		sanDER, err := marshalSANs(sans)
		if err != nil {
			return nil, err
		}
		extsDER, err := asn1.Marshal([]extension{{ID: oidExtSubjectAltName, Value: sanDER}})
		if err != nil {
			return nil, fmt.Errorf("pqx509: marshaling extensionRequest: %w", err)
		}
		attrDER, err := asn1.Marshal(csrAttributeDER{
			Type:   oidExtensionRequest,
			Values: []asn1.RawValue{{FullBytes: extsDER}},
		})
		if err != nil {
			return nil, fmt.Errorf("pqx509: marshaling extensionRequest attribute: %w", err)
		}
		content = attrDER
	}
	out := append([]byte{0xA0}, marshalLength(len(content))...)
	return append(out, content...), nil
}

// ParseCertificateRequest decodes a DER PKCS#10 CSR. Wrong version, present
// signature parameters, signature/SPKI algorithm mismatch, wrong signature
// size, malformed attributes and trailing bytes are hard errors. Attributes
// other than extensionRequest (e.g. challengePassword) are ignored.
func ParseCertificateRequest(der []byte) (*CertificateRequest, error) {
	var outer certificationRequestDER
	rest, err := asn1.Unmarshal(der, &outer)
	if err != nil {
		return nil, fmt.Errorf("%w: CSR: %w", ErrInvalidCSR, err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: %d bytes after CSR", ErrTrailingData, len(rest))
	}
	var cri certificationRequestInfoDER
	if trailing, err := asn1.Unmarshal(outer.CRI.FullBytes, &cri); err != nil {
		return nil, fmt.Errorf("%w: CertificationRequestInfo: %w", ErrInvalidCSR, err)
	} else if len(trailing) != 0 {
		return nil, fmt.Errorf("%w: after CertificationRequestInfo", ErrTrailingData)
	}
	if cri.Version != 0 {
		return nil, fmt.Errorf("%w: CSR version %d, want 0", ErrInvalidCSR, cri.Version)
	}
	subject, err := ParseName(cri.Subject.FullBytes)
	if err != nil {
		return nil, err
	}
	pub, err := publicKeyFromSPKI(cri.PublicKey)
	if err != nil {
		return nil, err
	}
	sigAlg, err := algorithmFromOID(outer.SignatureAlgorithm.Algorithm)
	if err != nil {
		return nil, err
	}
	if len(outer.SignatureAlgorithm.Parameters.FullBytes) != 0 {
		return nil, fmt.Errorf("%w: CSR signature AlgorithmIdentifier must omit parameters", ErrInvalidCSR)
	}
	if sigAlg != pub.Algorithm {
		return nil, fmt.Errorf("%w: signature algorithm %v does not match the subject public key algorithm %v",
			ErrInvalidCSR, sigAlg, pub.Algorithm)
	}
	if outer.SignatureValue.BitLength%8 != 0 {
		return nil, fmt.Errorf("%w: CSR signature BIT STRING has unused bits", ErrInvalidCSR)
	}
	if len(outer.SignatureValue.Bytes) != sigAlg.SignatureSize() {
		return nil, fmt.Errorf("%w: %s signature is %d bytes, want %d",
			ErrInvalidCSR, sigAlg, len(outer.SignatureValue.Bytes), sigAlg.SignatureSize())
	}
	sans, err := sansFromCSRAttributes(cri.Attributes)
	if err != nil {
		return nil, err
	}
	return &CertificateRequest{
		Raw:                bytes.Clone(der),
		RawTBSCSR:          bytes.Clone(outer.CRI.FullBytes),
		Subject:            subject,
		PublicKey:          pub,
		SignatureAlgorithm: sigAlg,
		Signature:          bytes.Clone(outer.SignatureValue.Bytes),
		DNSNames:           sans.DNSNames,
		IPAddresses:        sans.IPAddresses,
		EmailAddresses:     sans.EmailAddresses,
	}, nil
}

// sansFromCSRAttributes extracts subjectAltName from extensionRequest.
// Multiple extensionRequest attributes are ambiguous and rejected; duplicate
// SAN extensions inside one attribute are rejected; every other requested
// extension is ignored.
func sansFromCSRAttributes(attrs []csrAttributeDER) (SANs, error) {
	var sans SANs
	seenExtReq := false
	for _, a := range attrs {
		if !a.Type.Equal(oidExtensionRequest) {
			continue
		}
		if seenExtReq {
			return SANs{}, fmt.Errorf("%w: multiple extensionRequest attributes", ErrInvalidCSR)
		}
		seenExtReq = true
		if len(a.Values) != 1 {
			return SANs{}, fmt.Errorf("%w: extensionRequest must carry exactly one value, got %d", ErrInvalidCSR, len(a.Values))
		}
		var exts []extension
		rest, err := asn1.Unmarshal(a.Values[0].FullBytes, &exts)
		if err != nil {
			return SANs{}, fmt.Errorf("%w: extensionRequest: %w", ErrInvalidCSR, err)
		}
		if len(rest) != 0 {
			return SANs{}, fmt.Errorf("%w: after extensionRequest", ErrTrailingData)
		}
		seenSANs := false
		for _, e := range exts {
			if !e.ID.Equal(oidExtSubjectAltName) {
				continue
			}
			if seenSANs {
				return SANs{}, fmt.Errorf("%w: duplicate subjectAltName in extensionRequest", ErrInvalidCSR)
			}
			seenSANs = true
			s, err := parseSANs(e.Value)
			if err != nil {
				return SANs{}, err
			}
			sans = s
		}
	}
	return sans, nil
}

// CheckSignature verifies the CSR's pure-mode self-signature over RawTBSCSR.
func (csr *CertificateRequest) CheckSignature() error {
	if err := Verify(csr.PublicKey, csr.RawTBSCSR, csr.Signature); err != nil {
		return fmt.Errorf("%w: %w", ErrCSRSignature, err)
	}
	return nil
}
