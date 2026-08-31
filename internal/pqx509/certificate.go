package pqx509

import (
	"bytes"
	"crypto/rand"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"time"
)

// Extension is a raw X.509 extension.
type Extension struct {
	ID       asn1.ObjectIdentifier
	Critical bool
	Value    []byte
}

// Certificate is a parsed or to-be-created X.509 certificate with a
// post-quantum signature algorithm.
type Certificate struct {
	Raw               []byte
	RawTBSCertificate []byte

	Version            int
	SerialNumber       *big.Int
	SignatureAlgorithm Algorithm
	Signature          []byte

	Issuer     Name
	RawIssuer  []byte
	Subject    Name
	RawSubject []byte

	NotBefore time.Time
	NotAfter  time.Time

	PublicKey PublicKey

	BasicConstraints      BasicConstraints
	BasicConstraintsValid bool
	KeyUsage              KeyUsage
	ExtKeyUsage           []ExtKeyUsage
	SubjectKeyID          []byte
	AuthorityKeyID        []byte
	SANs                  SANs

	// UnhandledExtensions carries extensions pqtrust does not interpret. On
	// parse only non-critical ones can appear (critical unknowns are errors).
	UnhandledExtensions []Extension
}

// IsSelfSigned reports whether issuer and subject DNs are byte-identical.
func (c *Certificate) IsSelfSigned() bool {
	return len(c.RawIssuer) > 0 && bytes.Equal(c.RawIssuer, c.RawSubject)
}

// GenerateSerialNumber returns a random positive 128-bit serial number.
func GenerateSerialNumber(r io.Reader) (*big.Int, error) {
	if r == nil {
		r = rand.Reader
	}
	limit := new(big.Int).Lsh(big.NewInt(1), 127)
	for i := 0; i < 8; i++ {
		n, err := rand.Int(r, limit)
		if err != nil {
			return nil, fmt.Errorf("pqx509: generating serial number: %w", err)
		}
		if n.Sign() > 0 {
			return n, nil
		}
	}
	return nil, fmt.Errorf("pqx509: could not generate a nonzero serial number")
}

// CreateCertificate builds and signs a certificate. Pass template as parent to
// create a self-signed certificate. pub is the subject public key; signer holds
// the issuer's private key.
func CreateCertificate(r io.Reader, template, parent *Certificate, pub PublicKey, signer Signer) ([]byte, error) {
	if template == nil || parent == nil || signer == nil {
		return nil, fmt.Errorf("pqx509: template, parent and signer are required")
	}
	if template.SerialNumber == nil {
		return nil, fmt.Errorf("pqx509: template.SerialNumber must be set")
	}
	if template.SerialNumber.Sign() <= 0 {
		return nil, fmt.Errorf("pqx509: serial number must be positive")
	}
	if !template.NotAfter.After(template.NotBefore) {
		return nil, fmt.Errorf("pqx509: NotAfter (%v) must be after NotBefore (%v)", template.NotAfter, template.NotBefore)
	}
	if template.SignatureAlgorithm != signer.Algorithm() {
		return nil, fmt.Errorf("pqx509: template signature algorithm %v does not match signer algorithm %v",
			template.SignatureAlgorithm, signer.Algorithm())
	}

	subjectDER := template.RawSubject
	if len(subjectDER) == 0 {
		var err error
		if subjectDER, err = template.Subject.ToRDNSequence(); err != nil {
			return nil, err
		}
	}
	subjectEmpty := bytes.Equal(subjectDER, []byte{0x30, 0x00})
	if subjectEmpty && template.SANs.Empty() {
		return nil, fmt.Errorf("pqx509: a certificate with an empty subject must carry subjectAltName")
	}

	var issuerDER []byte
	if parent == template {
		issuerDER = subjectDER
	} else {
		issuerDER = parent.RawSubject
		if len(issuerDER) == 0 {
			var err error
			if issuerDER, err = parent.Subject.ToRDNSequence(); err != nil {
				return nil, err
			}
		}
	}

	spki, err := MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	var spkiStruct subjectPublicKeyInfo
	if _, err := asn1.Unmarshal(spki, &spkiStruct); err != nil {
		return nil, fmt.Errorf("pqx509: re-reading SPKI: %w", err)
	}

	notBefore, err := marshalTime(template.NotBefore)
	if err != nil {
		return nil, err
	}
	notAfter, err := marshalTime(template.NotAfter)
	if err != nil {
		return nil, err
	}

	exts, err := buildExtensions(template, pub, signer, subjectEmpty)
	if err != nil {
		return nil, err
	}

	tbs := tbsCertificate{
		Version:            2,
		SerialNumber:       template.SerialNumber,
		SignatureAlgorithm: algorithmIdentifier{Algorithm: template.SignatureAlgorithm.OID()},
		Issuer:             asn1.RawValue{FullBytes: issuerDER},
		Validity:           validity{NotBefore: notBefore, NotAfter: notAfter},
		Subject:            asn1.RawValue{FullBytes: subjectDER},
		PublicKey:          spkiStruct,
		Extensions:         exts,
	}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, fmt.Errorf("pqx509: marshaling TBSCertificate: %w", err)
	}

	sig, err := signer.Sign(r, tbsDER)
	if err != nil {
		return nil, fmt.Errorf("pqx509: signing certificate: %w", err)
	}

	certDER, err := asn1.Marshal(certificateDER{
		TBSCertificate:     asn1.RawValue{FullBytes: tbsDER},
		SignatureAlgorithm: algorithmIdentifier{Algorithm: template.SignatureAlgorithm.OID()},
		SignatureValue:     asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	})
	if err != nil {
		return nil, fmt.Errorf("pqx509: marshaling certificate: %w", err)
	}
	return certDER, nil
}

func buildExtensions(template *Certificate, pub PublicKey, signer Signer, subjectEmpty bool) ([]extension, error) {
	var exts []extension

	if template.BasicConstraintsValid {
		v, err := marshalBasicConstraints(template.BasicConstraints)
		if err != nil {
			return nil, err
		}
		exts = append(exts, extension{ID: oidExtBasicConstraints, Critical: true, Value: v})
	}
	if template.KeyUsage != 0 {
		v, err := marshalKeyUsage(template.KeyUsage)
		if err != nil {
			return nil, err
		}
		exts = append(exts, extension{ID: oidExtKeyUsage, Critical: true, Value: v})
	}
	if len(template.ExtKeyUsage) > 0 {
		v, err := marshalExtKeyUsage(template.ExtKeyUsage)
		if err != nil {
			return nil, err
		}
		exts = append(exts, extension{ID: oidExtExtendedKeyUsage, Value: v})
	}

	skid := template.SubjectKeyID
	if len(skid) == 0 {
		var err error
		if skid, err = KeyIdentifier(pub); err != nil {
			return nil, err
		}
	}
	skidDER, err := marshalKeyID(skid)
	if err != nil {
		return nil, err
	}
	exts = append(exts, extension{ID: oidExtSubjectKeyID, Value: skidDER})

	akid := template.AuthorityKeyID
	if len(akid) == 0 {
		if akid, err = KeyIdentifier(signer.Public()); err != nil {
			return nil, err
		}
	}
	akidDER, err := marshalAuthorityKeyID(akid)
	if err != nil {
		return nil, err
	}
	exts = append(exts, extension{ID: oidExtAuthorityKeyID, Value: akidDER})

	if !template.SANs.Empty() {
		v, err := marshalSANs(template.SANs)
		if err != nil {
			return nil, err
		}
		exts = append(exts, extension{ID: oidExtSubjectAltName, Critical: subjectEmpty, Value: v})
	}

	for _, e := range template.UnhandledExtensions {
		exts = append(exts, extension{ID: e.ID, Critical: e.Critical, Value: e.Value}) //nolint:staticcheck // internal ASN.1 type has a distinct struct tag
	}
	return exts, nil
}

// ParseCertificate decodes a DER certificate. Malformed DER, trailing bytes and
// unknown critical extensions are hard errors.
func ParseCertificate(der []byte) (*Certificate, error) {
	var outer certificateDER
	rest, err := asn1.Unmarshal(der, &outer)
	if err != nil {
		return nil, fmt.Errorf("%w: certificate: %w", ErrMalformedDER, err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: %d bytes after certificate", ErrTrailingData, len(rest))
	}

	var tbs tbsCertificate
	if trailing, err := asn1.Unmarshal(outer.TBSCertificate.FullBytes, &tbs); err != nil {
		return nil, fmt.Errorf("%w: TBSCertificate: %w", ErrMalformedDER, err)
	} else if len(trailing) != 0 {
		return nil, fmt.Errorf("%w: after TBSCertificate", ErrTrailingData)
	}

	sigAlg, err := algorithmFromOID(outer.SignatureAlgorithm.Algorithm)
	if err != nil {
		return nil, err
	}
	if len(outer.SignatureAlgorithm.Parameters.FullBytes) != 0 {
		return nil, fmt.Errorf("%w: signature AlgorithmIdentifier must omit parameters", ErrMalformedDER)
	}
	if !tbs.SignatureAlgorithm.Algorithm.Equal(outer.SignatureAlgorithm.Algorithm) {
		return nil, fmt.Errorf("%w: inner and outer signature algorithms differ", ErrMalformedDER)
	}
	if len(tbs.SignatureAlgorithm.Parameters.FullBytes) != 0 {
		return nil, fmt.Errorf("%w: TBSCertificate signature AlgorithmIdentifier must omit parameters", ErrMalformedDER)
	}
	if outer.SignatureValue.BitLength%8 != 0 {
		return nil, fmt.Errorf("%w: signature BIT STRING has unused bits", ErrMalformedDER)
	}
	if len(outer.SignatureValue.Bytes) != sigAlg.SignatureSize() {
		return nil, fmt.Errorf("%w: %s signature is %d bytes, want %d", ErrMalformedDER, sigAlg, len(outer.SignatureValue.Bytes), sigAlg.SignatureSize())
	}
	if tbs.SerialNumber == nil || tbs.SerialNumber.Sign() <= 0 {
		return nil, fmt.Errorf("%w: serial number must be positive", ErrMalformedDER)
	}

	issuer, err := ParseName(tbs.Issuer.FullBytes)
	if err != nil {
		return nil, err
	}
	subject, err := ParseName(tbs.Subject.FullBytes)
	if err != nil {
		return nil, err
	}
	notBefore, err := parseTime(tbs.Validity.NotBefore)
	if err != nil {
		return nil, err
	}
	notAfter, err := parseTime(tbs.Validity.NotAfter)
	if err != nil {
		return nil, err
	}
	pub, err := publicKeyFromSPKI(tbs.PublicKey)
	if err != nil {
		return nil, err
	}

	cert := &Certificate{
		Raw:                bytes.Clone(der),
		RawTBSCertificate:  bytes.Clone(outer.TBSCertificate.FullBytes),
		Version:            tbs.Version + 1,
		SerialNumber:       tbs.SerialNumber,
		SignatureAlgorithm: sigAlg,
		Signature:          bytes.Clone(outer.SignatureValue.Bytes),
		Issuer:             issuer,
		RawIssuer:          bytes.Clone(tbs.Issuer.FullBytes),
		Subject:            subject,
		RawSubject:         bytes.Clone(tbs.Subject.FullBytes),
		NotBefore:          notBefore,
		NotAfter:           notAfter,
		PublicKey:          pub,
	}
	if cert.Version != 3 {
		return nil, fmt.Errorf("%w: certificate version %d, want 3", ErrMalformedDER, cert.Version)
	}

	seen := map[string]bool{}
	for _, e := range tbs.Extensions {
		if seen[e.ID.String()] {
			return nil, fmt.Errorf("%w: duplicate extension %s", ErrMalformedDER, e.ID)
		}
		seen[e.ID.String()] = true

		switch {
		case e.ID.Equal(oidExtBasicConstraints):
			bc, err := parseBasicConstraints(e.Value)
			if err != nil {
				return nil, err
			}
			cert.BasicConstraints, cert.BasicConstraintsValid = bc, true
		case e.ID.Equal(oidExtKeyUsage):
			if cert.KeyUsage, err = parseKeyUsage(e.Value); err != nil {
				return nil, err
			}
		case e.ID.Equal(oidExtExtendedKeyUsage):
			if cert.ExtKeyUsage, err = parseExtKeyUsage(e.Value); err != nil {
				return nil, err
			}
		case e.ID.Equal(oidExtSubjectKeyID):
			if cert.SubjectKeyID, err = parseSubjectKeyID(e.Value); err != nil {
				return nil, err
			}
		case e.ID.Equal(oidExtAuthorityKeyID):
			if cert.AuthorityKeyID, err = parseAuthorityKeyID(e.Value); err != nil {
				return nil, err
			}
		case e.ID.Equal(oidExtSubjectAltName):
			if cert.SANs, err = parseSANs(e.Value); err != nil {
				return nil, err
			}
		default:
			if e.Critical {
				return nil, fmt.Errorf("%w: %s", ErrUnsupportedCriticalExtension, e.ID)
			}
			cert.UnhandledExtensions = append(cert.UnhandledExtensions, Extension{ID: e.ID, Critical: e.Critical, Value: bytes.Clone(e.Value)})
		}
	}
	return cert, nil
}
