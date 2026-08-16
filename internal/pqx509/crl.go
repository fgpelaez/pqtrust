package pqx509

import (
	"bytes"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"time"
)

// RevocationEntry is one revoked certificate on a CRL.
type RevocationEntry struct {
	SerialNumber   *big.Int
	RevocationTime time.Time
	// ReasonCode is an RFC 5280 5.3.1 CRLReason. Zero (unspecified) omits the extension.
	ReasonCode int
}

// RevocationList is a parsed or newly built RFC 5280 section 5 CRL.
type RevocationList struct {
	Raw    []byte
	RawTBS []byte

	Issuer             Name
	RawIssuer          []byte
	SignatureAlgorithm Algorithm
	Signature          []byte

	ThisUpdate time.Time
	NextUpdate time.Time

	Number         *big.Int
	AuthorityKeyID []byte
	Entries        []RevocationEntry
}

// CreateRevocationList builds and signs a v2 CRL for issuer.
func CreateRevocationList(r io.Reader, issuer *Certificate, signer Signer, number *big.Int, entries []RevocationEntry, thisUpdate, nextUpdate time.Time) ([]byte, error) {
	if issuer == nil || signer == nil {
		return nil, fmt.Errorf("pqx509: issuer and signer are required")
	}
	if number == nil || number.Sign() < 0 {
		return nil, fmt.Errorf("pqx509: CRL number must be a non-negative integer")
	}
	if !nextUpdate.After(thisUpdate) {
		return nil, fmt.Errorf("pqx509: nextUpdate (%v) must be after thisUpdate (%v)", nextUpdate, thisUpdate)
	}
	if issuer.KeyUsage != 0 && issuer.KeyUsage&KeyUsageCRLSign == 0 {
		return nil, fmt.Errorf("%w: %q lacks cRLSign", ErrKeyUsageNotPermitted, issuer.Subject)
	}
	if signer.Algorithm() != issuer.PublicKey.Algorithm {
		return nil, fmt.Errorf("pqx509: signer algorithm %v does not match the issuer key algorithm %v",
			signer.Algorithm(), issuer.PublicKey.Algorithm)
	}

	thisDER, err := marshalTime(thisUpdate)
	if err != nil {
		return nil, err
	}
	nextDER, err := marshalTime(nextUpdate)
	if err != nil {
		return nil, err
	}

	var revoked []revokedCertificateDER
	for _, e := range entries {
		if e.SerialNumber == nil || e.SerialNumber.Sign() <= 0 {
			return nil, fmt.Errorf("pqx509: revocation entry serial number must be positive")
		}
		when, err := marshalTime(e.RevocationTime)
		if err != nil {
			return nil, err
		}
		entry := revokedCertificateDER{SerialNumber: e.SerialNumber, RevocationDate: when}
		if e.ReasonCode != 0 {
			v, err := marshalCRLReason(e.ReasonCode)
			if err != nil {
				return nil, err
			}
			entry.Extensions = []extension{{ID: oidExtCRLReason, Value: v}}
		}
		revoked = append(revoked, entry)
	}

	akid, err := KeyIdentifier(issuer.PublicKey)
	if err != nil {
		return nil, err
	}
	akidDER, err := marshalAuthorityKeyID(akid)
	if err != nil {
		return nil, err
	}
	numberDER, err := marshalCRLNumber(number)
	if err != nil {
		return nil, err
	}

	issuerDER := issuer.RawSubject
	if len(issuerDER) == 0 {
		if issuerDER, err = issuer.Subject.ToRDNSequence(); err != nil {
			return nil, err
		}
	}

	tbs := tbsCertList{
		Version:            1, // v2
		SignatureAlgorithm: algorithmIdentifier{Algorithm: signer.Algorithm().OID()},
		Issuer:             asn1.RawValue{FullBytes: issuerDER},
		ThisUpdate:         thisDER,
		NextUpdate:         nextDER,
		RevokedCertificates: revoked,
		Extensions: []extension{
			{ID: oidExtAuthorityKeyID, Value: akidDER},
			{ID: oidExtCRLNumber, Value: numberDER},
		},
	}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, fmt.Errorf("pqx509: marshaling TBSCertList: %w", err)
	}
	sig, err := signer.Sign(r, tbsDER)
	if err != nil {
		return nil, fmt.Errorf("pqx509: signing CRL: %w", err)
	}
	der, err := asn1.Marshal(certificateListDER{
		TBSCertList:        asn1.RawValue{FullBytes: tbsDER},
		SignatureAlgorithm: algorithmIdentifier{Algorithm: signer.Algorithm().OID()},
		SignatureValue:     asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	})
	if err != nil {
		return nil, fmt.Errorf("pqx509: marshaling CRL: %w", err)
	}
	return der, nil
}

// ParseRevocationList decodes a DER CRL.
func ParseRevocationList(der []byte) (*RevocationList, error) {
	var outer certificateListDER
	rest, err := asn1.Unmarshal(der, &outer)
	if err != nil {
		return nil, fmt.Errorf("%w: CRL: %w", ErrMalformedDER, err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: %d bytes after CRL", ErrTrailingData, len(rest))
	}
	var tbs tbsCertList
	if trailing, err := asn1.Unmarshal(outer.TBSCertList.FullBytes, &tbs); err != nil {
		return nil, fmt.Errorf("%w: TBSCertList: %w", ErrMalformedDER, err)
	} else if len(trailing) != 0 {
		return nil, fmt.Errorf("%w: after TBSCertList", ErrTrailingData)
	}

	alg, err := algorithmFromOID(outer.SignatureAlgorithm.Algorithm)
	if err != nil {
		return nil, err
	}
	if len(outer.SignatureAlgorithm.Parameters.FullBytes) != 0 {
		return nil, fmt.Errorf("%w: CRL signature AlgorithmIdentifier must omit parameters", ErrMalformedDER)
	}
	issuer, err := ParseName(tbs.Issuer.FullBytes)
	if err != nil {
		return nil, err
	}
	thisUpdate, err := parseTime(tbs.ThisUpdate)
	if err != nil {
		return nil, err
	}
	l := &RevocationList{
		Raw:                bytes.Clone(der),
		RawTBS:             bytes.Clone(outer.TBSCertList.FullBytes),
		Issuer:             issuer,
		RawIssuer:          bytes.Clone(tbs.Issuer.FullBytes),
		SignatureAlgorithm: alg,
		Signature:          bytes.Clone(outer.SignatureValue.Bytes),
		ThisUpdate:         thisUpdate,
	}
	if len(tbs.NextUpdate.FullBytes) > 0 {
		if l.NextUpdate, err = parseTime(tbs.NextUpdate); err != nil {
			return nil, err
		}
	}
	for _, e := range tbs.Extensions {
		switch {
		case e.ID.Equal(oidExtAuthorityKeyID):
			if l.AuthorityKeyID, err = parseAuthorityKeyID(e.Value); err != nil {
				return nil, err
			}
		case e.ID.Equal(oidExtCRLNumber):
			var n *big.Int
			if trailing, err := asn1.Unmarshal(e.Value, &n); err != nil {
				return nil, fmt.Errorf("%w: CRL number: %w", ErrMalformedDER, err)
			} else if len(trailing) != 0 {
				return nil, fmt.Errorf("%w: after CRL number", ErrTrailingData)
			}
			l.Number = n
		default:
			if e.Critical {
				return nil, fmt.Errorf("%w: CRL extension %s", ErrUnsupportedCriticalExtension, e.ID)
			}
		}
	}
	for _, rc := range tbs.RevokedCertificates {
		when, err := parseTime(rc.RevocationDate)
		if err != nil {
			return nil, err
		}
		entry := RevocationEntry{SerialNumber: rc.SerialNumber, RevocationTime: when}
		for _, e := range rc.Extensions {
			switch {
			case e.ID.Equal(oidExtCRLReason):
				if entry.ReasonCode, err = parseCRLReason(e.Value); err != nil {
					return nil, err
				}
			default:
				if e.Critical {
					return nil, fmt.Errorf("%w: CRL entry extension %s", ErrUnsupportedCriticalExtension, e.ID)
				}
			}
		}
		l.Entries = append(l.Entries, entry)
	}
	return l, nil
}

// VerifySignatureFrom checks the CRL signature against issuer's public key.
func (l *RevocationList) VerifySignatureFrom(issuer *Certificate) error {
	if issuer == nil {
		return fmt.Errorf("pqx509: issuer is required")
	}
	if !bytes.Equal(l.RawIssuer, issuer.RawSubject) {
		return fmt.Errorf("%w: CRL issuer does not match certificate subject", ErrUnknownAuthority)
	}
	if l.SignatureAlgorithm != issuer.PublicKey.Algorithm {
		return fmt.Errorf("%w: CRL is signed with %v but the issuer key is %v",
			ErrBadSignature, l.SignatureAlgorithm, issuer.PublicKey.Algorithm)
	}
	return Verify(issuer.PublicKey, l.RawTBS, l.Signature)
}

// IsRevoked reports whether serial appears on the CRL.
func (l *RevocationList) IsRevoked(serial *big.Int) (RevocationEntry, bool) {
	for _, e := range l.Entries {
		if e.SerialNumber != nil && serial != nil && e.SerialNumber.Cmp(serial) == 0 {
			return e, true
		}
	}
	return RevocationEntry{}, false
}
