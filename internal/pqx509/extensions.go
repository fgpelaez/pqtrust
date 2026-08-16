package pqx509

import (
	"encoding/asn1"
	"fmt"
	"math/big"
	"net"
)

var (
	oidExtSubjectKeyID     = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidExtKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtSubjectAltName   = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidExtBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidExtCRLNumber        = asn1.ObjectIdentifier{2, 5, 29, 20}
	oidExtCRLReason        = asn1.ObjectIdentifier{2, 5, 29, 21}
	oidExtAuthorityKeyID   = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidExtExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
)

func isSupportedExtension(oid asn1.ObjectIdentifier) bool {
	for _, known := range []asn1.ObjectIdentifier{
		oidExtSubjectKeyID, oidExtKeyUsage, oidExtSubjectAltName,
		oidExtBasicConstraints, oidExtCRLNumber, oidExtCRLReason,
		oidExtAuthorityKeyID, oidExtExtendedKeyUsage,
	} {
		if known.Equal(oid) {
			return true
		}
	}
	return false
}

// KeyUsage is a bitmask of RFC 5280 key usages. Only the usages pqtrust issues
// are named; parsing preserves every bit so that round-trips are lossless.
type KeyUsage uint16

// Supported key usages, positioned by their RFC 5280 bit numbers.
const (
	KeyUsageDigitalSignature KeyUsage = 1 << 0
	KeyUsageKeyCertSign      KeyUsage = 1 << 5
	KeyUsageCRLSign          KeyUsage = 1 << 6
)

var keyUsageNames = []struct {
	ku   KeyUsage
	name string
}{
	{KeyUsageDigitalSignature, "digitalSignature"},
	{KeyUsageKeyCertSign, "keyCertSign"},
	{KeyUsageCRLSign, "cRLSign"},
}

// Strings renders ku as canonical RFC 5280 names, in bit order.
func (ku KeyUsage) Strings() []string {
	var out []string
	for _, e := range keyUsageNames {
		if ku&e.ku != 0 {
			out = append(out, e.name)
		}
	}
	return out
}

// ParseKeyUsages resolves canonical names, rejecting anything pqtrust cannot issue.
func ParseKeyUsages(names []string) (KeyUsage, error) {
	var ku KeyUsage
	for _, n := range names {
		found := false
		for _, e := range keyUsageNames {
			if e.name == n {
				ku |= e.ku
				found = true
				break
			}
		}
		if !found {
			return 0, fmt.Errorf("pqx509: unsupported key usage %q", n)
		}
	}
	return ku, nil
}

// bit number in the DER BIT STRING for KeyUsage bit i of our mask
func marshalKeyUsage(ku KeyUsage) ([]byte, error) {
	// Build the BIT STRING with the minimum number of octets and strip
	// trailing zero bits, as DER requires for named bit lists.
	var bytesOut [2]byte
	highest := -1
	for bit := 0; bit < 16; bit++ {
		if ku&(1<<uint(bit)) != 0 {
			bytesOut[bit/8] |= 0x80 >> uint(bit%8)
			highest = bit
		}
	}
	if highest < 0 {
		return nil, fmt.Errorf("pqx509: key usage must not be empty")
	}
	n := highest/8 + 1
	bs := asn1.BitString{Bytes: bytesOut[:n], BitLength: highest + 1}
	der, err := asn1.Marshal(bs)
	if err != nil {
		return nil, fmt.Errorf("pqx509: marshaling key usage: %w", err)
	}
	return der, nil
}

func parseKeyUsage(der []byte) (KeyUsage, error) {
	var bs asn1.BitString
	rest, err := asn1.Unmarshal(der, &bs)
	if err != nil {
		return 0, fmt.Errorf("%w: key usage: %w", ErrMalformedDER, err)
	}
	if len(rest) != 0 {
		return 0, fmt.Errorf("%w: after key usage", ErrTrailingData)
	}
	var ku KeyUsage
	for bit := 0; bit < 16 && bit < bs.BitLength; bit++ {
		if bs.At(bit) == 1 {
			ku |= 1 << uint(bit)
		}
	}
	return ku, nil
}

// ExtKeyUsage is a supported extended key usage.
type ExtKeyUsage int

// Supported extended key usages.
const (
	ExtKeyUsageServerAuth ExtKeyUsage = iota + 1
	ExtKeyUsageClientAuth
)

var extKeyUsages = []struct {
	eku  ExtKeyUsage
	name string
	oid  asn1.ObjectIdentifier
}{
	{ExtKeyUsageServerAuth, "serverAuth", asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}},
	{ExtKeyUsageClientAuth, "clientAuth", asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}},
}

// String returns the canonical name, e.g. "serverAuth".
func (e ExtKeyUsage) String() string {
	for _, x := range extKeyUsages {
		if x.eku == e {
			return x.name
		}
	}
	return fmt.Sprintf("ExtKeyUsage(%d)", int(e))
}

// ParseExtKeyUsages resolves canonical EKU names.
func ParseExtKeyUsages(names []string) ([]ExtKeyUsage, error) {
	var out []ExtKeyUsage
	for _, n := range names {
		found := false
		for _, x := range extKeyUsages {
			if x.name == n {
				out = append(out, x.eku)
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("pqx509: unsupported extended key usage %q", n)
		}
	}
	return out, nil
}

func marshalExtKeyUsage(ekus []ExtKeyUsage) ([]byte, error) {
	oids := make([]asn1.ObjectIdentifier, 0, len(ekus))
	for _, e := range ekus {
		found := false
		for _, x := range extKeyUsages {
			if x.eku == e {
				oids = append(oids, x.oid)
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("pqx509: unsupported extended key usage %v", e)
		}
	}
	der, err := asn1.Marshal(oids)
	if err != nil {
		return nil, fmt.Errorf("pqx509: marshaling extended key usage: %w", err)
	}
	return der, nil
}

func parseExtKeyUsage(der []byte) ([]ExtKeyUsage, error) {
	var oids []asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(der, &oids)
	if err != nil {
		return nil, fmt.Errorf("%w: extended key usage: %w", ErrMalformedDER, err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: after extended key usage", ErrTrailingData)
	}
	var out []ExtKeyUsage
	for _, oid := range oids {
		for _, x := range extKeyUsages {
			if x.oid.Equal(oid) {
				out = append(out, x.eku)
			}
		}
	}
	return out, nil
}

// BasicConstraints is the RFC 5280 basicConstraints extension.
type BasicConstraints struct {
	IsCA          bool
	MaxPathLen    int
	MaxPathLenSet bool
}

type basicConstraintsDER struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

func marshalBasicConstraints(bc BasicConstraints) ([]byte, error) {
	v := basicConstraintsDER{IsCA: bc.IsCA, MaxPathLen: -1}
	if bc.IsCA && bc.MaxPathLenSet {
		if bc.MaxPathLen < 0 {
			return nil, fmt.Errorf("pqx509: negative pathLenConstraint %d", bc.MaxPathLen)
		}
		v.MaxPathLen = bc.MaxPathLen
	}
	der, err := asn1.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("pqx509: marshaling basic constraints: %w", err)
	}
	return der, nil
}

func parseBasicConstraints(der []byte) (BasicConstraints, error) {
	v := basicConstraintsDER{MaxPathLen: -1}
	rest, err := asn1.Unmarshal(der, &v)
	if err != nil {
		return BasicConstraints{}, fmt.Errorf("%w: basic constraints: %w", ErrMalformedDER, err)
	}
	if len(rest) != 0 {
		return BasicConstraints{}, fmt.Errorf("%w: after basic constraints", ErrTrailingData)
	}
	bc := BasicConstraints{IsCA: v.IsCA}
	if v.MaxPathLen >= 0 {
		if !v.IsCA {
			return BasicConstraints{}, fmt.Errorf("%w: pathLenConstraint present on a non-CA certificate", ErrMalformedDER)
		}
		bc.MaxPathLen, bc.MaxPathLenSet = v.MaxPathLen, true
	}
	return bc, nil
}

func marshalKeyID(id []byte) ([]byte, error) {
	der, err := asn1.Marshal(id)
	if err != nil {
		return nil, fmt.Errorf("pqx509: marshaling key identifier: %w", err)
	}
	return der, nil
}

func parseSubjectKeyID(der []byte) ([]byte, error) {
	var id []byte
	rest, err := asn1.Unmarshal(der, &id)
	if err != nil {
		return nil, fmt.Errorf("%w: subject key identifier: %w", ErrMalformedDER, err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: after subject key identifier", ErrTrailingData)
	}
	return id, nil
}

type authorityKeyIDDER struct {
	KeyIdentifier []byte `asn1:"optional,tag:0"`
}

func marshalAuthorityKeyID(id []byte) ([]byte, error) {
	der, err := asn1.Marshal(authorityKeyIDDER{KeyIdentifier: id})
	if err != nil {
		return nil, fmt.Errorf("pqx509: marshaling authority key identifier: %w", err)
	}
	return der, nil
}

func parseAuthorityKeyID(der []byte) ([]byte, error) {
	var v authorityKeyIDDER
	rest, err := asn1.Unmarshal(der, &v)
	if err != nil {
		return nil, fmt.Errorf("%w: authority key identifier: %w", ErrMalformedDER, err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: after authority key identifier", ErrTrailingData)
	}
	return v.KeyIdentifier, nil
}

// SANs is the subset of GeneralName types pqtrust supports.
type SANs struct {
	DNSNames       []string
	EmailAddresses []string
	IPAddresses    []net.IP
}

// GeneralName context tags (RFC 5280 4.2.1.6).
const (
	sanTagEmail = 1
	sanTagDNS   = 2
	sanTagIP    = 7
)

// Empty reports whether s carries no names.
func (s SANs) Empty() bool {
	return len(s.DNSNames) == 0 && len(s.EmailAddresses) == 0 && len(s.IPAddresses) == 0
}

func marshalSANs(s SANs) ([]byte, error) {
	var names []asn1.RawValue
	for _, v := range s.DNSNames {
		names = append(names, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: sanTagDNS, Bytes: []byte(v)})
	}
	for _, v := range s.EmailAddresses {
		names = append(names, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: sanTagEmail, Bytes: []byte(v)})
	}
	for _, ip := range s.IPAddresses {
		b := ip
		if v4 := ip.To4(); v4 != nil {
			b = v4
		}
		names = append(names, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: sanTagIP, Bytes: b})
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("pqx509: subjectAltName must not be empty")
	}
	der, err := asn1.Marshal(names)
	if err != nil {
		return nil, fmt.Errorf("pqx509: marshaling subject alternative names: %w", err)
	}
	return der, nil
}

func parseSANs(der []byte) (SANs, error) {
	var names []asn1.RawValue
	rest, err := asn1.Unmarshal(der, &names)
	if err != nil {
		return SANs{}, fmt.Errorf("%w: subject alternative names: %w", ErrMalformedDER, err)
	}
	if len(rest) != 0 {
		return SANs{}, fmt.Errorf("%w: after subject alternative names", ErrTrailingData)
	}
	var s SANs
	for _, n := range names {
		switch n.Tag {
		case sanTagDNS:
			s.DNSNames = append(s.DNSNames, string(n.Bytes))
		case sanTagEmail:
			s.EmailAddresses = append(s.EmailAddresses, string(n.Bytes))
		case sanTagIP:
			if l := len(n.Bytes); l != 4 && l != 16 {
				return SANs{}, fmt.Errorf("%w: IP address SAN is %d bytes", ErrMalformedDER, l)
			}
			s.IPAddresses = append(s.IPAddresses, net.IP(n.Bytes))
		default:
			return SANs{}, fmt.Errorf("%w: unsupported GeneralName tag %d", ErrMalformedDER, n.Tag)
		}
	}
	return s, nil
}

func marshalCRLReason(reason int) ([]byte, error) {
	der, err := asn1.Marshal(asn1.Enumerated(reason))
	if err != nil {
		return nil, fmt.Errorf("pqx509: marshaling CRL reason: %w", err)
	}
	return der, nil
}

func parseCRLReason(der []byte) (int, error) {
	var e asn1.Enumerated
	rest, err := asn1.Unmarshal(der, &e)
	if err != nil {
		return 0, fmt.Errorf("%w: CRL reason: %w", ErrMalformedDER, err)
	}
	if len(rest) != 0 {
		return 0, fmt.Errorf("%w: after CRL reason", ErrTrailingData)
	}
	return int(e), nil
}

func marshalCRLNumber(n *big.Int) ([]byte, error) {
	der, err := asn1.Marshal(n)
	if err != nil {
		return nil, fmt.Errorf("pqx509: marshaling CRL number: %w", err)
	}
	return der, nil
}
