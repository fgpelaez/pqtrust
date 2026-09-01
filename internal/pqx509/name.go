package pqx509

import (
	"encoding/asn1"
	"fmt"
	"strings"
)

var (
	oidCountry            = asn1.ObjectIdentifier{2, 5, 4, 6}
	oidOrganization       = asn1.ObjectIdentifier{2, 5, 4, 10}
	oidOrganizationalUnit = asn1.ObjectIdentifier{2, 5, 4, 11}
	oidCommonName         = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidLocality           = asn1.ObjectIdentifier{2, 5, 4, 7}
	oidProvince           = asn1.ObjectIdentifier{2, 5, 4, 8}
)

// Name is the subset of X.501 Name attributes pqtrust supports.
type Name struct {
	Country            []string
	Organization       []string
	OrganizationalUnit []string
	Locality           []string
	Province           []string
	CommonName         string
}

type attributeTypeAndValue struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue
}

// ToRDNSequence encodes n as a DER RDNSequence. Attribute order is
// C, ST, L, O, OU, CN — most general to most specific, as X.500 expects.
//
// RDNSequence = SEQUENCE OF RelativeDistinguishedName
// RelativeDistinguishedName = SET SIZE (1..MAX) OF AttributeTypeAndValue
// AttributeTypeAndValue = SEQUENCE { type OID, value DirectoryString }
func (n Name) ToRDNSequence() ([]byte, error) {
	var rdnSequence []byte
	add := func(oid asn1.ObjectIdentifier, values []string) error {
		for _, v := range values {
			rv, err := marshalDirectoryString(v)
			if err != nil {
				return err
			}
			atvDER, err := asn1.Marshal(attributeTypeAndValue{Type: oid, Value: rv})
			if err != nil {
				return fmt.Errorf("pqx509: marshaling attributeTypeAndValue: %w", err)
			}
			rdnSequence = append(rdnSequence, marshalSet(atvDER)...)
		}
		return nil
	}
	for _, part := range []struct {
		oid    asn1.ObjectIdentifier
		values []string
	}{
		{oidCountry, n.Country},
		{oidProvince, n.Province},
		{oidLocality, n.Locality},
		{oidOrganization, n.Organization},
		{oidOrganizationalUnit, n.OrganizationalUnit},
	} {
		if err := add(part.oid, part.values); err != nil {
			return nil, err
		}
	}
	if n.CommonName != "" {
		if err := add(oidCommonName, []string{n.CommonName}); err != nil {
			return nil, err
		}
	}
	return marshalSequence(rdnSequence), nil
}

// marshalSet wraps content in a DER SET tag (0x31).
func marshalSet(content []byte) []byte {
	return append([]byte{0x31}, append(marshalLength(len(content)), content...)...)
}

// marshalSequence wraps content in a DER SEQUENCE tag (0x30).
func marshalSequence(content []byte) []byte {
	return append([]byte{0x30}, append(marshalLength(len(content)), content...)...)
}

// marshalLength encodes a DER length field.
func marshalLength(l int) []byte {
	if l < 0x80 {
		return []byte{byte(l)}
	}
	// Long form: first byte = 0x80 | number of length bytes
	var buf []byte
	for v := l; v > 0; v >>= 8 {
		buf = append([]byte{byte(v)}, buf...)
	}
	return append([]byte{byte(0x80 | len(buf))}, buf...)
}

func marshalDirectoryString(s string) (asn1.RawValue, error) {
	// PrintableString when possible (widest interoperability), else UTF8String.
	params := "utf8"
	if isPrintableString(s) {
		params = "printable"
	}
	der, err := asn1.MarshalWithParams(s, params)
	if err != nil {
		return asn1.RawValue{}, fmt.Errorf("pqx509: marshaling %q: %w", s, err)
	}
	var rv asn1.RawValue
	if _, err := asn1.Unmarshal(der, &rv); err != nil {
		return asn1.RawValue{}, fmt.Errorf("pqx509: re-reading marshaled string: %w", err)
	}
	return rv, nil
}

func isPrintableString(s string) bool {
	const extra = " '()+,-./:=?"
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune(extra, r):
		default:
			return false
		}
	}
	return true
}

// ParseName decodes a DER RDNSequence, keeping the attribute types pqtrust supports.
// The encoding is SEQUENCE OF (SET OF (SEQUENCE { OID, DirectoryString })).
func ParseName(der []byte) (Name, error) {
	// Expect outer SEQUENCE (RDNSequence)
	inner, rest, err := parseSequence(der)
	if err != nil {
		return Name{}, fmt.Errorf("%w: name: %w", ErrMalformedDER, err)
	}
	if len(rest) != 0 {
		return Name{}, fmt.Errorf("%w: %d bytes after name", ErrTrailingData, len(rest))
	}
	var n Name
	for len(inner) > 0 {
		// Each RDN is a SET
		setContent, r, err := parseSet(inner)
		if err != nil {
			return Name{}, fmt.Errorf("%w: name RDN: %w", ErrMalformedDER, err)
		}
		inner = r
		// Each SET contains one AttributeTypeAndValue (SEQUENCE)
		atvBytes, s, err := parseSequence(setContent)
		if err != nil {
			return Name{}, fmt.Errorf("%w: name AttributeTypeAndValue: %w", ErrMalformedDER, err)
		}
		if len(s) != 0 {
			return Name{}, fmt.Errorf("%w: trailing data in RDN SET", ErrMalformedDER)
		}
		var atvOID asn1.ObjectIdentifier
		rest2, err := asn1.Unmarshal(atvBytes, &atvOID)
		if err != nil {
			return Name{}, fmt.Errorf("%w: name OID: %w", ErrMalformedDER, err)
		}
		var atvValue asn1.RawValue
		if _, err := asn1.Unmarshal(rest2, &atvValue); err != nil {
			return Name{}, fmt.Errorf("%w: name value: %w", ErrMalformedDER, err)
		}
		dirStr, err := parseDirectoryString(atvValue)
		if err != nil {
			return Name{}, err
		}
		switch {
		case atvOID.Equal(oidCountry):
			n.Country = append(n.Country, dirStr)
		case atvOID.Equal(oidProvince):
			n.Province = append(n.Province, dirStr)
		case atvOID.Equal(oidLocality):
			n.Locality = append(n.Locality, dirStr)
		case atvOID.Equal(oidOrganization):
			n.Organization = append(n.Organization, dirStr)
		case atvOID.Equal(oidOrganizationalUnit):
			n.OrganizationalUnit = append(n.OrganizationalUnit, dirStr)
		case atvOID.Equal(oidCommonName):
			n.CommonName = dirStr
		}
	}
	return n, nil
}

// parseSet extracts a SET tag and returns (content, rest).
func parseSet(data []byte) ([]byte, []byte, error) {
	if len(data) < 2 || data[0] != 0x31 {
		return nil, nil, fmt.Errorf("expected SET tag 0x31")
	}
	l, rest, err := parseDERLength(data[1:])
	if err != nil {
		return nil, nil, err
	}
	if len(rest) < l {
		return nil, nil, fmt.Errorf("short read in SET: need %d, have %d", l, len(rest))
	}
	return rest[:l], rest[l:], nil
}

// parseSequence extracts a SEQUENCE tag and returns (content, rest).
func parseSequence(data []byte) ([]byte, []byte, error) {
	if len(data) < 2 || data[0] != 0x30 {
		return nil, nil, fmt.Errorf("expected SEQUENCE tag 0x30")
	}
	l, rest, err := parseDERLength(data[1:])
	if err != nil {
		return nil, nil, err
	}
	if len(rest) < l {
		return nil, nil, fmt.Errorf("short read in SEQUENCE: need %d, have %d", l, len(rest))
	}
	return rest[:l], rest[l:], nil
}

// parseDERLength reads a DER length field and returns (length, rest, error).
func parseDERLength(data []byte) (int, []byte, error) {
	if len(data) == 0 {
		return 0, nil, fmt.Errorf("unexpected end of data in length")
	}
	if data[0]&0x80 == 0 {
		return int(data[0]), data[1:], nil
	}
	numBytes := int(data[0] & 0x7f)
	if numBytes == 0 {
		return 0, nil, fmt.Errorf("indefinite length not allowed in DER")
	}
	if len(data) < 1+numBytes {
		return 0, nil, fmt.Errorf("short read in length bytes")
	}
	l := 0
	for i := 1; i <= numBytes; i++ {
		l = l<<8 | int(data[i])
	}
	return l, data[1+numBytes:], nil
}

func parseDirectoryString(rv asn1.RawValue) (string, error) {
	switch rv.Tag {
	case asn1.TagPrintableString, asn1.TagUTF8String, asn1.TagIA5String, asn1.TagT61String:
		return string(rv.Bytes), nil
	default:
		return "", fmt.Errorf("%w: unsupported directory string tag %d", ErrMalformedDER, rv.Tag)
	}
}

// String renders n as a comma-separated RFC 4514-style DN, most specific first.
func (n Name) String() string {
	var parts []string
	if n.CommonName != "" {
		parts = append(parts, "CN="+n.CommonName)
	}
	for _, v := range n.OrganizationalUnit {
		parts = append(parts, "OU="+v)
	}
	for _, v := range n.Organization {
		parts = append(parts, "O="+v)
	}
	for _, v := range n.Locality {
		parts = append(parts, "L="+v)
	}
	for _, v := range n.Province {
		parts = append(parts, "ST="+v)
	}
	for _, v := range n.Country {
		parts = append(parts, "C="+v)
	}
	return strings.Join(parts, ",")
}

// ParseNameString parses the form String produces. Unknown attribute types are
// a hard error so that a typo in an API request never silently drops a field.
func ParseNameString(s string) (Name, error) {
	var n Name
	if strings.TrimSpace(s) == "" {
		return n, fmt.Errorf("pqx509: empty distinguished name")
	}
	for _, part := range strings.Split(s, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || key == "" || value == "" {
			return Name{}, fmt.Errorf("pqx509: malformed DN component %q", part)
		}
		switch strings.ToUpper(key) {
		case "CN":
			n.CommonName = value
		case "OU":
			n.OrganizationalUnit = append(n.OrganizationalUnit, value)
		case "O":
			n.Organization = append(n.Organization, value)
		case "L":
			n.Locality = append(n.Locality, value)
		case "ST":
			n.Province = append(n.Province, value)
		case "C":
			n.Country = append(n.Country, value)
		default:
			return Name{}, fmt.Errorf("pqx509: unsupported DN attribute %q", key)
		}
	}
	return n, nil
}
