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
func (n Name) ToRDNSequence() ([]byte, error) {
	var rdns []([]attributeTypeAndValue)
	add := func(oid asn1.ObjectIdentifier, values []string) error {
		for _, v := range values {
			rv, err := marshalDirectoryString(v)
			if err != nil {
				return err
			}
			rdns = append(rdns, []attributeTypeAndValue{{Type: oid, Value: rv}})
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
	der, err := asn1.Marshal(rdns)
	if err != nil {
		return nil, fmt.Errorf("pqx509: marshaling name: %w", err)
	}
	return der, nil
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
func ParseName(der []byte) (Name, error) {
	var rdns []([]attributeTypeAndValue)
	rest, err := asn1.Unmarshal(der, &rdns)
	if err != nil {
		return Name{}, fmt.Errorf("%w: name: %w", ErrMalformedDER, err)
	}
	if len(rest) != 0 {
		return Name{}, fmt.Errorf("%w: %d bytes after name", ErrTrailingData, len(rest))
	}
	var n Name
	for _, rdn := range rdns {
		for _, atv := range rdn {
			value, err := parseDirectoryString(atv.Value)
			if err != nil {
				return Name{}, err
			}
			switch {
			case atv.Type.Equal(oidCountry):
				n.Country = append(n.Country, value)
			case atv.Type.Equal(oidProvince):
				n.Province = append(n.Province, value)
			case atv.Type.Equal(oidLocality):
				n.Locality = append(n.Locality, value)
			case atv.Type.Equal(oidOrganization):
				n.Organization = append(n.Organization, value)
			case atv.Type.Equal(oidOrganizationalUnit):
				n.OrganizationalUnit = append(n.OrganizationalUnit, value)
			case atv.Type.Equal(oidCommonName):
				n.CommonName = value
			}
		}
	}
	return n, nil
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
