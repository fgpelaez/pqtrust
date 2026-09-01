package pqx509

import (
	"encoding/asn1"
	"reflect"
	"strings"
	"testing"
)

func TestNameRoundTrip(t *testing.T) {
	n := Name{
		Country:            []string{"ES"},
		Organization:       []string{"pqtrust"},
		OrganizationalUnit: []string{"PKI"},
		Locality:           []string{"Madrid"},
		Province:           []string{"Madrid"},
		CommonName:         "pqtrust Root CA",
	}
	der, err := n.ToRDNSequence()
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseName(der)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(n, back) {
		t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", back, n)
	}
}

func TestNameStringRoundTrip(t *testing.T) {
	n := Name{Country: []string{"ES"}, Organization: []string{"pqtrust"}, CommonName: "api.example.com"}
	s := n.String()
	if s != "CN=api.example.com,O=pqtrust,C=ES" {
		t.Fatalf("String() = %q", s)
	}
	back, err := ParseNameString(s)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(n, back) {
		t.Errorf("ParseNameString mismatch:\n got %+v\nwant %+v", back, n)
	}
}

func TestEmptyNameEncodesAsEmptySequence(t *testing.T) {
	der, err := Name{}.ToRDNSequence()
	if err != nil {
		t.Fatal(err)
	}
	if len(der) != 2 || der[0] != 0x30 || der[1] != 0x00 {
		t.Errorf("empty name DER = % x, want 30 00", der)
	}
}

func TestParseNameRejectsTrailingData(t *testing.T) {
	der, _ := Name{CommonName: "x"}.ToRDNSequence()
	if _, err := ParseName(append(der, 0x00)); err == nil {
		t.Error("ParseName must reject trailing data")
	}
}

func TestParseNameStringRejectsMalformed(t *testing.T) {
	for _, s := range []string{"CN", "=value", "XX=unsupported"} {
		if _, err := ParseNameString(s); err == nil {
			t.Errorf("ParseNameString(%q) must fail", s)
		}
	}
}

func TestMarshalLength(t *testing.T) {
	for _, tc := range []struct {
		in   int
		want []byte
	}{
		{0, []byte{0x00}},
		{5, []byte{0x05}},
		{127, []byte{0x7f}},
		{128, []byte{0x81, 0x80}},
		{300, []byte{0x82, 0x01, 0x2c}},
		{70000, []byte{0x83, 0x01, 0x11, 0x70}},
		{0x123456, []byte{0x83, 0x12, 0x34, 0x56}},
	} {
		if got := marshalLength(tc.in); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("marshalLength(%d) = % x, want % x", tc.in, got, tc.want)
		}
	}
}

func TestParseDERLength(t *testing.T) {
	for _, tc := range []struct {
		name    string
		in      []byte
		want    int
		rest    int
		wantErr bool
	}{
		{"short form", []byte{0x05, 1, 2, 3, 4, 5, 9}, 5, 6, false},
		{"long form 1 byte", []byte{0x81, 0x80}, 128, 0, false},
		{"long form 2 bytes", []byte{0x82, 0x01, 0x2c}, 300, 0, false},
		{"long form 3 bytes", []byte{0x83, 0x01, 0x2c, 0x40}, 76864, 0, false},
		{"indefinite rejected", []byte{0x80, 0x00}, 0, 0, true},
		{"zero long-form byte rejected", []byte{0x80}, 0, 0, true},
		{"truncated long form", []byte{0x82, 0x01}, 0, 0, true},
		{"empty", nil, 0, 0, true},
	} {
		got, rest, err := parseDERLength(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("%s: parseDERLength(% x) must fail", tc.name, tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: parseDERLength(% x): %v", tc.name, tc.in, err)
			continue
		}
		if got != tc.want || len(rest) != tc.rest {
			t.Errorf("%s: parseDERLength(% x) = %d, %d rest; want %d, %d rest",
				tc.name, tc.in, got, len(rest), tc.want, tc.rest)
		}
	}
}

func TestMarshalLengthParseDERLengthRoundTrip(t *testing.T) {
	for _, l := range []int{0, 1, 127, 128, 255, 256, 300, 65535, 65536, 70000, 1 << 24} {
		encoded := marshalLength(l)
		decoded, rest, err := parseDERLength(append(encoded, 0xff))
		if err != nil {
			t.Fatalf("marshalLength(%d) = % x does not parse: %v", l, encoded, err)
		}
		if decoded != l {
			t.Errorf("round-trip: %d encodes to % x and decodes back as %d", l, encoded, decoded)
		}
		if len(rest) != 1 {
			t.Errorf("round-trip %d: want 1 trailing byte, got %d", l, len(rest))
		}
	}
}

func TestNameRoundTripWithLongFormLengths(t *testing.T) {
	// A 320-byte CN forces DER long-form lengths in the SET, SEQUENCE and
	// outer RDNSequence, on both the encode and the parse side.
	n := Name{CommonName: strings.Repeat("pqtrust CA ", 29)}
	der, err := n.ToRDNSequence()
	if err != nil {
		t.Fatal(err)
	}
	if der[1]&0x80 == 0 {
		t.Fatalf("expected long-form outer length, got % x", der[:4])
	}
	back, err := ParseName(der)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(n, back) {
		t.Errorf("round-trip mismatch on long-form name")
	}
}

func TestParseSetAndSequenceRejectMalformed(t *testing.T) {
	if _, _, err := parseSet([]byte{0x30, 0x00}); err == nil {
		t.Error("parseSet must reject a SEQUENCE tag")
	}
	if _, _, err := parseSet([]byte{0x31, 0x82, 0x01}); err == nil {
		t.Error("parseSet must reject a truncated long-form length")
	}
	if _, _, err := parseSet([]byte{0x31, 0x05, 0x00}); err == nil {
		t.Error("parseSet must reject a short read")
	}
	if _, _, err := parseSequence([]byte{0x31, 0x00}); err == nil {
		t.Error("parseSequence must reject a SET tag")
	}
	if _, _, err := parseSequence([]byte{0x30, 0x82, 0x01}); err == nil {
		t.Error("parseSequence must reject a truncated long-form length")
	}
	if _, _, err := parseSequence([]byte{0x30, 0x05, 0x00}); err == nil {
		t.Error("parseSequence must reject a short read")
	}
	if _, _, err := parseSet(nil); err == nil {
		t.Error("parseSet must reject empty input")
	}
	if _, _, err := parseSequence(nil); err == nil {
		t.Error("parseSequence must reject empty input")
	}
}

func TestParseDirectoryStringRejectsUnsupportedTag(t *testing.T) {
	if _, err := parseDirectoryString(asn1.RawValue{Tag: asn1.TagBMPString, Bytes: []byte("x")}); err == nil {
		t.Error("parseDirectoryString must reject unsupported tags")
	}
	for _, tag := range []int{asn1.TagPrintableString, asn1.TagUTF8String, asn1.TagIA5String, asn1.TagT61String} {
		if _, err := parseDirectoryString(asn1.RawValue{Tag: tag, Bytes: []byte("ok")}); err != nil {
			t.Errorf("parseDirectoryString(tag %d): %v", tag, err)
		}
	}
}
func TestParseNameRejectsNonDERSetLength(t *testing.T) {
	der, err := Name{CommonName: "x"}.ToRDNSequence()
	if err != nil {
		t.Fatal(err)
	}
	// Break the inner SET by truncating its declared length bytes.
	for i := range der {
		if der[i] == 0x31 {
			broken := append([]byte{}, der[:i+1]...)
			broken = append(broken, 0x82, 0x01)
			if _, err := ParseName(append(broken, der[i+2:]...)); err == nil {
				t.Error("ParseName must reject a truncated SET length")
			}
			return
		}
	}
	t.Fatal("test premise failed: no SET found")
}
