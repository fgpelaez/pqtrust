package pqx509

import (
	"encoding/asn1"
	"math/big"
	"net"
	"reflect"
	"testing"
)

func TestBasicConstraintsRoundTrip(t *testing.T) {
	for _, bc := range []BasicConstraints{
		{IsCA: false},
		{IsCA: true},
		{IsCA: true, MaxPathLen: 0, MaxPathLenSet: true},
		{IsCA: true, MaxPathLen: 1, MaxPathLenSet: true},
	} {
		der, err := marshalBasicConstraints(bc)
		if err != nil {
			t.Fatalf("%+v: %v", bc, err)
		}
		back, err := parseBasicConstraints(der)
		if err != nil {
			t.Fatalf("%+v: %v", bc, err)
		}
		if !reflect.DeepEqual(bc, back) {
			t.Errorf("round-trip: got %+v, want %+v", back, bc)
		}
	}
}

func TestBasicConstraintsCAFalseOmitsDefault(t *testing.T) {
	der, err := marshalBasicConstraints(BasicConstraints{IsCA: false})
	if err != nil {
		t.Fatal(err)
	}
	// DER must omit cA when FALSE (it is DEFAULT FALSE): empty SEQUENCE.
	if len(der) != 2 || der[0] != 0x30 || der[1] != 0x00 {
		t.Errorf("got % x, want 30 00", der)
	}
}

func TestKeyUsageRoundTripAndMinimalEncoding(t *testing.T) {
	ku := KeyUsageKeyCertSign | KeyUsageCRLSign
	der, err := marshalKeyUsage(ku)
	if err != nil {
		t.Fatal(err)
	}
	back, err := parseKeyUsage(der)
	if err != nil {
		t.Fatal(err)
	}
	if back != ku {
		t.Errorf("round-trip = %b, want %b", back, ku)
	}
	// keyCertSign (bit 5) + cRLSign (bit 6): one content octet, 1 unused bit.
	var bs asn1.BitString
	if _, err := asn1.Unmarshal(der, &bs); err != nil {
		t.Fatal(err)
	}
	if len(bs.Bytes) != 1 || bs.BitLength != 7 {
		t.Errorf("BIT STRING = % x (BitLength %d), want 1 byte / BitLength 7", bs.Bytes, bs.BitLength)
	}
	if bs.Bytes[0] != 0x06 {
		t.Errorf("content octet = %#x, want 0x06", bs.Bytes[0])
	}
}

func TestKeyUsageDigitalSignatureOnly(t *testing.T) {
	der, err := marshalKeyUsage(KeyUsageDigitalSignature)
	if err != nil {
		t.Fatal(err)
	}
	var bs asn1.BitString
	if _, err := asn1.Unmarshal(der, &bs); err != nil {
		t.Fatal(err)
	}
	if len(bs.Bytes) != 1 || bs.Bytes[0] != 0x80 || bs.BitLength != 1 {
		t.Errorf("got % x BitLength %d, want 80 / 1", bs.Bytes, bs.BitLength)
	}
}

func TestKeyUsageStringsRoundTrip(t *testing.T) {
	ku := KeyUsageKeyCertSign | KeyUsageCRLSign
	got := ku.Strings()
	want := []string{"keyCertSign", "cRLSign"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Strings() = %v, want %v", got, want)
	}
	back, err := ParseKeyUsages(want)
	if err != nil || back != ku {
		t.Errorf("ParseKeyUsages = %b, %v", back, err)
	}
	if _, err := ParseKeyUsages([]string{"nonRepudiation"}); err == nil {
		t.Error("unsupported key usage must be rejected")
	}
}

func TestExtKeyUsageRoundTrip(t *testing.T) {
	in := []ExtKeyUsage{ExtKeyUsageServerAuth, ExtKeyUsageClientAuth}
	der, err := marshalExtKeyUsage(in)
	if err != nil {
		t.Fatal(err)
	}
	back, err := parseExtKeyUsage(der)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in, back) {
		t.Errorf("got %v, want %v", back, in)
	}
	parsed, err := ParseExtKeyUsages([]string{"serverAuth", "clientAuth"})
	if err != nil || !reflect.DeepEqual(parsed, in) {
		t.Errorf("ParseExtKeyUsages = %v, %v", parsed, err)
	}
	if _, err := ParseExtKeyUsages([]string{"codeSigning"}); err == nil {
		t.Error("unsupported EKU must be rejected")
	}
}

func TestExtKeyUsageString(t *testing.T) {
	cases := []struct {
		eku  ExtKeyUsage
		want string
	}{
		{ExtKeyUsageServerAuth, "serverAuth"},
		{ExtKeyUsageClientAuth, "clientAuth"},
		{ExtKeyUsage(0), "ExtKeyUsage(0)"},
	}
	for _, c := range cases {
		if got := c.eku.String(); got != c.want {
			t.Errorf("String() = %q, want %q", got, c.want)
		}
	}
}

func TestKeyIDExtensionsRoundTrip(t *testing.T) {
	id := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	skidDER, err := marshalKeyID(id)
	if err != nil {
		t.Fatal(err)
	}
	gotSKID, err := parseSubjectKeyID(skidDER)
	if err != nil || !reflect.DeepEqual(gotSKID, id) {
		t.Errorf("SKID round-trip = % x, %v", gotSKID, err)
	}
	akidDER, err := marshalAuthorityKeyID(id)
	if err != nil {
		t.Fatal(err)
	}
	gotAKID, err := parseAuthorityKeyID(akidDER)
	if err != nil || !reflect.DeepEqual(gotAKID, id) {
		t.Errorf("AKID round-trip = % x, %v", gotAKID, err)
	}
}

func TestSANsRoundTrip(t *testing.T) {
	in := SANs{
		DNSNames:       []string{"api.example.com", "example.com"},
		EmailAddresses: []string{"pki@example.com"},
		IPAddresses:    []net.IP{net.ParseIP("192.0.2.10").To4(), net.ParseIP("2001:db8::1")},
	}
	der, err := marshalSANs(in)
	if err != nil {
		t.Fatal(err)
	}
	back, err := parseSANs(der)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in.DNSNames, back.DNSNames) {
		t.Errorf("DNS: got %v, want %v", back.DNSNames, in.DNSNames)
	}
	if !reflect.DeepEqual(in.EmailAddresses, back.EmailAddresses) {
		t.Errorf("email: got %v, want %v", back.EmailAddresses, in.EmailAddresses)
	}
	if len(back.IPAddresses) != 2 || !back.IPAddresses[0].Equal(in.IPAddresses[0]) || !back.IPAddresses[1].Equal(in.IPAddresses[1]) {
		t.Errorf("IP: got %v, want %v", back.IPAddresses, in.IPAddresses)
	}
}

func TestCRLExtensionHelpers(t *testing.T) {
	der, err := marshalCRLReason(1) // keyCompromise
	if err != nil {
		t.Fatal(err)
	}
	reason, err := parseCRLReason(der)
	if err != nil || reason != 1 {
		t.Errorf("CRL reason round-trip = %d, %v", reason, err)
	}
	if _, err := marshalCRLNumber(big.NewInt(7)); err != nil {
		t.Fatal(err)
	}
}

func TestIsSupportedExtension(t *testing.T) {
	if !isSupportedExtension(oidExtBasicConstraints) {
		t.Error("basicConstraints must be supported")
	}
	if isSupportedExtension(asn1.ObjectIdentifier{2, 5, 29, 30}) { // nameConstraints
		t.Error("nameConstraints must not be supported")
	}
}
