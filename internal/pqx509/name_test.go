package pqx509

import (
	"reflect"
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
