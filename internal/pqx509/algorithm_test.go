package pqx509

import (
	"encoding/asn1"
	"testing"
)

func TestAlgorithmOIDsAndSizes(t *testing.T) {
	cases := []struct {
		alg     Algorithm
		name    string
		oid     string
		pkSize  int
		sigSize int
	}{
		{MLDSA44, "ML-DSA-44", "2.16.840.1.101.3.4.3.17", 1312, 2420},
		{MLDSA65, "ML-DSA-65", "2.16.840.1.101.3.4.3.18", 1952, 3309},
		{MLDSA87, "ML-DSA-87", "2.16.840.1.101.3.4.3.19", 2592, 4627},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.alg.String(); got != c.name {
				t.Errorf("String() = %q, want %q", got, c.name)
			}
			if got := c.alg.OID().String(); got != c.oid {
				t.Errorf("OID() = %s, want %s", got, c.oid)
			}
			if got := c.alg.PublicKeySize(); got != c.pkSize {
				t.Errorf("PublicKeySize() = %d, want %d", got, c.pkSize)
			}
			if got := c.alg.SignatureSize(); got != c.sigSize {
				t.Errorf("SignatureSize() = %d, want %d", got, c.sigSize)
			}
			back, err := algorithmFromOID(c.alg.OID())
			if err != nil || back != c.alg {
				t.Errorf("algorithmFromOID round-trip = %v, %v", back, err)
			}
			parsed, err := ParseAlgorithm(c.name)
			if err != nil || parsed != c.alg {
				t.Errorf("ParseAlgorithm(%q) = %v, %v", c.name, parsed, err)
			}
		})
	}
}

func TestUnknownAlgorithm(t *testing.T) {
	if _, err := ParseAlgorithm("ML-DSA-99"); err == nil {
		t.Error("ParseAlgorithm should reject unknown names")
	}
	// RSA encryption OID must not resolve.
	if _, err := algorithmFromOID(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}); err == nil {
		t.Error("algorithmFromOID should reject non-ML-DSA OIDs")
	}
}

func TestAlgorithmSeedSizeIs32(t *testing.T) {
	for _, alg := range []Algorithm{MLDSA44, MLDSA65, MLDSA87} {
		if got := alg.SeedSize(); got != 32 {
			t.Errorf("%s.SeedSize() = %d, want 32", alg, got)
		}
	}
}
