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

func TestAlgorithmSLHDSAMetadata(t *testing.T) {
	cases := []struct {
		alg      Algorithm
		name     string
		oid      string
		pkSize   int
		sigSize  int
		seedSize int
	}{
		{SLHDSA_SHA2_128s, "SLH-DSA-SHA2-128s", "2.16.840.1.101.3.4.3.20", 32, 7856, 64},
		{SLHDSA_SHA2_128f, "SLH-DSA-SHA2-128f", "2.16.840.1.101.3.4.3.21", 32, 17088, 64},
		{SLHDSA_SHA2_192s, "SLH-DSA-SHA2-192s", "2.16.840.1.101.3.4.3.22", 48, 16224, 96},
		{SLHDSA_SHA2_192f, "SLH-DSA-SHA2-192f", "2.16.840.1.101.3.4.3.23", 48, 35664, 96},
		{SLHDSA_SHA2_256s, "SLH-DSA-SHA2-256s", "2.16.840.1.101.3.4.3.24", 64, 29792, 128},
		{SLHDSA_SHA2_256f, "SLH-DSA-SHA2-256f", "2.16.840.1.101.3.4.3.25", 64, 49856, 128},
		{SLHDSA_SHAKE_128s, "SLH-DSA-SHAKE-128s", "2.16.840.1.101.3.4.3.26", 32, 7856, 64},
		{SLHDSA_SHAKE_128f, "SLH-DSA-SHAKE-128f", "2.16.840.1.101.3.4.3.27", 32, 17088, 64},
		{SLHDSA_SHAKE_192s, "SLH-DSA-SHAKE-192s", "2.16.840.1.101.3.4.3.28", 48, 16224, 96},
		{SLHDSA_SHAKE_192f, "SLH-DSA-SHAKE-192f", "2.16.840.1.101.3.4.3.29", 48, 35664, 96},
		{SLHDSA_SHAKE_256s, "SLH-DSA-SHAKE-256s", "2.16.840.1.101.3.4.3.30", 64, 29792, 128},
		{SLHDSA_SHAKE_256f, "SLH-DSA-SHAKE-256f", "2.16.840.1.101.3.4.3.31", 64, 49856, 128},
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
			if got := c.alg.SeedSize(); got != c.seedSize {
				t.Errorf("SeedSize() = %d, want %d", got, c.seedSize)
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
	// Case-insensitive intake, the way the API receives names.
	if parsed, err := ParseAlgorithm("slh-dsa-sha2-128s"); err != nil || parsed != SLHDSA_SHA2_128s {
		t.Errorf("ParseAlgorithm(lowercase) = %v, %v", parsed, err)
	}
	// HashSLH-DSA (pre-hash, sigAlgs 35) is out of scope and must not resolve.
	if _, err := algorithmFromOID(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 35}); err == nil {
		t.Error("algorithmFromOID must reject HashSLH-DSA OIDs")
	}
}
