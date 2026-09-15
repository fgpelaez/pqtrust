package pqx509

import (
	"encoding/asn1"
	"fmt"
	"strings"
)

// Algorithm identifies a post-quantum signature algorithm.
type Algorithm int

// Supported signature algorithms.
//nolint:revive // circl-style parameter-set names
const (
	MLDSA44 Algorithm = iota + 1
	MLDSA65
	MLDSA87
	SLHDSA_SHA2_128s
	SLHDSA_SHA2_128f
	SLHDSA_SHA2_192s
	SLHDSA_SHA2_192f
	SLHDSA_SHA2_256s
	SLHDSA_SHA2_256f
	SLHDSA_SHAKE_128s
	SLHDSA_SHAKE_128f
	SLHDSA_SHAKE_192s
	SLHDSA_SHAKE_192f
	SLHDSA_SHAKE_256s
	SLHDSA_SHAKE_256f
)

type algorithmInfo struct {
	name     string
	oid      asn1.ObjectIdentifier
	pkSize   int
	sigSize  int
	seedSize int
	family   algorithmFamily
}

var algorithms = map[Algorithm]algorithmInfo{
	MLDSA44:          {"ML-DSA-44", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}, 1312, 2420, 32, mldsaFamily{}},
	MLDSA65:          {"ML-DSA-65", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}, 1952, 3309, 32, mldsaFamily{}},
	MLDSA87:          {"ML-DSA-87", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}, 2592, 4627, 32, mldsaFamily{}},
	SLHDSA_SHA2_128s: {"SLH-DSA-SHA2-128s", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 20}, 32, 7856, 64, slhdsaFamily{}},
	SLHDSA_SHA2_128f: {"SLH-DSA-SHA2-128f", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 21}, 32, 17088, 64, slhdsaFamily{}},
	SLHDSA_SHA2_192s: {"SLH-DSA-SHA2-192s", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 22}, 48, 16224, 96, slhdsaFamily{}},
	SLHDSA_SHA2_192f: {"SLH-DSA-SHA2-192f", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 23}, 48, 35664, 96, slhdsaFamily{}},
	SLHDSA_SHA2_256s: {"SLH-DSA-SHA2-256s", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 24}, 64, 29792, 128, slhdsaFamily{}},
	SLHDSA_SHA2_256f: {"SLH-DSA-SHA2-256f", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 25}, 64, 49856, 128, slhdsaFamily{}},
	SLHDSA_SHAKE_128s: {"SLH-DSA-SHAKE-128s", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 26}, 32, 7856, 64, slhdsaFamily{}},
	SLHDSA_SHAKE_128f: {"SLH-DSA-SHAKE-128f", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 27}, 32, 17088, 64, slhdsaFamily{}},
	SLHDSA_SHAKE_192s: {"SLH-DSA-SHAKE-192s", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 28}, 48, 16224, 96, slhdsaFamily{}},
	SLHDSA_SHAKE_192f: {"SLH-DSA-SHAKE-192f", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 29}, 48, 35664, 96, slhdsaFamily{}},
	SLHDSA_SHAKE_256s: {"SLH-DSA-SHAKE-256s", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 30}, 64, 29792, 128, slhdsaFamily{}},
	SLHDSA_SHAKE_256f: {"SLH-DSA-SHAKE-256f", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 31}, 64, 49856, 128, slhdsaFamily{}},
}

// String returns the canonical FIPS 204/205 name, e.g. "ML-DSA-65" or
// "SLH-DSA-SHA2-128s".
func (a Algorithm) String() string {
	if info, ok := algorithms[a]; ok {
		return info.name
	}
	return fmt.Sprintf("Algorithm(%d)", int(a))
}

// OID returns the NIST CSOR signature algorithm OID.
func (a Algorithm) OID() asn1.ObjectIdentifier { return algorithms[a].oid }

// PublicKeySize returns the encoded public key length in bytes.
func (a Algorithm) PublicKeySize() int { return algorithms[a].pkSize }

// SignatureSize returns the signature length in bytes.
func (a Algorithm) SignatureSize() int { return algorithms[a].sigSize }

// SeedSize returns the private key material length in bytes: 32 for the
// ML-DSA seed, 4n (64/96/128) for SLH-DSA.
func (a Algorithm) SeedSize() int { return algorithms[a].seedSize }

// Valid reports whether a is a supported algorithm.
func (a Algorithm) Valid() bool { _, ok := algorithms[a]; return ok }

// ParseAlgorithm resolves a canonical algorithm name, case-insensitively.
func ParseAlgorithm(s string) (Algorithm, error) {
	for alg, info := range algorithms {
		if strings.EqualFold(s, info.name) {
			return alg, nil
		}
	}
	return 0, fmt.Errorf("%w: %q", ErrUnknownAlgorithm, s)
}

func algorithmFromOID(oid asn1.ObjectIdentifier) (Algorithm, error) {
	for alg, info := range algorithms {
		if info.oid.Equal(oid) {
			return alg, nil
		}
	}
	return 0, fmt.Errorf("%w: OID %s", ErrUnknownAlgorithm, oid)
}
