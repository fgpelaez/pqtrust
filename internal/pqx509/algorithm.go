package pqx509

import (
	"encoding/asn1"
	"fmt"
	"strings"
)

// Algorithm identifies a post-quantum signature algorithm.
type Algorithm int

// Supported signature algorithms.
const (
	MLDSA44 Algorithm = iota + 1
	MLDSA65
	MLDSA87
)

type algorithmInfo struct {
	name    string
	oid     asn1.ObjectIdentifier
	pkSize  int
	sigSize int
}

var algorithms = map[Algorithm]algorithmInfo{
	MLDSA44: {"ML-DSA-44", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}, 1312, 2420},
	MLDSA65: {"ML-DSA-65", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}, 1952, 3309},
	MLDSA87: {"ML-DSA-87", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}, 2592, 4627},
}

// String returns the canonical FIPS 204 name, e.g. "ML-DSA-65".
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

// SeedSize returns the private key seed length in bytes.
func (a Algorithm) SeedSize() int { return 32 }

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
