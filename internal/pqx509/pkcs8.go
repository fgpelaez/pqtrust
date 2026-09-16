package pqx509

import (
	"bytes"
	"encoding/asn1"
	"fmt"
)

// oneAsymmetricKey is the PKCS#8 (RFC 5958) private key structure. For ML-DSA
// the privateKey OCTET STRING carries the raw 32-byte seed per RFC 9881; for
// SLH-DSA it carries the 4n-byte private key per RFC 9909 §7. The
// AlgorithmIdentifier parameters are absent, matching every other structure
// pqtrust emits.
type oneAsymmetricKey struct {
	Version    int
	Algorithm  algorithmIdentifier
	PrivateKey []byte
}

// MarshalPKCS8PrivateKey encodes priv as a DER OneAsymmetricKey (version 0).
func MarshalPKCS8PrivateKey(priv PrivateKey) ([]byte, error) {
	if !priv.Algorithm.Valid() {
		return nil, fmt.Errorf("%w: %v", ErrUnknownAlgorithm, priv.Algorithm)
	}
	if len(priv.Seed) != priv.Algorithm.SeedSize() {
		return nil, fmt.Errorf("%w: key material is %d bytes, want %d", ErrInvalidKeySize, len(priv.Seed), priv.Algorithm.SeedSize())
	}
	der, err := asn1.Marshal(oneAsymmetricKey{
		Version:    0,
		Algorithm:  algorithmIdentifier{Algorithm: priv.Algorithm.OID()},
		PrivateKey: priv.Seed,
	})
	if err != nil {
		return nil, fmt.Errorf("pqx509: marshaling PKCS#8 private key: %w", err)
	}
	return der, nil
}

// ParsePKCS8PrivateKey decodes a DER OneAsymmetricKey. Wrong version, present
// parameters, wrong key material size and trailing data are hard errors.
func ParsePKCS8PrivateKey(der []byte) (PrivateKey, error) {
	var k oneAsymmetricKey
	rest, err := asn1.Unmarshal(der, &k)
	if err != nil {
		return PrivateKey{}, fmt.Errorf("%w: PKCS#8 private key: %w", ErrMalformedDER, err)
	}
	if len(rest) != 0 {
		return PrivateKey{}, fmt.Errorf("%w: %d bytes after PKCS#8 private key", ErrTrailingData, len(rest))
	}
	if k.Version != 0 {
		return PrivateKey{}, fmt.Errorf("%w: PKCS#8 version %d, want 0", ErrMalformedDER, k.Version)
	}
	alg, err := algorithmFromOID(k.Algorithm.Algorithm)
	if err != nil {
		return PrivateKey{}, err
	}
	if len(k.Algorithm.Parameters.FullBytes) != 0 {
		return PrivateKey{}, fmt.Errorf("%w: AlgorithmIdentifier must omit parameters", ErrMalformedDER)
	}
	if len(k.PrivateKey) != alg.SeedSize() {
		return PrivateKey{}, fmt.Errorf("%w: key material is %d bytes, want %d", ErrInvalidKeySize, len(k.PrivateKey), alg.SeedSize())
	}
	return PrivateKey{Algorithm: alg, Seed: bytes.Clone(k.PrivateKey)}, nil
}
