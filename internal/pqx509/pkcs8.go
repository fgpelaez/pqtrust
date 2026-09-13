package pqx509

import (
	"bytes"
	"encoding/asn1"
	"fmt"
)

// oneAsymmetricKey is the PKCS#8 (RFC 5958) private key structure. For ML-DSA
// the privateKey OCTET STRING carries the raw 32-byte seed, per
// draft-ietf-lamps-dilithium-certificates; the AlgorithmIdentifier parameters
// are absent, matching every other ML-DSA structure pqtrust emits.
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
	if len(priv.Seed) != 32 {
		return nil, fmt.Errorf("%w: seed is %d bytes, want 32", ErrInvalidKeySize, len(priv.Seed))
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

// ParsePKCS8PrivateKey decodes a DER OneAsymmetricKey holding an ML-DSA seed.
// Wrong version, present parameters, wrong seed size and trailing data are
// hard errors.
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
		return PrivateKey{}, fmt.Errorf("%w: ML-DSA AlgorithmIdentifier must omit parameters", ErrMalformedDER)
	}
	if len(k.PrivateKey) != 32 {
		return PrivateKey{}, fmt.Errorf("%w: seed is %d bytes, want 32", ErrInvalidKeySize, len(k.PrivateKey))
	}
	return PrivateKey{Algorithm: alg, Seed: bytes.Clone(k.PrivateKey)}, nil
}
