package pqx509

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"io"
)

// PublicKey is an algorithm-tagged post-quantum public key in its encoded form.
type PublicKey struct {
	Algorithm Algorithm
	Bytes     []byte
}

// PrivateKey is an algorithm-tagged post-quantum private key, held as the
// family's canonical encoding: a 32-byte ML-DSA seed or a 4n-byte SLH-DSA key.
type PrivateKey struct {
	Algorithm Algorithm
	Seed      []byte
}

// Signer signs messages with a post-quantum private key. keystore-loaded keys
// implement it, which lets a future HSM backend sign without exposing key bytes.
type Signer interface {
	Public() PublicKey
	Sign(rand io.Reader, msg []byte) ([]byte, error)
	Algorithm() Algorithm
}

// GenerateKey generates a key pair for alg using entropy from rand.
func GenerateKey(rand io.Reader, alg Algorithm) (PublicKey, PrivateKey, error) {
	if !alg.Valid() {
		return PublicKey{}, PrivateKey{}, fmt.Errorf("%w: %v", ErrUnknownAlgorithm, alg)
	}
	return algorithms[alg].family.generateKey(rand, alg)
}

type circlSigner struct {
	alg  Algorithm
	pub  PublicKey
	sign func(msg []byte) ([]byte, error)
}

func (s *circlSigner) Public() PublicKey    { return s.pub }
func (s *circlSigner) Algorithm() Algorithm { return s.alg }
func (s *circlSigner) Sign(_ io.Reader, msg []byte) ([]byte, error) {
	return s.sign(msg)
}

// Signer expands the key material and returns a Signer. The returned Signer
// signs in pure mode with an empty context string, as X.509 requires.
func (k PrivateKey) Signer() (Signer, error) {
	if !k.Algorithm.Valid() {
		return nil, fmt.Errorf("%w: %v", ErrUnknownAlgorithm, k.Algorithm)
	}
	return algorithms[k.Algorithm].family.signer(k.Seed, k.Algorithm)
}

// Verify checks a pure-mode signature with an empty context string.
func Verify(pub PublicKey, msg, sig []byte) error {
	if !pub.Algorithm.Valid() {
		return fmt.Errorf("%w: %v", ErrUnknownAlgorithm, pub.Algorithm)
	}
	return algorithms[pub.Algorithm].family.verify(pub, msg, sig)
}

// MarshalPKIXPublicKey encodes pub as a DER SubjectPublicKeyInfo, with the raw
// key in the BIT STRING and no AlgorithmIdentifier parameters.
func MarshalPKIXPublicKey(pub PublicKey) ([]byte, error) {
	if !pub.Algorithm.Valid() {
		return nil, fmt.Errorf("%w: %v", ErrUnknownAlgorithm, pub.Algorithm)
	}
	if len(pub.Bytes) != pub.Algorithm.PublicKeySize() {
		return nil, fmt.Errorf("%w: public key is %d bytes, want %d", ErrInvalidKeySize, len(pub.Bytes), pub.Algorithm.PublicKeySize())
	}
	der, err := asn1.Marshal(subjectPublicKeyInfo{
		Algorithm: algorithmIdentifier{Algorithm: pub.Algorithm.OID()},
		PublicKey: asn1.BitString{Bytes: pub.Bytes, BitLength: len(pub.Bytes) * 8},
	})
	if err != nil {
		return nil, fmt.Errorf("pqx509: marshaling SPKI: %w", err)
	}
	return der, nil
}

// ParsePKIXPublicKey decodes a DER SubjectPublicKeyInfo.
func ParsePKIXPublicKey(der []byte) (PublicKey, error) {
	var spki subjectPublicKeyInfo
	rest, err := asn1.Unmarshal(der, &spki)
	if err != nil {
		return PublicKey{}, fmt.Errorf("%w: SPKI: %w", ErrMalformedDER, err)
	}
	if len(rest) != 0 {
		return PublicKey{}, fmt.Errorf("%w: %d bytes after SPKI", ErrTrailingData, len(rest))
	}
	return publicKeyFromSPKI(spki)
}

func publicKeyFromSPKI(spki subjectPublicKeyInfo) (PublicKey, error) {
	alg, err := algorithmFromOID(spki.Algorithm.Algorithm)
	if err != nil {
		return PublicKey{}, err
	}
	if len(spki.Algorithm.Parameters.FullBytes) != 0 {
		return PublicKey{}, fmt.Errorf("%w: AlgorithmIdentifier must omit parameters", ErrMalformedDER)
	}
	if spki.PublicKey.BitLength%8 != 0 {
		return PublicKey{}, fmt.Errorf("%w: SPKI BIT STRING has unused bits", ErrMalformedDER)
	}
	if len(spki.PublicKey.Bytes) != alg.PublicKeySize() {
		return PublicKey{}, fmt.Errorf("%w: %s public key is %d bytes, want %d", ErrInvalidKeySize, alg, len(spki.PublicKey.Bytes), alg.PublicKeySize())
	}
	return PublicKey{Algorithm: alg, Bytes: bytes.Clone(spki.PublicKey.Bytes)}, nil
}

// KeyIdentifier computes an RFC 7093 section 2 method 1 key identifier: the
// leftmost 160 bits of SHA-256 over the SPKI BIT STRING bits.
func KeyIdentifier(pub PublicKey) ([]byte, error) {
	if len(pub.Bytes) != pub.Algorithm.PublicKeySize() {
		return nil, fmt.Errorf("%w: public key is %d bytes, want %d", ErrInvalidKeySize, len(pub.Bytes), pub.Algorithm.PublicKeySize())
	}
	sum := sha256.Sum256(pub.Bytes)
	return sum[:20], nil
}
