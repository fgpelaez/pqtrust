package pqx509

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// PublicKey is an algorithm-tagged ML-DSA public key in its FIPS 204 encoding.
type PublicKey struct {
	Algorithm Algorithm
	Bytes     []byte
}

// PrivateKey is an algorithm-tagged ML-DSA private key, held as its 32-byte seed.
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
	var seed [32]byte
	if _, err := io.ReadFull(rand, seed[:]); err != nil {
		return PublicKey{}, PrivateKey{}, fmt.Errorf("pqx509: reading seed: %w", err)
	}
	priv := PrivateKey{Algorithm: alg, Seed: seed[:]}
	signer, err := priv.Signer()
	if err != nil {
		return PublicKey{}, PrivateKey{}, err
	}
	return signer.Public(), priv, nil
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

// Signer expands the seed and returns a Signer. The returned Signer signs in
// pure mode with an empty ML-DSA context string, as X.509 requires.
func (k PrivateKey) Signer() (Signer, error) {
	if len(k.Seed) != 32 {
		return nil, fmt.Errorf("%w: seed is %d bytes, want 32", ErrInvalidKeySize, len(k.Seed))
	}
	var seed [32]byte
	copy(seed[:], k.Seed)

	switch k.Algorithm {
	case MLDSA44:
		pub, sk := mldsa44.NewKeyFromSeed(&seed)
		return &circlSigner{alg: k.Algorithm, pub: PublicKey{k.Algorithm, pub.Bytes()}, sign: func(msg []byte) ([]byte, error) {
			return sk.Sign(nil, msg, crypto.Hash(0))
		}}, nil
	case MLDSA65:
		pub, sk := mldsa65.NewKeyFromSeed(&seed)
		return &circlSigner{alg: k.Algorithm, pub: PublicKey{k.Algorithm, pub.Bytes()}, sign: func(msg []byte) ([]byte, error) {
			return sk.Sign(nil, msg, crypto.Hash(0))
		}}, nil
	case MLDSA87:
		pub, sk := mldsa87.NewKeyFromSeed(&seed)
		return &circlSigner{alg: k.Algorithm, pub: PublicKey{k.Algorithm, pub.Bytes()}, sign: func(msg []byte) ([]byte, error) {
			return sk.Sign(nil, msg, crypto.Hash(0))
		}}, nil
	default:
		return nil, fmt.Errorf("%w: %v", ErrUnknownAlgorithm, k.Algorithm)
	}
}

// Verify checks a pure-mode ML-DSA signature with an empty context string.
func Verify(pub PublicKey, msg, sig []byte) error {
	if len(pub.Bytes) != pub.Algorithm.PublicKeySize() {
		return fmt.Errorf("%w: public key is %d bytes, want %d", ErrInvalidKeySize, len(pub.Bytes), pub.Algorithm.PublicKeySize())
	}
	var ok bool
	switch pub.Algorithm {
	case MLDSA44:
		var k mldsa44.PublicKey
		if err := k.UnmarshalBinary(pub.Bytes); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidKeySize, err)
		}
		ok = mldsa44.Verify(&k, msg, nil, sig)
	case MLDSA65:
		var k mldsa65.PublicKey
		if err := k.UnmarshalBinary(pub.Bytes); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidKeySize, err)
		}
		ok = mldsa65.Verify(&k, msg, nil, sig)
	case MLDSA87:
		var k mldsa87.PublicKey
		if err := k.UnmarshalBinary(pub.Bytes); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidKeySize, err)
		}
		ok = mldsa87.Verify(&k, msg, nil, sig)
	default:
		return fmt.Errorf("%w: %v", ErrUnknownAlgorithm, pub.Algorithm)
	}
	if !ok {
		return ErrBadSignature
	}
	return nil
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
		return PublicKey{}, fmt.Errorf("%w: ML-DSA AlgorithmIdentifier must omit parameters", ErrMalformedDER)
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
