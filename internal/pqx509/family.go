package pqx509

import (
	"crypto"
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// algorithmFamily implements one signature family's key operations. The
// registry in algorithm.go selects the implementation per Algorithm; nothing
// outside a family knows which crypto library is underneath.
type algorithmFamily interface {
	// generateKey produces a key pair for alg. The returned PrivateKey.Seed
	// holds the family's canonical private-key encoding.
	generateKey(r io.Reader, alg Algorithm) (PublicKey, PrivateKey, error)
	// signer expands keyMaterial (PrivateKey.Seed) into a Signer.
	signer(keyMaterial []byte, alg Algorithm) (Signer, error)
	// verify checks a pure-mode, empty-context signature.
	verify(pub PublicKey, msg, sig []byte) error
}

type mldsaFamily struct{}

func (mldsaFamily) generateKey(r io.Reader, alg Algorithm) (PublicKey, PrivateKey, error) {
	seed := make([]byte, alg.SeedSize())
	if _, err := io.ReadFull(r, seed); err != nil {
		return PublicKey{}, PrivateKey{}, fmt.Errorf("pqx509: reading seed: %w", err)
	}
	priv := PrivateKey{Algorithm: alg, Seed: seed}
	signer, err := priv.Signer()
	if err != nil {
		return PublicKey{}, PrivateKey{}, err
	}
	return signer.Public(), priv, nil
}

func (mldsaFamily) signer(keyMaterial []byte, alg Algorithm) (Signer, error) {
	if len(keyMaterial) != alg.SeedSize() {
		return nil, fmt.Errorf("%w: seed is %d bytes, want %d", ErrInvalidKeySize, len(keyMaterial), alg.SeedSize())
	}
	var seed [32]byte
	copy(seed[:], keyMaterial)

	switch alg {
	case MLDSA44:
		pub, sk := mldsa44.NewKeyFromSeed(&seed)
		return &circlSigner{alg: alg, pub: PublicKey{alg, pub.Bytes()}, sign: func(msg []byte) ([]byte, error) {
			return sk.Sign(nil, msg, crypto.Hash(0))
		}}, nil
	case MLDSA65:
		pub, sk := mldsa65.NewKeyFromSeed(&seed)
		return &circlSigner{alg: alg, pub: PublicKey{alg, pub.Bytes()}, sign: func(msg []byte) ([]byte, error) {
			return sk.Sign(nil, msg, crypto.Hash(0))
		}}, nil
	case MLDSA87:
		pub, sk := mldsa87.NewKeyFromSeed(&seed)
		return &circlSigner{alg: alg, pub: PublicKey{alg, pub.Bytes()}, sign: func(msg []byte) ([]byte, error) {
			return sk.Sign(nil, msg, crypto.Hash(0))
		}}, nil
	default:
		return nil, fmt.Errorf("%w: %v", ErrUnknownAlgorithm, alg)
	}
}

func (mldsaFamily) verify(pub PublicKey, msg, sig []byte) error {
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
