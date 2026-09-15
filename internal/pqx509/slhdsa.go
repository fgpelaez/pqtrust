package pqx509

import (
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/slhdsa"
)

// slhdsaID resolves an Algorithm to its circl parameter-set identifier.
func slhdsaID(alg Algorithm) (slhdsa.ID, error) {
	id, err := slhdsa.IDByName(alg.String())
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrUnknownAlgorithm, alg)
	}
	return id, nil
}

// slhdsaFamily implements FIPS 205 key operations via circl. Private key
// material is the RFC 9909 4n-byte SLH-DSA private key
// (SK.seed || SK.prf || PK.seed || PK.root), which is exactly what circl's
// PrivateKey marshals to. Signing is deterministic, pure mode, empty context.
type slhdsaFamily struct{}

func (slhdsaFamily) generateKey(r io.Reader, alg Algorithm) (PublicKey, PrivateKey, error) {
	id, err := slhdsaID(alg)
	if err != nil {
		return PublicKey{}, PrivateKey{}, err
	}
	pub, priv, err := slhdsa.GenerateKey(r, id)
	if err != nil {
		return PublicKey{}, PrivateKey{}, fmt.Errorf("pqx509: generating SLH-DSA key: %w", err)
	}
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		return PublicKey{}, PrivateKey{}, fmt.Errorf("pqx509: encoding SLH-DSA public key: %w", err)
	}
	keyMaterial, err := priv.MarshalBinary()
	if err != nil {
		return PublicKey{}, PrivateKey{}, fmt.Errorf("pqx509: encoding SLH-DSA private key: %w", err)
	}
	return PublicKey{Algorithm: alg, Bytes: pubBytes}, PrivateKey{Algorithm: alg, Seed: keyMaterial}, nil
}

func (slhdsaFamily) signer(keyMaterial []byte, alg Algorithm) (Signer, error) {
	if len(keyMaterial) != alg.SeedSize() {
		return nil, fmt.Errorf("%w: SLH-DSA key material is %d bytes, want %d", ErrInvalidKeySize, len(keyMaterial), alg.SeedSize())
	}
	id, err := slhdsaID(alg)
	if err != nil {
		return nil, err
	}
	sk := slhdsa.PrivateKey{ID: id} // UnmarshalBinary requires the ID set first.
	if err := sk.UnmarshalBinary(keyMaterial); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKeySize, err)
	}
	pubBytes, err := sk.PublicKey().MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("pqx509: encoding SLH-DSA public key: %w", err)
	}
	return &circlSigner{
		alg: alg,
		pub: PublicKey{alg, pubBytes},
		sign: func(msg []byte) ([]byte, error) {
			return slhdsa.SignDeterministic(&sk, slhdsa.NewMessage(msg), nil)
		},
	}, nil
}

func (slhdsaFamily) verify(pub PublicKey, msg, sig []byte) error {
	if len(pub.Bytes) != pub.Algorithm.PublicKeySize() {
		return fmt.Errorf("%w: public key is %d bytes, want %d", ErrInvalidKeySize, len(pub.Bytes), pub.Algorithm.PublicKeySize())
	}
	id, err := slhdsaID(pub.Algorithm)
	if err != nil {
		return err
	}
	k := slhdsa.PublicKey{ID: id}
	if err := k.UnmarshalBinary(pub.Bytes); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidKeySize, err)
	}
	if !slhdsa.Verify(&k, slhdsa.NewMessage(msg), sig, nil) {
		return ErrBadSignature
	}
	return nil
}
