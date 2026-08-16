package keystore

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"

	"github.com/fernando/pqtrust/internal/pqx509"
)

// Backend generates, stores and loads sealed private keys. A future HSM or
// PKCS#11 implementation satisfies the same interface, which is why Load
// returns a Signer rather than key material.
type Backend interface {
	Generate(alg pqx509.Algorithm, passphrase []byte) (keyID string, pub pqx509.PublicKey, priv pqx509.PrivateKey, err error)
	Load(keyID string, passphrase []byte) (pqx509.Signer, error)
	Store(keyID string, priv pqx509.PrivateKey, passphrase []byte) error
	Delete(keyID string) error
	Has(keyID string) (bool, error)
}

var keyIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// NewKeyID returns a random 32-character lowercase hex key identifier.
func NewKeyID() (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("keystore: generating key ID: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func validateKeyID(keyID string) error {
	if !keyIDPattern.MatchString(keyID) {
		return fmt.Errorf("keystore: invalid key ID %q (want 32 lowercase hex characters)", keyID)
	}
	return nil
}
