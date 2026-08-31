package keystore

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/fgpelaez/pqtrust/internal/pqx509"
)

// FileBackend stores sealed keys as 0600 files in a 0700 directory.
type FileBackend struct {
	dir string
}

// NewFileBackend creates dir if needed and returns a filesystem-backed keystore.
func NewFileBackend(dir string) (*FileBackend, error) {
	if dir == "" {
		return nil, fmt.Errorf("keystore: key directory must not be empty")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("keystore: creating key directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // key directory must be owner-only
		return nil, fmt.Errorf("keystore: tightening key directory permissions: %w", err)
	}
	return &FileBackend{dir: dir}, nil
}

func (b *FileBackend) path(keyID string) string {
	return filepath.Join(b.dir, keyID+".key")
}

// Generate creates a key pair, seals the private key and returns both halves.
// The caller is responsible for discarding priv once it is no longer needed.
func (b *FileBackend) Generate(alg pqx509.Algorithm, passphrase []byte) (string, pqx509.PublicKey, pqx509.PrivateKey, error) {
	pub, priv, err := pqx509.GenerateKey(rand.Reader, alg)
	if err != nil {
		return "", pqx509.PublicKey{}, pqx509.PrivateKey{}, err
	}
	keyID, err := NewKeyID()
	if err != nil {
		return "", pqx509.PublicKey{}, pqx509.PrivateKey{}, err
	}
	if err := b.Store(keyID, priv, passphrase); err != nil {
		return "", pqx509.PublicKey{}, pqx509.PrivateKey{}, err
	}
	return keyID, pub, priv, nil
}

// Store seals priv and writes it under keyID. It never overwrites.
func (b *FileBackend) Store(keyID string, priv pqx509.PrivateKey, passphrase []byte) error {
	if err := validateKeyID(keyID); err != nil {
		return err
	}
	sealed, err := Seal(priv, passphrase)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(b.path(keyID), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%w: %s", ErrKeyExists, keyID)
		}
		return fmt.Errorf("keystore: creating key file: %w", err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(sealed); err != nil {
		return fmt.Errorf("keystore: writing key file: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("keystore: syncing key file: %w", err)
	}
	return nil
}

// Load unseals the key and returns a Signer. Key material is discarded as soon
// as the signer has been derived.
func (b *FileBackend) Load(keyID string, passphrase []byte) (pqx509.Signer, error) {
	if err := validateKeyID(keyID); err != nil {
		return nil, err
	}
	sealed, err := os.ReadFile(b.path(keyID))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, keyID)
		}
		return nil, fmt.Errorf("keystore: reading key file: %w", err)
	}
	priv, err := Unseal(sealed, passphrase)
	if err != nil {
		return nil, err
	}
	defer zero(priv.Seed)
	return priv.Signer()
}

// Delete removes a sealed key.
func (b *FileBackend) Delete(keyID string) error {
	if err := validateKeyID(keyID); err != nil {
		return err
	}
	if err := os.Remove(b.path(keyID)); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%w: %s", ErrKeyNotFound, keyID)
		}
		return fmt.Errorf("keystore: deleting key file: %w", err)
	}
	return nil
}

// Has reports whether a sealed key exists.
func (b *FileBackend) Has(keyID string) (bool, error) {
	if err := validateKeyID(keyID); err != nil {
		return false, err
	}
	_, err := os.Stat(b.path(keyID))
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	default:
		return false, fmt.Errorf("keystore: stat key file: %w", err)
	}
}

var _ Backend = (*FileBackend)(nil)
