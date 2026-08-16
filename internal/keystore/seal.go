// Package keystore generates post-quantum private keys and stores them sealed
// with AES-256-GCM under an Argon2id-derived key.
package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"

	"github.com/fernando/pqtrust/internal/pqx509"
)

var (
	// ErrWrongPassphrase reports that a sealed key could not be authenticated.
	ErrWrongPassphrase = errors.New("keystore: wrong passphrase or corrupted key material")
	// ErrKeyNotFound reports an unknown key ID.
	ErrKeyNotFound = errors.New("keystore: key not found")
	// ErrKeyExists reports an attempt to overwrite an existing key.
	ErrKeyExists = errors.New("keystore: key already exists")
	// ErrEmptyPassphrase reports a missing passphrase.
	ErrEmptyPassphrase = errors.New("keystore: passphrase must not be empty")
)

// Argon2id parameters. Changing these requires bumping envelopeVersion.
const (
	argonTime    uint32 = 3
	argonMemory  uint32 = 64 * 1024 // KiB
	argonThreads uint8  = 2
	argonKeyLen  uint32 = 32
	saltSize            = 16

	envelopeVersion = 1
)

type envelope struct {
	Version int    `json:"v"`
	Alg     string `json:"alg"`
	KDF     string `json:"kdf"`
	Time    uint32 `json:"t"`
	Memory  uint32 `json:"m"`
	Threads uint8  `json:"p"`
	Salt    []byte `json:"salt"`
	Nonce   []byte `json:"nonce"`
	Cipher  []byte `json:"ct"`
}

func aad(alg string) []byte {
	return []byte(fmt.Sprintf("pqtrust-sealed-key-v%d|%s", envelopeVersion, alg))
}

// Seal encrypts priv's seed under a key derived from passphrase.
func Seal(priv pqx509.PrivateKey, passphrase []byte) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, ErrEmptyPassphrase
	}
	if !priv.Algorithm.Valid() {
		return nil, fmt.Errorf("keystore: %w: %v", pqx509.ErrUnknownAlgorithm, priv.Algorithm)
	}
	if len(priv.Seed) != 32 {
		return nil, fmt.Errorf("keystore: %w: seed is %d bytes, want 32", pqx509.ErrInvalidKeySize, len(priv.Seed))
	}

	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("keystore: reading salt: %w", err)
	}
	key := argon2.IDKey(passphrase, salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	defer zero(key)

	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("keystore: reading nonce: %w", err)
	}
	algName := priv.Algorithm.String()
	ct := gcm.Seal(nil, nonce, priv.Seed, aad(algName))

	blob, err := json.Marshal(envelope{
		Version: envelopeVersion,
		Alg:     algName,
		KDF:     "argon2id",
		Time:    argonTime,
		Memory:  argonMemory,
		Threads: argonThreads,
		Salt:    salt,
		Nonce:   nonce,
		Cipher:  ct,
	})
	if err != nil {
		return nil, fmt.Errorf("keystore: marshaling envelope: %w", err)
	}
	return blob, nil
}

// Unseal decrypts a sealed key produced by Seal.
func Unseal(sealed, passphrase []byte) (pqx509.PrivateKey, error) {
	if len(passphrase) == 0 {
		return pqx509.PrivateKey{}, ErrEmptyPassphrase
	}
	var env envelope
	if err := json.Unmarshal(sealed, &env); err != nil {
		return pqx509.PrivateKey{}, fmt.Errorf("keystore: parsing sealed key: %w", err)
	}
	if env.Version != envelopeVersion {
		return pqx509.PrivateKey{}, fmt.Errorf("keystore: unsupported sealed key version %d", env.Version)
	}
	if env.KDF != "argon2id" {
		return pqx509.PrivateKey{}, fmt.Errorf("keystore: unsupported KDF %q", env.KDF)
	}
	alg, err := pqx509.ParseAlgorithm(env.Alg)
	if err != nil {
		return pqx509.PrivateKey{}, fmt.Errorf("keystore: %w", err)
	}
	if env.Threads == 0 || env.Time == 0 || env.Memory == 0 || len(env.Salt) == 0 || len(env.Nonce) == 0 {
		return pqx509.PrivateKey{}, fmt.Errorf("keystore: incomplete sealed key envelope")
	}

	key := argon2.IDKey(passphrase, env.Salt, env.Time, env.Memory, env.Threads, argonKeyLen)
	defer zero(key)

	gcm, err := newGCM(key)
	if err != nil {
		return pqx509.PrivateKey{}, err
	}
	if len(env.Nonce) != gcm.NonceSize() {
		return pqx509.PrivateKey{}, fmt.Errorf("keystore: nonce is %d bytes, want %d", len(env.Nonce), gcm.NonceSize())
	}
	seed, err := gcm.Open(nil, env.Nonce, env.Cipher, aad(env.Alg))
	if err != nil {
		return pqx509.PrivateKey{}, ErrWrongPassphrase
	}
	if len(seed) != 32 {
		zero(seed)
		return pqx509.PrivateKey{}, fmt.Errorf("keystore: %w: sealed seed is %d bytes", pqx509.ErrInvalidKeySize, len(seed))
	}
	return pqx509.PrivateKey{Algorithm: alg, Seed: seed}, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("keystore: creating AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("keystore: creating GCM: %w", err)
	}
	return gcm, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
