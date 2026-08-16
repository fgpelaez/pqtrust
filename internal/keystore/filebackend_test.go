package keystore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/fernando/pqtrust/internal/pqx509"
)

func newTestBackend(t *testing.T) *FileBackend {
	t.Helper()
	b, err := NewFileBackend(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestFileBackendGenerateLoad(t *testing.T) {
	b := newTestBackend(t)
	pass := []byte("s3cret")

	keyID, pub, priv, err := b.Generate(pqx509.MLDSA65, pass)
	if err != nil {
		t.Fatal(err)
	}
	if len(keyID) != 32 {
		t.Errorf("key ID = %q, want 32 hex characters", keyID)
	}
	if priv.Algorithm != pqx509.MLDSA65 || len(priv.Seed) != 32 {
		t.Errorf("returned private key = %+v", priv.Algorithm)
	}

	ok, err := b.Has(keyID)
	if err != nil || !ok {
		t.Errorf("Has(%q) = %v, %v", keyID, ok, err)
	}

	signer, err := b.Load(keyID, pass)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(signer.Public().Bytes, pub.Bytes) {
		t.Error("loaded signer public key differs from the generated one")
	}
	if signer.Algorithm() != pqx509.MLDSA65 {
		t.Errorf("signer algorithm = %v", signer.Algorithm())
	}
	msg := []byte("sign me")
	sig, err := signer.Sign(nil, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := pqx509.Verify(pub, msg, sig); err != nil {
		t.Errorf("signature from a loaded key must verify: %v", err)
	}
}

func TestFileBackendWrongPassphrase(t *testing.T) {
	b := newTestBackend(t)
	keyID, _, _, err := b.Generate(pqx509.MLDSA44, []byte("right"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Load(keyID, []byte("wrong")); !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("want ErrWrongPassphrase, got %v", err)
	}
}

func TestFileBackendMissingKey(t *testing.T) {
	b := newTestBackend(t)
	if _, err := b.Load("0123456789abcdef0123456789abcdef", []byte("pw")); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("want ErrKeyNotFound, got %v", err)
	}
	ok, err := b.Has("0123456789abcdef0123456789abcdef")
	if err != nil || ok {
		t.Errorf("Has on a missing key = %v, %v", ok, err)
	}
}

func TestFileBackendStoreRejectsDuplicate(t *testing.T) {
	b := newTestBackend(t)
	_, _, priv, err := b.Generate(pqx509.MLDSA44, []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	id, err := NewKeyID()
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Store(id, priv, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	if err := b.Store(id, priv, []byte("pw")); !errors.Is(err, ErrKeyExists) {
		t.Errorf("want ErrKeyExists, got %v", err)
	}
}

func TestFileBackendDelete(t *testing.T) {
	b := newTestBackend(t)
	keyID, _, _, _ := b.Generate(pqx509.MLDSA44, []byte("pw"))
	if err := b.Delete(keyID); err != nil {
		t.Fatal(err)
	}
	if ok, _ := b.Has(keyID); ok {
		t.Error("key must be gone after Delete")
	}
	if err := b.Delete(keyID); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("deleting a missing key: want ErrKeyNotFound, got %v", err)
	}
}

func TestFileBackendFilePermissions(t *testing.T) {
	dir := t.TempDir()
	b, err := NewFileBackend(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	keyID, _, _, err := b.Generate(pqx509.MLDSA44, []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "keys", keyID+".key"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file mode = %#o, want 0600", perm)
	}
	dirInfo, err := os.Stat(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Errorf("key directory mode = %#o, want 0700", perm)
	}
}

func TestFileBackendRejectsUnsafeKeyID(t *testing.T) {
	b := newTestBackend(t)
	_, _, priv, _ := b.Generate(pqx509.MLDSA44, []byte("pw"))
	for _, id := range []string{"../escape", "with/slash", "", "UPPERCASE", "short"} {
		if err := b.Store(id, priv, []byte("pw")); err == nil {
			t.Errorf("Store(%q) must be rejected", id)
		}
	}
}
