package keystore

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"

	"github.com/fgpelaez/pqtrust/internal/pqx509"
)

func TestSealUnsealRoundTrip(t *testing.T) {
	for _, alg := range []pqx509.Algorithm{pqx509.MLDSA44, pqx509.MLDSA65, pqx509.MLDSA87} {
		t.Run(alg.String(), func(t *testing.T) {
			_, priv, err := pqx509.GenerateKey(rand.Reader, alg)
			if err != nil {
				t.Fatal(err)
			}
			sealed, err := Seal(priv, []byte("correct horse battery staple"))
			if err != nil {
				t.Fatal(err)
			}
			// The seed must not appear anywhere in the sealed blob.
			if bytes.Contains(sealed, priv.Seed) {
				t.Fatal("sealed blob leaks the raw seed")
			}
			back, err := Unseal(sealed, []byte("correct horse battery staple"))
			if err != nil {
				t.Fatal(err)
			}
			if back.Algorithm != priv.Algorithm || !bytes.Equal(back.Seed, priv.Seed) {
				t.Error("unsealed key does not match the original")
			}
		})
	}
}

func TestUnsealWrongPassphrase(t *testing.T) {
	_, priv, _ := pqx509.GenerateKey(rand.Reader, pqx509.MLDSA44)
	sealed, err := Seal(priv, []byte("right"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Unseal(sealed, []byte("wrong")); !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("want ErrWrongPassphrase, got %v", err)
	}
}

func TestSealRejectsEmptyPassphrase(t *testing.T) {
	_, priv, _ := pqx509.GenerateKey(rand.Reader, pqx509.MLDSA44)
	if _, err := Seal(priv, nil); !errors.Is(err, ErrEmptyPassphrase) {
		t.Errorf("want ErrEmptyPassphrase, got %v", err)
	}
}

func TestSealUsesDistinctSaltAndNonce(t *testing.T) {
	_, priv, _ := pqx509.GenerateKey(rand.Reader, pqx509.MLDSA44)
	a, _ := Seal(priv, []byte("pw"))
	b, _ := Seal(priv, []byte("pw"))
	if bytes.Equal(a, b) {
		t.Fatal("sealing the same key twice must not produce identical output")
	}

	var ea, eb map[string]any
	if err := json.Unmarshal(a, &ea); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &eb); err != nil {
		t.Fatal(err)
	}
	if ea["salt"] == eb["salt"] {
		t.Error("salt must be random per seal")
	}
	if ea["nonce"] == eb["nonce"] {
		t.Error("nonce must be random per seal")
	}
	if ea["kdf"] != "argon2id" || ea["v"] != float64(1) {
		t.Errorf("unexpected envelope header: %v", ea)
	}
}

func TestUnsealDetectsTampering(t *testing.T) {
	_, priv, _ := pqx509.GenerateKey(rand.Reader, pqx509.MLDSA44)
	sealed, _ := Seal(priv, []byte("pw"))

	var env map[string]any
	if err := json.Unmarshal(sealed, &env); err != nil {
		t.Fatal(err)
	}
	// Claim a different algorithm: the AAD binding must make this fail.
	env["alg"] = "ML-DSA-87"
	tampered, _ := json.Marshal(env)
	if _, err := Unseal(tampered, []byte("pw")); err == nil {
		t.Error("tampering with the algorithm field must be detected")
	}
}

func TestUnsealRejectsGarbage(t *testing.T) {
	if _, err := Unseal([]byte("not json"), []byte("pw")); err == nil {
		t.Error("garbage input must be rejected")
	}
}
