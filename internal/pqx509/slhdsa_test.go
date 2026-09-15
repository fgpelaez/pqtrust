package pqx509

import (
	"bytes"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"testing"
)

var allSLHDSA = []Algorithm{
	SLHDSA_SHA2_128s, SLHDSA_SHA2_128f,
	SLHDSA_SHA2_192s, SLHDSA_SHA2_192f,
	SLHDSA_SHA2_256s, SLHDSA_SHA2_256f,
	SLHDSA_SHAKE_128s, SLHDSA_SHAKE_128f,
	SLHDSA_SHAKE_192s, SLHDSA_SHAKE_192f,
	SLHDSA_SHAKE_256s, SLHDSA_SHAKE_256f,
}

func TestSLHDSAKeyLifecycle(t *testing.T) {
	msg := []byte("FIPS 205 pure mode, empty context")
	for _, alg := range allSLHDSA {
		t.Run(alg.String(), func(t *testing.T) {
			pub, priv, err := GenerateKey(rand.Reader, alg)
			if err != nil {
				t.Fatal(err)
			}
			if len(pub.Bytes) != alg.PublicKeySize() {
				t.Fatalf("public key is %d bytes, want %d", len(pub.Bytes), alg.PublicKeySize())
			}
			if len(priv.Seed) != alg.SeedSize() {
				t.Fatalf("private key material is %d bytes, want %d", len(priv.Seed), alg.SeedSize())
			}

			signer, err := priv.Signer()
			if err != nil {
				t.Fatal(err)
			}
			if signer.Algorithm() != alg {
				t.Fatalf("signer algorithm = %v, want %v", signer.Algorithm(), alg)
			}
			sig, err := signer.Sign(nil, msg)
			if err != nil {
				t.Fatal(err)
			}
			if len(sig) != alg.SignatureSize() {
				t.Fatalf("signature is %d bytes, want %d", len(sig), alg.SignatureSize())
			}
			if err := Verify(pub, msg, sig); err != nil {
				t.Fatalf("Verify rejected our own signature: %v", err)
			}

			// Deterministic signing: same key + message => identical signature.
			sig2, err := signer.Sign(nil, msg)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(sig, sig2) {
				t.Error("SLH-DSA signing must be deterministic")
			}

			// Tampered message must fail.
			if err := Verify(pub, append(msg, 'x'), sig); !errors.Is(err, ErrBadSignature) {
				t.Errorf("tampered message: want ErrBadSignature, got %v", err)
			}
			// Tampered signature must fail.
			bad := bytes.Clone(sig)
			bad[0] ^= 0xFF
			if err := Verify(pub, msg, bad); !errors.Is(err, ErrBadSignature) {
				t.Errorf("tampered signature: want ErrBadSignature, got %v", err)
			}
		})
	}
}

func TestSLHDSAKeyMaterialSizeChecks(t *testing.T) {
	for _, alg := range allSLHDSA {
		if _, err := (PrivateKey{Algorithm: alg, Seed: make([]byte, 32)}).Signer(); !errors.Is(err, ErrInvalidKeySize) {
			t.Errorf("%s: 32-byte key material: want ErrInvalidKeySize, got %v", alg, err)
		}
	}
	// A 4n SLH-DSA blob must not pass as an ML-DSA seed and vice versa.
	if _, err := (PrivateKey{Algorithm: MLDSA44, Seed: make([]byte, 64)}).Signer(); !errors.Is(err, ErrInvalidKeySize) {
		t.Errorf("ML-DSA with 64-byte seed: want ErrInvalidKeySize, got %v", err)
	}
}

func TestSLHDSASPKIAndPKCS8RoundTrip(t *testing.T) {
	for _, alg := range allSLHDSA {
		t.Run(alg.String(), func(t *testing.T) {
			pub, priv, err := GenerateKey(rand.Reader, alg)
			if err != nil {
				t.Fatal(err)
			}

			spkiDER, err := MarshalPKIXPublicKey(pub)
			if err != nil {
				t.Fatal(err)
			}
			back, err := ParsePKIXPublicKey(spkiDER)
			if err != nil {
				t.Fatal(err)
			}
			if back.Algorithm != alg || !bytes.Equal(back.Bytes, pub.Bytes) {
				t.Error("SPKI round-trip mismatch")
			}

			p8, err := MarshalPKCS8PrivateKey(priv)
			if err != nil {
				t.Fatal(err)
			}
			privBack, err := ParsePKCS8PrivateKey(p8)
			if err != nil {
				t.Fatal(err)
			}
			if privBack.Algorithm != alg || !bytes.Equal(privBack.Seed, priv.Seed) {
				t.Error("PKCS#8 round-trip mismatch")
			}
			signer, err := privBack.Signer()
			if err != nil {
				t.Fatal(err)
			}
			msg := []byte("pkcs8 round trip")
			sig, err := signer.Sign(nil, msg)
			if err != nil {
				t.Fatal(err)
			}
			if err := Verify(pub, msg, sig); err != nil {
				t.Errorf("key restored from PKCS#8 does not sign verifiably: %v", err)
			}
		})
	}
}

func TestParsePKCS8RejectsWrongSizeSLHDSA(t *testing.T) {
	// Hand-build a OneAsymmetricKey whose privateKey is 32 bytes but whose
	// algorithm is SLH-DSA-SHA2-128s (needs 64): asn1.Marshal with the right
	// OID and a 32-byte payload.
	der, err := asn1.Marshal(oneAsymmetricKey{
		Version:    0,
		Algorithm:  algorithmIdentifier{Algorithm: SLHDSA_SHA2_128s.OID()},
		PrivateKey: make([]byte, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePKCS8PrivateKey(der); !errors.Is(err, ErrInvalidKeySize) {
		t.Errorf("want ErrInvalidKeySize, got %v", err)
	}
}
