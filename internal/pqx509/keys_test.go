package pqx509

import (
	"bytes"
	"crypto/rand"
	"encoding/asn1"
	"testing"
)

func TestGenerateSignVerify(t *testing.T) {
	for _, alg := range []Algorithm{MLDSA44, MLDSA65, MLDSA87} {
		t.Run(alg.String(), func(t *testing.T) {
			pub, priv, err := GenerateKey(rand.Reader, alg)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			if len(pub.Bytes) != alg.PublicKeySize() {
				t.Fatalf("public key size = %d, want %d", len(pub.Bytes), alg.PublicKeySize())
			}
			if len(priv.Seed) != 32 {
				t.Fatalf("seed size = %d, want 32", len(priv.Seed))
			}
			signer, err := priv.Signer()
			if err != nil {
				t.Fatalf("Signer: %v", err)
			}
			if !bytes.Equal(signer.Public().Bytes, pub.Bytes) {
				t.Fatal("signer public key does not match generated public key")
			}
			msg := []byte("pqtrust test message")
			sig, err := signer.Sign(rand.Reader, msg)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if len(sig) != alg.SignatureSize() {
				t.Fatalf("signature size = %d, want %d", len(sig), alg.SignatureSize())
			}
			if err := Verify(pub, msg, sig); err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if err := Verify(pub, []byte("other message"), sig); err == nil {
				t.Fatal("Verify must fail on a different message")
			}
			sig[0] ^= 0xff
			if err := Verify(pub, msg, sig); err == nil {
				t.Fatal("Verify must fail on a corrupted signature")
			}
		})
	}
}

func TestSPKIRoundTripAndEncoding(t *testing.T) {
	pub, _, err := GenerateKey(rand.Reader, MLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	der, err := MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatal(err)
	}
	if back.Algorithm != pub.Algorithm || !bytes.Equal(back.Bytes, pub.Bytes) {
		t.Fatal("SPKI round-trip mismatch")
	}

	// The AlgorithmIdentifier must carry NO parameters (not even NULL).
	var spki subjectPublicKeyInfo
	rest, err := asn1.Unmarshal(der, &spki)
	if err != nil || len(rest) != 0 {
		t.Fatalf("unmarshal spki: %v, rest=%d", err, len(rest))
	}
	if len(spki.Algorithm.Parameters.FullBytes) != 0 {
		t.Errorf("AlgorithmIdentifier.parameters must be absent, got % x", spki.Algorithm.Parameters.FullBytes)
	}
	// The public key must be raw in the BIT STRING, with no unused bits.
	if !bytes.Equal(spki.PublicKey.Bytes, pub.Bytes) {
		t.Error("public key must sit raw in the SPKI BIT STRING")
	}
	if spki.PublicKey.BitLength != len(pub.Bytes)*8 {
		t.Errorf("BitLength = %d, want %d", spki.PublicKey.BitLength, len(pub.Bytes)*8)
	}
}

func TestParsePKIXRejectsTrailingData(t *testing.T) {
	pub, _, _ := GenerateKey(rand.Reader, MLDSA44)
	der, _ := MarshalPKIXPublicKey(pub)
	if _, err := ParsePKIXPublicKey(append(der, 0x00)); err == nil {
		t.Error("ParsePKIXPublicKey must reject trailing data")
	}
}

func TestKeyIdentifierIs20BytesAndStable(t *testing.T) {
	pub, _, _ := GenerateKey(rand.Reader, MLDSA44)
	a, err := KeyIdentifier(pub)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 20 {
		t.Fatalf("KeyIdentifier length = %d, want 20", len(a))
	}
	b, _ := KeyIdentifier(pub)
	if !bytes.Equal(a, b) {
		t.Fatal("KeyIdentifier must be deterministic")
	}
	other, _, _ := GenerateKey(rand.Reader, MLDSA44)
	c, _ := KeyIdentifier(other)
	if bytes.Equal(a, c) {
		t.Fatal("different keys must produce different identifiers")
	}
}
