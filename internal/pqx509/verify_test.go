package pqx509

import (
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

type testHierarchy struct {
	root        *Certificate
	rootSigner  Signer
	inter       *Certificate
	interSigner Signer
	leaf        *Certificate
}

func issue(t *testing.T, tmpl, parent *Certificate, pub PublicKey, signer Signer) *Certificate {
	t.Helper()
	der, err := CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

func buildHierarchy(t *testing.T) testHierarchy {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)

	root, rootSigner := testCA(t, MLDSA87, 1)

	interPub, interPriv, _ := GenerateKey(rand.Reader, MLDSA65)
	interSigner, err := interPriv.Signer()
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := GenerateSerialNumber(rand.Reader)
	inter := issue(t, &Certificate{
		SerialNumber:          serial,
		SignatureAlgorithm:    MLDSA87,
		Subject:               Name{CommonName: "pqtrust Test Intermediate"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(5 * 365 * 24 * time.Hour),
		BasicConstraints:      BasicConstraints{IsCA: true, MaxPathLen: 0, MaxPathLenSet: true},
		BasicConstraintsValid: true,
		KeyUsage:              KeyUsageKeyCertSign | KeyUsageCRLSign,
	}, root, interPub, rootSigner)

	leafPub, _, _ := GenerateKey(rand.Reader, MLDSA44)
	serial2, _ := GenerateSerialNumber(rand.Reader)
	leaf := issue(t, &Certificate{
		SerialNumber:          serial2,
		SignatureAlgorithm:    MLDSA65,
		Subject:               Name{CommonName: "api.example.com"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(397 * 24 * time.Hour),
		BasicConstraints:      BasicConstraints{IsCA: false},
		BasicConstraintsValid: true,
		KeyUsage:              KeyUsageDigitalSignature,
		ExtKeyUsage:           []ExtKeyUsage{ExtKeyUsageServerAuth},
		SANs:                  SANs{DNSNames: []string{"api.example.com"}},
	}, inter, leafPub, interSigner)

	return testHierarchy{root: root, rootSigner: rootSigner, inter: inter, interSigner: interSigner, leaf: leaf}
}

func TestVerifySignatureFrom(t *testing.T) {
	h := buildHierarchy(t)
	if err := h.leaf.VerifySignatureFrom(h.inter); err != nil {
		t.Errorf("leaf under intermediate: %v", err)
	}
	if err := h.inter.VerifySignatureFrom(h.root); err != nil {
		t.Errorf("intermediate under root: %v", err)
	}
	if err := h.root.VerifySignatureFrom(h.root); err != nil {
		t.Errorf("self-signed root: %v", err)
	}
	if err := h.leaf.VerifySignatureFrom(h.root); !errors.Is(err, ErrBadSignature) {
		t.Errorf("leaf under root should fail with ErrBadSignature, got %v", err)
	}
}

func TestVerifyBuildsFullChain(t *testing.T) {
	h := buildHierarchy(t)
	chains, err := h.leaf.Verify(VerifyOptions{
		Roots:         []*Certificate{h.root},
		Intermediates: []*Certificate{h.inter},
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(chains) != 1 {
		t.Fatalf("got %d chains, want 1", len(chains))
	}
	chain := chains[0]
	if len(chain) != 3 {
		t.Fatalf("chain length = %d, want 3", len(chain))
	}
	if chain[0] != h.leaf || chain[1] != h.inter || chain[2] != h.root {
		t.Error("chain must be leaf, intermediate, root")
	}
}

func TestVerifyUnknownAuthority(t *testing.T) {
	h := buildHierarchy(t)
	if _, err := h.leaf.Verify(VerifyOptions{Roots: []*Certificate{h.root}}); !errors.Is(err, ErrUnknownAuthority) {
		t.Errorf("missing intermediate should yield ErrUnknownAuthority, got %v", err)
	}
	other, _ := testCA(t, MLDSA87, 1)
	if _, err := h.inter.Verify(VerifyOptions{Roots: []*Certificate{other}}); err == nil {
		t.Error("an unrelated root must not validate the intermediate")
	}
}

func TestVerifyExpiredAndNotYetValid(t *testing.T) {
	h := buildHierarchy(t)
	opts := VerifyOptions{Roots: []*Certificate{h.root}, Intermediates: []*Certificate{h.inter}}

	past := opts
	past.CurrentTime = h.leaf.NotBefore.Add(-time.Hour)
	if _, err := h.leaf.Verify(past); !errors.Is(err, ErrNotYetValid) {
		t.Errorf("want ErrNotYetValid, got %v", err)
	}

	future := opts
	future.CurrentTime = h.leaf.NotAfter.Add(time.Hour)
	if _, err := h.leaf.Verify(future); !errors.Is(err, ErrExpired) {
		t.Errorf("want ErrExpired, got %v", err)
	}
}

func TestVerifyRejectsNonCAIssuer(t *testing.T) {
	h := buildHierarchy(t)
	now := time.Now().UTC().Truncate(time.Second)

	badPub, badPriv, _ := GenerateKey(rand.Reader, MLDSA44)
	_ = badPub
	badSigner, _ := badPriv.Signer()

	serial, _ := GenerateSerialNumber(rand.Reader)
	nonCA := issue(t, &Certificate{
		SerialNumber:          serial,
		SignatureAlgorithm:    MLDSA65,
		Subject:               Name{CommonName: "not-a-ca"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		BasicConstraints:      BasicConstraints{IsCA: false},
		BasicConstraintsValid: true,
		KeyUsage:              KeyUsageDigitalSignature,
	}, h.inter, badSigner.Public(), h.interSigner)

	childPub, _, _ := GenerateKey(rand.Reader, MLDSA44)
	serial2, _ := GenerateSerialNumber(rand.Reader)
	child := issue(t, &Certificate{
		SerialNumber:          serial2,
		SignatureAlgorithm:    MLDSA44,
		Subject:               Name{CommonName: "child-of-non-ca"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		BasicConstraints:      BasicConstraints{IsCA: false},
		BasicConstraintsValid: true,
		KeyUsage:              KeyUsageDigitalSignature,
	}, nonCA, childPub, badSigner)

	_, err := child.Verify(VerifyOptions{
		Roots:         []*Certificate{h.root},
		Intermediates: []*Certificate{h.inter, nonCA},
	})
	if !errors.Is(err, ErrNotACA) && !errors.Is(err, ErrUnknownAuthority) {
		t.Errorf("want ErrNotACA (or ErrUnknownAuthority once the branch is pruned), got %v", err)
	}
}

func TestVerifyRejectsIssuerWithoutKeyCertSign(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	root, rootSigner := testCA(t, MLDSA87, 1)

	interPub, interPriv, _ := GenerateKey(rand.Reader, MLDSA65)
	interSigner, _ := interPriv.Signer()
	serial, _ := GenerateSerialNumber(rand.Reader)
	inter := issue(t, &Certificate{
		SerialNumber:          serial,
		SignatureAlgorithm:    MLDSA87,
		Subject:               Name{CommonName: "crl-only CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		BasicConstraints:      BasicConstraints{IsCA: true, MaxPathLen: 0, MaxPathLenSet: true},
		BasicConstraintsValid: true,
		KeyUsage:              KeyUsageCRLSign,
	}, root, interPub, rootSigner)

	leafPub, _, _ := GenerateKey(rand.Reader, MLDSA44)
	serial2, _ := GenerateSerialNumber(rand.Reader)
	leaf := issue(t, &Certificate{
		SerialNumber:          serial2,
		SignatureAlgorithm:    MLDSA65,
		Subject:               Name{CommonName: "leaf"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		BasicConstraints:      BasicConstraints{IsCA: false},
		BasicConstraintsValid: true,
		KeyUsage:              KeyUsageDigitalSignature,
	}, inter, leafPub, interSigner)

	_, err := leaf.Verify(VerifyOptions{Roots: []*Certificate{root}, Intermediates: []*Certificate{inter}})
	if !errors.Is(err, ErrKeyUsageNotPermitted) && !errors.Is(err, ErrUnknownAuthority) {
		t.Errorf("want ErrKeyUsageNotPermitted, got %v", err)
	}
}

func TestVerifyRejectsPathLenViolation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	root, rootSigner := testCA(t, MLDSA87, 0)

	interPub, interPriv, _ := GenerateKey(rand.Reader, MLDSA65)
	interSigner, _ := interPriv.Signer()
	s1, _ := GenerateSerialNumber(rand.Reader)
	inter := issue(t, &Certificate{
		SerialNumber:          s1,
		SignatureAlgorithm:    MLDSA87,
		Subject:               Name{CommonName: "inter-1"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		BasicConstraints:      BasicConstraints{IsCA: true, MaxPathLen: 0, MaxPathLenSet: true},
		BasicConstraintsValid: true,
		KeyUsage:              KeyUsageKeyCertSign | KeyUsageCRLSign,
	}, root, interPub, rootSigner)

	inter2Pub, inter2Priv, _ := GenerateKey(rand.Reader, MLDSA65)
	inter2Signer, _ := inter2Priv.Signer()
	s2, _ := GenerateSerialNumber(rand.Reader)
	inter2 := issue(t, &Certificate{
		SerialNumber:          s2,
		SignatureAlgorithm:    MLDSA65,
		Subject:               Name{CommonName: "inter-2"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		BasicConstraints:      BasicConstraints{IsCA: true},
		BasicConstraintsValid: true,
		KeyUsage:              KeyUsageKeyCertSign | KeyUsageCRLSign,
	}, inter, inter2Pub, interSigner)

	leafPub, _, _ := GenerateKey(rand.Reader, MLDSA44)
	s3, _ := GenerateSerialNumber(rand.Reader)
	leaf := issue(t, &Certificate{
		SerialNumber:          s3,
		SignatureAlgorithm:    MLDSA65,
		Subject:               Name{CommonName: "deep-leaf"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		BasicConstraints:      BasicConstraints{IsCA: false},
		BasicConstraintsValid: true,
		KeyUsage:              KeyUsageDigitalSignature,
	}, inter2, leafPub, inter2Signer)

	_, err := leaf.Verify(VerifyOptions{Roots: []*Certificate{root}, Intermediates: []*Certificate{inter, inter2}})
	if !errors.Is(err, ErrPathLenExceeded) && !errors.Is(err, ErrUnknownAuthority) {
		t.Errorf("want ErrPathLenExceeded, got %v", err)
	}
}

func TestVerifyCheckRevocationHook(t *testing.T) {
	h := buildHierarchy(t)
	called := 0
	_, err := h.leaf.Verify(VerifyOptions{
		Roots:         []*Certificate{h.root},
		Intermediates: []*Certificate{h.inter},
		CheckRevocation: func(cert, _ *Certificate) error {
			called++
			if cert.Subject.CommonName == "api.example.com" {
				return ErrRevoked
			}
			return nil
		},
	})
	if !errors.Is(err, ErrRevoked) {
		t.Errorf("want ErrRevoked, got %v", err)
	}
	if called == 0 {
		t.Error("CheckRevocation was never called")
	}
}
