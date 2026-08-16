package pqx509

import (
	"crypto/rand"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "regenerate golden fixtures")

func TestGoldenSelfSignedRoot(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "golden", "root-mldsa87.der")

	if *update {
		pub, priv, err := GenerateKey(rand.Reader, MLDSA87)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := priv.Signer()
		if err != nil {
			t.Fatal(err)
		}
		serial, _ := GenerateSerialNumber(rand.Reader)
		tmpl := &Certificate{
			SerialNumber:          serial,
			SignatureAlgorithm:    MLDSA87,
			Subject:               Name{CommonName: "pqtrust Golden Root", Organization: []string{"pqtrust"}, Country: []string{"ES"}},
			NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:              time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC),
			BasicConstraints:      BasicConstraints{IsCA: true, MaxPathLen: 1, MaxPathLenSet: true},
			BasicConstraintsValid: true,
			KeyUsage:              KeyUsageKeyCertSign | KeyUsageCRLSign,
		}
		der, err := CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, der, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Log("golden fixture regenerated")
		return
	}

	der, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden fixture (run `go test ./internal/pqx509 -update` once to create it): %v", err)
	}
	cert, err := ParseCertificate(der)
	if err != nil {
		t.Fatalf("golden certificate must parse: %v", err)
	}
	if cert.Subject.CommonName != "pqtrust Golden Root" {
		t.Errorf("CN = %q", cert.Subject.CommonName)
	}
	if !cert.NotBefore.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("NotBefore = %v", cert.NotBefore)
	}
	if err := Verify(cert.PublicKey, cert.RawTBSCertificate, cert.Signature); err != nil {
		t.Errorf("golden self-signature must verify: %v", err)
	}
}
