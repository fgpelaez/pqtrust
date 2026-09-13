// Command mkcsr generates an ML-DSA-44 key pair and a PKCS#10 CSR for the
// interop script: writes pqtrust-csr.pem (CERTIFICATE REQUEST) and
// pqtrust-key.pem (PKCS#8 PRIVATE KEY) into -dir.
package main

import (
	"crypto/rand"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fgpelaez/pqtrust/internal/pqx509"
)

func main() {
	dir := flag.String("dir", ".", "output directory")
	flag.Parse()

	pub, priv, err := pqx509.GenerateKey(rand.Reader, pqx509.MLDSA44)
	if err != nil {
		fail(err)
	}
	signer, err := priv.Signer()
	if err != nil {
		fail(err)
	}
	der, err := pqx509.CreateCertificateRequest(rand.Reader,
		pqx509.Name{CommonName: "pqtrust-csr.example.com"}, pub, signer,
		pqx509.SANs{DNSNames: []string{"pqtrust-csr.example.com"}})
	if err != nil {
		fail(err)
	}
	keyPEM, err := pqx509.EncodePrivateKeyPEM(priv)
	if err != nil {
		fail(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	if err := os.WriteFile(filepath.Join(*dir, "pqtrust-csr.pem"), csrPEM, 0o600); err != nil {
		fail(err)
	}
	if err := os.WriteFile(filepath.Join(*dir, "pqtrust-key.pem"), keyPEM, 0o600); err != nil {
		fail(err)
	}
	fmt.Println("mkcsr: wrote pqtrust-csr.pem and pqtrust-key.pem to", *dir)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "mkcsr:", err)
	os.Exit(1)
}
