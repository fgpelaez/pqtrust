// Command parsecsr parses a PEM PKCS#10 CSR with pqtrust's own X.509 layer and
// verifies its self-signature. It exists so the interop script can prove we
// read third-party CSRs.
package main

import (
	"encoding/pem"
	"fmt"
	"os"

	"github.com/fgpelaez/pqtrust/internal/pqx509"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: parsecsr <request.pem>")
		os.Exit(2)
	}
	pemBytes, err := os.ReadFile(os.Args[1]) //nolint:gosec // this CLI intentionally reads the user-selected CSR
	if err != nil {
		fmt.Fprintln(os.Stderr, "parsecsr:", err)
		os.Exit(1)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		fmt.Fprintln(os.Stderr, "parsecsr: want a CERTIFICATE REQUEST PEM block")
		os.Exit(1)
	}
	csr, err := pqx509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "parsecsr:", err)
		os.Exit(1)
	}
	if err := csr.CheckSignature(); err != nil {
		fmt.Fprintln(os.Stderr, "parsecsr: self-signature does not verify:", err)
		os.Exit(1)
	}
	fmt.Printf("parsed %s CSR: subject=%q dns=%v ips=%v emails=%v; self-signature verified\n",
		csr.PublicKey.Algorithm, csr.Subject, csr.DNSNames, csr.IPAddresses, csr.EmailAddresses)
}
