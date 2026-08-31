// Command parsecert parses a PEM certificate with pqtrust's own X.509 layer.
// It exists so that the interop script can prove we read third-party output.
package main

import (
	"fmt"
	"os"

	"github.com/fgpelaez/pqtrust/internal/pqx509"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: parsecert <certificate.pem>")
		os.Exit(2)
	}
	pemBytes, err := os.ReadFile(os.Args[1]) //nolint:gosec // this CLI intentionally reads the user-selected certificate
	if err != nil {
		fmt.Fprintln(os.Stderr, "parsecert:", err)
		os.Exit(1)
	}
	der, err := pqx509.DecodeCertificatePEM(pemBytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "parsecert:", err)
		os.Exit(1)
	}
	cert, err := pqx509.ParseCertificate(der)
	if err != nil {
		fmt.Fprintln(os.Stderr, "parsecert:", err)
		os.Exit(1)
	}
	fmt.Printf("parsed %s certificate: subject=%q issuer=%q serial=%s notAfter=%s\n",
		cert.SignatureAlgorithm, cert.Subject, cert.Issuer, cert.SerialNumber.Text(16), cert.NotAfter)
	if cert.IsSelfSigned() {
		if err := cert.VerifySignatureFrom(cert); err != nil {
			fmt.Fprintln(os.Stderr, "parsecert: self-signature does not verify:", err)
			os.Exit(1)
		}
		fmt.Println("self-signature verified")
	}
}
