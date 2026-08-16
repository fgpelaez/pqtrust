package pqx509

import (
	"encoding/pem"
	"fmt"
)

const (
	pemTypeCertificate = "CERTIFICATE"
	pemTypeCRL         = "X509 CRL"
)

// EncodeCertificatePEM wraps a DER certificate in a PEM block.
func EncodeCertificatePEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: pemTypeCertificate, Bytes: der})
}

// EncodeCRLPEM wraps a DER CRL in a PEM block.
func EncodeCRLPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: pemTypeCRL, Bytes: der})
}

// DecodeCertificatePEM extracts the DER from the first CERTIFICATE block.
func DecodeCertificatePEM(pemBytes []byte) ([]byte, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("pqx509: no PEM block found")
	}
	if block.Type != pemTypeCertificate {
		return nil, fmt.Errorf("pqx509: PEM block type is %q, want %q", block.Type, pemTypeCertificate)
	}
	return block.Bytes, nil
}
