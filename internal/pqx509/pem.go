package pqx509

import (
	"bytes"
	"encoding/pem"
	"fmt"
)

const (
	pemTypeCertificate = "CERTIFICATE"
	pemTypeCRL         = "X509 CRL"
	pemTypePrivateKey  = "PRIVATE KEY"
	pemTypeLegacyKey   = "PQTRUST ML-DSA PRIVATE KEY"
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

// EncodePrivateKeyPEM wraps a PKCS#8-encoded private key in a PEM block.
func EncodePrivateKeyPEM(priv PrivateKey) ([]byte, error) {
	der, err := MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("pqx509: encoding private key PEM: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemTypePrivateKey, Bytes: der}), nil
}

// DecodePrivateKeyPEM reads a PKCS#8 "PRIVATE KEY" block or the legacy
// Phase 1 "PQTRUST ML-DSA PRIVATE KEY" block (raw seed + Algorithm header).
func DecodePrivateKeyPEM(pemBytes []byte) (PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return PrivateKey{}, fmt.Errorf("pqx509: no PEM block found")
	}
	switch block.Type {
	case pemTypePrivateKey:
		priv, err := ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return PrivateKey{}, fmt.Errorf("pqx509: private key PEM: %w", err)
		}
		return priv, nil
	case pemTypeLegacyKey:
		alg, err := ParseAlgorithm(block.Headers["Algorithm"])
		if err != nil {
			return PrivateKey{}, fmt.Errorf("pqx509: legacy private key PEM algorithm header: %w", err)
		}
		if len(block.Bytes) != 32 {
			return PrivateKey{}, fmt.Errorf("%w: legacy seed is %d bytes, want 32", ErrInvalidKeySize, len(block.Bytes))
		}
		return PrivateKey{Algorithm: alg, Seed: bytes.Clone(block.Bytes)}, nil
	default:
		return PrivateKey{}, fmt.Errorf("pqx509: PEM block type is %q, want %q", block.Type, pemTypePrivateKey)
	}
}
