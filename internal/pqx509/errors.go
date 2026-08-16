// Package pqx509 builds, parses and verifies X.509 certificates and CRLs that
// carry post-quantum (ML-DSA, FIPS 204) signature algorithms. It performs no
// I/O and holds no state.
package pqx509

import "errors"

var (
	// ErrUnknownAlgorithm reports an unrecognized signature algorithm name or OID.
	ErrUnknownAlgorithm = errors.New("pqx509: unknown algorithm")
	// ErrMalformedDER reports input that is not valid DER for the expected structure.
	ErrMalformedDER = errors.New("pqx509: malformed DER")
	// ErrTrailingData reports valid DER followed by unexpected bytes.
	ErrTrailingData = errors.New("pqx509: trailing data after DER structure")
	// ErrBadSignature reports a signature that does not verify.
	ErrBadSignature = errors.New("pqx509: signature verification failed")
	// ErrUnsupportedCriticalExtension reports a critical extension pqtrust does not implement.
	ErrUnsupportedCriticalExtension = errors.New("pqx509: unsupported critical extension")
	// ErrInvalidKeySize reports key material whose length does not match its algorithm.
	ErrInvalidKeySize = errors.New("pqx509: invalid key size")
)
