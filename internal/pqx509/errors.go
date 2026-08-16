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
	// ErrExpired reports a certificate whose NotAfter has passed.
	ErrExpired = errors.New("pqx509: certificate has expired")
	// ErrNotYetValid reports a certificate whose NotBefore is in the future.
	ErrNotYetValid = errors.New("pqx509: certificate is not yet valid")
	// ErrUnknownAuthority reports that no chain to a configured root was found.
	ErrUnknownAuthority = errors.New("pqx509: unknown certificate authority")
	// ErrNotACA reports an issuer without basicConstraints cA=TRUE.
	ErrNotACA = errors.New("pqx509: issuer is not a CA")
	// ErrPathLenExceeded reports a chain longer than a pathLenConstraint allows.
	ErrPathLenExceeded = errors.New("pqx509: pathLenConstraint exceeded")
	// ErrKeyUsageNotPermitted reports an issuer lacking keyCertSign.
	ErrKeyUsageNotPermitted = errors.New("pqx509: key usage does not permit this operation")
	// ErrRevoked reports a certificate rejected by a revocation check.
	ErrRevoked = errors.New("pqx509: certificate has been revoked")
)
