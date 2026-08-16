// Package ca holds pqtrust's domain logic: what may be issued, by whom, and for
// how long. It builds certificates with pqx509, keeps keys in a keystore.Backend
// and records state through store.
package ca

import (
	"errors"
	"fmt"
	"time"

	"github.com/fernando/pqtrust/internal/pqx509"
)

var (
	// ErrConstraintViolation reports a request that policy forbids.
	ErrConstraintViolation = errors.New("ca: constraint violation")
	// ErrNotFound reports an unknown CA or certificate.
	ErrNotFound = errors.New("ca: not found")
	// ErrAlreadyRevoked reports a second revocation of the same certificate.
	ErrAlreadyRevoked = errors.New("ca: certificate is already revoked")
)

// Profile defaults, in days.
const (
	rootValidityDays         = 3650
	intermediateValidityDays = 1825
	endEntityValidityDays    = 90
	maxEndEntityValidityDays = 397
)

// clockSkew backdates NotBefore so that a freshly issued certificate is usable
// on a verifier whose clock is slightly behind.
const clockSkew = 5 * time.Minute

type caProfile struct {
	algorithm   pqx509.Algorithm
	pathLen     int
	keyUsage    pqx509.KeyUsage
	defaultDays int
	maxDays     int
}

var (
	rootProfile = caProfile{
		algorithm:   pqx509.MLDSA87,
		pathLen:     1,
		keyUsage:    pqx509.KeyUsageKeyCertSign | pqx509.KeyUsageCRLSign,
		defaultDays: rootValidityDays,
		maxDays:     rootValidityDays,
	}
	intermediateProfile = caProfile{
		algorithm:   pqx509.MLDSA65,
		pathLen:     0,
		keyUsage:    pqx509.KeyUsageKeyCertSign | pqx509.KeyUsageCRLSign,
		defaultDays: intermediateValidityDays,
		maxDays:     intermediateValidityDays,
	}
)

func (p caProfile) checkAlgorithm(alg pqx509.Algorithm) error {
	if alg != p.algorithm {
		return fmt.Errorf("%w: this CA level requires %v, got %v", ErrConstraintViolation, p.algorithm, alg)
	}
	return nil
}

func (p caProfile) resolveDays(requested int) (int, error) {
	if requested == 0 {
		return p.defaultDays, nil
	}
	if requested < 0 {
		return 0, fmt.Errorf("%w: validity must be positive, got %d days", ErrConstraintViolation, requested)
	}
	if requested > p.maxDays {
		return 0, fmt.Errorf("%w: validity %d days exceeds the %d day maximum for this CA level",
			ErrConstraintViolation, requested, p.maxDays)
	}
	return requested, nil
}

func checkEndEntityAlgorithm(alg pqx509.Algorithm) error {
	switch alg {
	case pqx509.MLDSA44, pqx509.MLDSA65:
		return nil
	default:
		return fmt.Errorf("%w: end-entity certificates support ML-DSA-44 and ML-DSA-65, got %v", ErrConstraintViolation, alg)
	}
}

func checkExtKeyUsage(ekus []pqx509.ExtKeyUsage) error {
	for _, e := range ekus {
		switch e {
		case pqx509.ExtKeyUsageServerAuth, pqx509.ExtKeyUsageClientAuth:
		default:
			return fmt.Errorf("%w: unsupported extended key usage %v", ErrConstraintViolation, e)
		}
	}
	return nil
}
