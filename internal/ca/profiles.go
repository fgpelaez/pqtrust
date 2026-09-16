// Package ca holds pqtrust's domain logic: what may be issued, by whom, and for
// how long. It builds certificates with pqx509, keeps keys in a keystore.Backend
// and records state through store.
package ca

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/fgpelaez/pqtrust/internal/pqx509"
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
	allowedAlgorithms []pqx509.Algorithm
	pathLen           int
	keyUsage          pqx509.KeyUsage
	defaultDays       int
	maxDays           int
}

var (
	rootProfile = caProfile{
		allowedAlgorithms: []pqx509.Algorithm{pqx509.MLDSA87, pqx509.SLHDSA_SHA2_256s, pqx509.SLHDSA_SHAKE_256s},
		pathLen:           1,
		keyUsage:          pqx509.KeyUsageKeyCertSign | pqx509.KeyUsageCRLSign,
		defaultDays:       rootValidityDays,
		maxDays:           rootValidityDays,
	}
	intermediateProfile = caProfile{
		allowedAlgorithms: []pqx509.Algorithm{pqx509.MLDSA65, pqx509.SLHDSA_SHA2_192s, pqx509.SLHDSA_SHAKE_192s},
		pathLen:           0,
		keyUsage:          pqx509.KeyUsageKeyCertSign | pqx509.KeyUsageCRLSign,
		defaultDays:       intermediateValidityDays,
		maxDays:           intermediateValidityDays,
	}
	endEntityAlgorithms = []pqx509.Algorithm{
		pqx509.MLDSA44, pqx509.MLDSA65,
		pqx509.SLHDSA_SHA2_128s, pqx509.SLHDSA_SHA2_128f,
		pqx509.SLHDSA_SHAKE_128s, pqx509.SLHDSA_SHAKE_128f,
	}
)

func algorithmAllowed(alg pqx509.Algorithm, allowed []pqx509.Algorithm) bool {
	for _, a := range allowed {
		if alg == a {
			return true
		}
	}
	return false
}

func algorithmList(algs []pqx509.Algorithm) string {
	names := make([]string, len(algs))
	for i, a := range algs {
		names[i] = a.String()
	}
	return strings.Join(names, ", ")
}

func (p caProfile) checkAlgorithm(alg pqx509.Algorithm) error {
	if !algorithmAllowed(alg, p.allowedAlgorithms) {
		return fmt.Errorf("%w: this CA level allows %s, got %v", ErrConstraintViolation, algorithmList(p.allowedAlgorithms), alg)
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
	if !algorithmAllowed(alg, endEntityAlgorithms) {
		return fmt.Errorf("%w: end-entity certificates allow %s, got %v", ErrConstraintViolation, algorithmList(endEntityAlgorithms), alg)
	}
	return nil
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
