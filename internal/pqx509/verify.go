package pqx509

import (
	"bytes"
	"errors"
	"fmt"
	"time"
)

const maxChainDepth = 6

// VerifySignatureFrom checks c's signature against parent's public key.
func (c *Certificate) VerifySignatureFrom(parent *Certificate) error {
	if parent == nil {
		return fmt.Errorf("pqx509: parent is required")
	}
	if c.SignatureAlgorithm != parent.PublicKey.Algorithm {
		return fmt.Errorf("%w: certificate is signed with %v but the issuer key is %v",
			ErrBadSignature, c.SignatureAlgorithm, parent.PublicKey.Algorithm)
	}
	if err := Verify(parent.PublicKey, c.RawTBSCertificate, c.Signature); err != nil {
		return err
	}
	return nil
}

// VerifyOptions configures path validation.
type VerifyOptions struct {
	Roots         []*Certificate
	Intermediates []*Certificate
	// CurrentTime defaults to time.Now when zero.
	CurrentTime time.Time
	// CheckRevocation, when set, is invoked for every certificate in a
	// candidate chain together with its issuer. A non-nil error rejects it.
	CheckRevocation func(cert, issuer *Certificate) error
}

// Verify performs a simplified RFC 5280 section 6 path validation and returns
// every chain from c to a configured root. Certificate policies and name
// constraints are not implemented.
func (c *Certificate) Verify(opts VerifyOptions) ([][]*Certificate, error) {
	now := opts.CurrentTime
	if now.IsZero() {
		now = time.Now()
	}
	if err := checkValidity(c, now); err != nil {
		return nil, err
	}

	var chains [][]*Certificate
	var firstErr error
	note := func(err error) {
		if firstErr == nil && err != nil {
			firstErr = err
		}
	}

	var walk func(chain []*Certificate)
	walk = func(chain []*Certificate) {
		leaf := chain[len(chain)-1]

		for _, root := range opts.Roots {
			if !bytes.Equal(leaf.RawIssuer, root.RawSubject) {
				continue
			}
			candidate := append(append([]*Certificate{}, chain...), root)
			if err := checkLink(leaf, root, candidate, now, opts); err != nil {
				note(err)
				continue
			}
			chains = append(chains, candidate)
		}

		if len(chain) >= maxChainDepth {
			return
		}
		for _, inter := range opts.Intermediates {
			if !bytes.Equal(leaf.RawIssuer, inter.RawSubject) {
				continue
			}
			if contains(chain, inter) {
				continue
			}
			candidate := append(append([]*Certificate{}, chain...), inter)
			if err := checkLink(leaf, inter, candidate, now, opts); err != nil {
				note(err)
				continue
			}
			walk(candidate)
		}
	}
	walk([]*Certificate{c})

	if len(chains) == 0 {
		if firstErr != nil {
			return nil, firstErr
		}
		return nil, fmt.Errorf("%w: no chain to a trusted root for %q", ErrUnknownAuthority, c.Subject)
	}
	return chains, nil
}

// checkLink validates issuer as the signer of child within candidate. candidate
// is the chain including issuer, so its length gives the issuer's depth.
func checkLink(child, issuer *Certificate, candidate []*Certificate, now time.Time, opts VerifyOptions) error {
	if err := checkValidity(issuer, now); err != nil {
		return err
	}
	if !issuer.BasicConstraintsValid || !issuer.BasicConstraints.IsCA {
		return fmt.Errorf("%w: %q", ErrNotACA, issuer.Subject)
	}
	if issuer.KeyUsage != 0 && issuer.KeyUsage&KeyUsageKeyCertSign == 0 {
		return fmt.Errorf("%w: %q lacks keyCertSign", ErrKeyUsageNotPermitted, issuer.Subject)
	}
	if issuer.BasicConstraints.MaxPathLenSet {
		below := len(candidate) - 2
		if below > issuer.BasicConstraints.MaxPathLen {
			return fmt.Errorf("%w: %q allows %d intermediate CAs, chain has %d",
				ErrPathLenExceeded, issuer.Subject, issuer.BasicConstraints.MaxPathLen, below)
		}
	}
	if err := child.VerifySignatureFrom(issuer); err != nil {
		return err
	}
	if opts.CheckRevocation != nil {
		if err := opts.CheckRevocation(child, issuer); err != nil {
			if errors.Is(err, ErrRevoked) {
				return err
			}
			return fmt.Errorf("pqx509: revocation check failed: %w", err)
		}
	}
	return nil
}

func checkValidity(c *Certificate, now time.Time) error {
	if now.Before(c.NotBefore) {
		return fmt.Errorf("%w: %q is valid from %v", ErrNotYetValid, c.Subject, c.NotBefore)
	}
	if now.After(c.NotAfter) {
		return fmt.Errorf("%w: %q expired at %v", ErrExpired, c.Subject, c.NotAfter)
	}
	return nil
}

func contains(chain []*Certificate, c *Certificate) bool {
	for _, x := range chain {
		if x == c || bytes.Equal(x.Raw, c.Raw) {
			return true
		}
	}
	return false
}
