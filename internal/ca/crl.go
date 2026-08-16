package ca

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/fernando/pqtrust/internal/pqx509"
)

type crlCacheEntry struct {
	der        []byte
	entryCount int
	nextUpdate time.Time
	number     *big.Int
}

// CRL returns the current CRL for caID, rebuilding it only when the set of
// revoked certificates has changed or the cached one has expired. passphrase is
// needed only when a rebuild is required.
func (e *Engine) CRL(ctx context.Context, caID string, passphrase []byte) ([]byte, error) {
	caRec, err := e.st.GetCA(ctx, caID)
	if err != nil {
		return nil, wrapStoreErr(err)
	}
	revoked, err := e.st.ListRevoked(ctx, caID)
	if err != nil {
		return nil, wrapStoreErr(err)
	}
	now := e.now().UTC().Truncate(time.Second)

	e.mu.Lock()
	cached, ok := e.crlCache[caID]
	e.mu.Unlock()
	if ok && cached.entryCount == len(revoked) && now.Before(cached.nextUpdate) {
		return cached.der, nil
	}

	caCert, err := parseCertPEM(caRec.CertPEM)
	if err != nil {
		return nil, err
	}
	signer, err := e.ks.Load(caRec.KeyID, passphrase)
	if err != nil {
		return nil, err
	}

	entries := make([]pqx509.RevocationEntry, 0, len(revoked))
	for _, rec := range revoked {
		serial, ok := new(big.Int).SetString(rec.Serial, 16)
		if !ok {
			return nil, fmt.Errorf("ca: stored serial %q is not hexadecimal", rec.Serial)
		}
		entry := pqx509.RevocationEntry{SerialNumber: serial, RevocationTime: now}
		if rec.RevokedAt != nil {
			entry.RevocationTime = *rec.RevokedAt
		}
		if rec.RevocationReason != nil {
			entry.ReasonCode = *rec.RevocationReason
		}
		entries = append(entries, entry)
	}

	number := big.NewInt(int64(len(revoked)) + 1)
	nextUpdate := now.Add(e.crlValidity)
	der, err := pqx509.CreateRevocationList(rand.Reader, caCert, signer, number, entries, now, nextUpdate)
	if err != nil {
		return nil, fmt.Errorf("ca: creating CRL: %w", err)
	}

	e.mu.Lock()
	e.crlCache[caID] = crlCacheEntry{der: der, entryCount: len(revoked), nextUpdate: nextUpdate, number: number}
	e.mu.Unlock()
	return der, nil
}

func (e *Engine) invalidateCRL(caID string) {
	e.mu.Lock()
	delete(e.crlCache, caID)
	e.mu.Unlock()
}
