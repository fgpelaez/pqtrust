package ca

import (
	"context"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/fgpelaez/pqtrust/internal/keystore"
	"github.com/fgpelaez/pqtrust/internal/pqx509"
	"github.com/fgpelaez/pqtrust/internal/store"
)

// Options configures an Engine.
type Options struct {
	// MaxValidity caps end-entity validity; zero means 397 days.
	MaxValidity time.Duration
	// CRLValidity is the nextUpdate offset; zero means 168 hours.
	CRLValidity time.Duration
	// Now is an injectable clock for tests; nil means time.Now.
	Now func() time.Time
}

// Engine is pqtrust's certificate authority.
type Engine struct {
	st  *store.Store
	ks  keystore.Backend
	now func() time.Time

	maxValidity time.Duration
	crlValidity time.Duration

	mu       sync.Mutex
	crlCache map[string]crlCacheEntry
}

// New builds an Engine over st and ks.
func New(st *store.Store, ks keystore.Backend, opts Options) (*Engine, error) {
	if st == nil || ks == nil {
		return nil, fmt.Errorf("ca: store and keystore are required")
	}
	e := &Engine{
		st:          st,
		ks:          ks,
		now:         opts.Now,
		maxValidity: opts.MaxValidity,
		crlValidity: opts.CRLValidity,
		crlCache:    map[string]crlCacheEntry{},
	}
	if e.now == nil {
		e.now = time.Now
	}
	if e.maxValidity == 0 {
		e.maxValidity = maxEndEntityValidityDays * 24 * time.Hour
	}
	if e.crlValidity == 0 {
		e.crlValidity = 168 * time.Hour
	}
	return e, nil
}

// CreateCARequest describes a root or intermediate CA to create.
type CreateCARequest struct {
	Name             string
	ParentID         string
	Algorithm        pqx509.Algorithm
	Subject          pqx509.Name
	ValidityDays     int
	Passphrase       []byte
	ParentPassphrase []byte
}

// CAResult is a CA and its chain.
//
//nolint:revive // CAResult is the established domain name exposed by the CA package.
type CAResult struct {
	ID          string
	Name        string
	ParentID    string
	Algorithm   pqx509.Algorithm
	CertPEM     string
	ChainPEM    string
	Certificate *pqx509.Certificate
	CreatedAt   time.Time
}

// CreateCA generates a key, issues the CA certificate and records it.
func (e *Engine) CreateCA(ctx context.Context, req CreateCARequest) (CAResult, error) {
	if strings.TrimSpace(req.Name) == "" {
		return CAResult{}, fmt.Errorf("%w: CA name must not be empty", ErrConstraintViolation)
	}
	if req.Subject.CommonName == "" {
		return CAResult{}, fmt.Errorf("%w: a CA subject must include a common name", ErrConstraintViolation)
	}
	if len(req.Passphrase) == 0 {
		return CAResult{}, fmt.Errorf("%w: a passphrase is required to seal the CA key", ErrConstraintViolation)
	}

	profile := rootProfile
	var parentRec store.CA
	var parentCert *pqx509.Certificate
	if req.ParentID != "" {
		profile = intermediateProfile
		var err error
		parentRec, err = e.st.GetCA(ctx, req.ParentID)
		if err != nil {
			return CAResult{}, wrapStoreErr(err)
		}
		if parentRec.ParentID != "" {
			return CAResult{}, fmt.Errorf("%w: only a root CA may issue an intermediate; %q is itself an intermediate",
				ErrConstraintViolation, req.ParentID)
		}
		if parentRec.Status != store.StatusActive {
			return CAResult{}, fmt.Errorf("%w: parent CA %q is %s", ErrConstraintViolation, req.ParentID, parentRec.Status)
		}
		if parentCert, err = parseCertPEM(parentRec.CertPEM); err != nil {
			return CAResult{}, err
		}
	}
	if err := profile.checkAlgorithm(req.Algorithm); err != nil {
		return CAResult{}, err
	}
	days, err := profile.resolveDays(req.ValidityDays)
	if err != nil {
		return CAResult{}, err
	}

	now := e.now().UTC().Truncate(time.Second)
	notBefore := now.Add(-clockSkew)
	notAfter := now.AddDate(0, 0, days)
	if parentCert != nil && notAfter.After(parentCert.NotAfter) {
		return CAResult{}, fmt.Errorf("%w: intermediate validity would outlast the root (%v)", ErrConstraintViolation, parentCert.NotAfter)
	}

	keyID, pub, priv, err := e.ks.Generate(req.Algorithm, req.Passphrase)
	if err != nil {
		return CAResult{}, fmt.Errorf("ca: generating CA key: %w", err)
	}
	defer zeroSeed(priv)

	serial, err := pqx509.GenerateSerialNumber(rand.Reader)
	if err != nil {
		return CAResult{}, err
	}

	var signer pqx509.Signer
	signatureAlg := req.Algorithm
	if req.ParentID == "" {
		if signer, err = priv.Signer(); err != nil {
			return CAResult{}, err
		}
	} else {
		signatureAlg = parentCert.PublicKey.Algorithm
		if signer, err = e.ks.Load(parentRec.KeyID, req.ParentPassphrase); err != nil {
			_ = e.ks.Delete(keyID)
			return CAResult{}, err
		}
	}

	tmpl := &pqx509.Certificate{
		SerialNumber:          serial,
		SignatureAlgorithm:    signatureAlg,
		Subject:               req.Subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraints:      pqx509.BasicConstraints{IsCA: true, MaxPathLen: profile.pathLen, MaxPathLenSet: true},
		BasicConstraintsValid: true,
		KeyUsage:              profile.keyUsage,
	}
	parentTmpl := tmpl
	if parentCert != nil {
		parentTmpl = parentCert
	}
	der, err := pqx509.CreateCertificate(rand.Reader, tmpl, parentTmpl, pub, signer)
	if err != nil {
		_ = e.ks.Delete(keyID)
		return CAResult{}, fmt.Errorf("ca: creating CA certificate: %w", err)
	}
	cert, err := pqx509.ParseCertificate(der)
	if err != nil {
		_ = e.ks.Delete(keyID)
		return CAResult{}, fmt.Errorf("ca: re-parsing the new CA certificate: %w", err)
	}

	caID, err := keystore.NewKeyID()
	if err != nil {
		_ = e.ks.Delete(keyID)
		return CAResult{}, err
	}
	certPEM := string(pqx509.EncodeCertificatePEM(der))
	rec := store.CA{
		ID:        caID,
		Name:      req.Name,
		ParentID:  req.ParentID,
		Algorithm: req.Algorithm.String(),
		CertPEM:   certPEM,
		KeyID:     keyID,
		Status:    store.StatusActive,
		CreatedAt: now,
	}
	if err := e.st.CreateCA(ctx, rec); err != nil {
		_ = e.ks.Delete(keyID)
		return CAResult{}, wrapStoreErr(err)
	}

	chainPEM := certPEM
	if parentRec.CertPEM != "" {
		chainPEM = certPEM + parentRec.CertPEM
	}
	return CAResult{
		ID: caID, Name: req.Name, ParentID: req.ParentID, Algorithm: req.Algorithm,
		CertPEM: certPEM, ChainPEM: chainPEM, Certificate: cert, CreatedAt: now,
	}, nil
}

// GetCA loads a CA and assembles its chain.
func (e *Engine) GetCA(ctx context.Context, id string) (CAResult, error) {
	rec, err := e.st.GetCA(ctx, id)
	if err != nil {
		return CAResult{}, wrapStoreErr(err)
	}
	return e.caResult(ctx, rec)
}

// ListCAs returns every CA with its chain.
func (e *Engine) ListCAs(ctx context.Context) ([]CAResult, error) {
	recs, err := e.st.ListCAs(ctx)
	if err != nil {
		return nil, wrapStoreErr(err)
	}
	out := make([]CAResult, 0, len(recs))
	for _, rec := range recs {
		res, err := e.caResult(ctx, rec)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (e *Engine) caResult(ctx context.Context, rec store.CA) (CAResult, error) {
	cert, err := parseCertPEM(rec.CertPEM)
	if err != nil {
		return CAResult{}, err
	}
	alg, err := pqx509.ParseAlgorithm(rec.Algorithm)
	if err != nil {
		return CAResult{}, fmt.Errorf("ca: stored CA %q: %w", rec.ID, err)
	}
	chain := rec.CertPEM
	if rec.ParentID != "" {
		parent, err := e.st.GetCA(ctx, rec.ParentID)
		if err != nil {
			return CAResult{}, wrapStoreErr(err)
		}
		chain += parent.CertPEM
	}
	return CAResult{
		ID: rec.ID, Name: rec.Name, ParentID: rec.ParentID, Algorithm: alg,
		CertPEM: rec.CertPEM, ChainPEM: chain, Certificate: cert, CreatedAt: rec.CreatedAt,
	}, nil
}

// IssueRequest describes an end-entity certificate to issue.
type IssueRequest struct {
	CAID         string
	CAPassphrase []byte
	Subject      pqx509.Name
	SANs         pqx509.SANs
	Algorithm    pqx509.Algorithm
	ValidityDays int
	ExtKeyUsage  []pqx509.ExtKeyUsage
	StoreKey     bool
}

// IssueResult is a newly issued certificate.
type IssueResult struct {
	Serial        string
	CertPEM       string
	ChainPEM      string
	PrivateKeyPEM string
	Certificate   *pqx509.Certificate
}

// IssueCertificate generates a key pair, issues a certificate and records it.
func (e *Engine) IssueCertificate(ctx context.Context, req IssueRequest) (IssueResult, error) {
	caRec, err := e.st.GetCA(ctx, req.CAID)
	if err != nil {
		return IssueResult{}, wrapStoreErr(err)
	}
	if caRec.Status != store.StatusActive {
		return IssueResult{}, fmt.Errorf("%w: CA %q is %s", ErrConstraintViolation, req.CAID, caRec.Status)
	}
	if caRec.ParentID == "" {
		return IssueResult{}, fmt.Errorf("%w: the root CA issues intermediates only; use an intermediate CA to issue end-entity certificates", ErrConstraintViolation)
	}
	caCert, err := parseCertPEM(caRec.CertPEM)
	if err != nil {
		return IssueResult{}, err
	}

	alg := req.Algorithm
	if alg == 0 {
		alg = pqx509.MLDSA44
	}
	if err := checkEndEntityAlgorithm(alg); err != nil {
		return IssueResult{}, err
	}
	ekus := req.ExtKeyUsage
	if len(ekus) == 0 {
		ekus = []pqx509.ExtKeyUsage{pqx509.ExtKeyUsageServerAuth}
	}
	if err := checkExtKeyUsage(ekus); err != nil {
		return IssueResult{}, err
	}
	if req.Subject.CommonName == "" && req.SANs.Empty() {
		return IssueResult{}, fmt.Errorf("%w: a certificate needs a common name or at least one subject alternative name", ErrConstraintViolation)
	}

	days := req.ValidityDays
	if days == 0 {
		days = endEntityValidityDays
	}
	if days < 0 {
		return IssueResult{}, fmt.Errorf("%w: validity must be positive, got %d days", ErrConstraintViolation, days)
	}
	if requested := time.Duration(days) * 24 * time.Hour; requested > e.maxValidity {
		return IssueResult{}, fmt.Errorf("%w: validity %d days exceeds the %.0f day maximum",
			ErrConstraintViolation, days, e.maxValidity.Hours()/24)
	}

	now := e.now().UTC().Truncate(time.Second)
	notBefore := now.Add(-clockSkew)
	notAfter := now.AddDate(0, 0, days)
	if notAfter.After(caCert.NotAfter) {
		return IssueResult{}, fmt.Errorf("%w: requested validity outlasts the issuing CA (%v)", ErrConstraintViolation, caCert.NotAfter)
	}

	signer, err := e.ks.Load(caRec.KeyID, req.CAPassphrase)
	if err != nil {
		return IssueResult{}, err
	}

	pub, priv, err := pqx509.GenerateKey(rand.Reader, alg)
	if err != nil {
		return IssueResult{}, err
	}
	serial, err := pqx509.GenerateSerialNumber(rand.Reader)
	if err != nil {
		return IssueResult{}, err
	}

	tmpl := &pqx509.Certificate{
		SerialNumber:          serial,
		SignatureAlgorithm:    caCert.PublicKey.Algorithm,
		Subject:               req.Subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraints:      pqx509.BasicConstraints{IsCA: false},
		BasicConstraintsValid: true,
		KeyUsage:              pqx509.KeyUsageDigitalSignature,
		ExtKeyUsage:           ekus,
		SANs:                  req.SANs,
	}
	der, err := pqx509.CreateCertificate(rand.Reader, tmpl, caCert, pub, signer)
	if err != nil {
		return IssueResult{}, fmt.Errorf("ca: issuing certificate: %w", err)
	}
	cert, err := pqx509.ParseCertificate(der)
	if err != nil {
		return IssueResult{}, fmt.Errorf("ca: re-parsing the issued certificate: %w", err)
	}

	var storedKeyID string
	if req.StoreKey {
		id, err := keystore.NewKeyID()
		if err != nil {
			return IssueResult{}, err
		}
		if err := e.ks.Store(id, priv, req.CAPassphrase); err != nil {
			return IssueResult{}, fmt.Errorf("ca: storing the end-entity key: %w", err)
		}
		storedKeyID = id
	}

	certPEM := string(pqx509.EncodeCertificatePEM(der))
	serialHex := SerialHex(serial)
	rec := store.Certificate{
		Serial:    serialHex,
		CAID:      caRec.ID,
		SubjectDN: req.Subject.String(),
		SANs:      sansString(req.SANs),
		Algorithm: alg.String(),
		CertPEM:   certPEM,
		KeyID:     storedKeyID,
		Status:    store.StatusValid,
		NotBefore: notBefore,
		NotAfter:  notAfter,
	}
	if err := e.st.InsertCertificate(ctx, rec); err != nil {
		if storedKeyID != "" {
			_ = e.ks.Delete(storedKeyID)
		}
		return IssueResult{}, wrapStoreErr(err)
	}

	caResult, err := e.caResult(ctx, caRec)
	if err != nil {
		return IssueResult{}, err
	}
	out := IssueResult{
		Serial:      serialHex,
		CertPEM:     certPEM,
		ChainPEM:    certPEM + caResult.ChainPEM,
		Certificate: cert,
	}
	if !req.StoreKey {
		out.PrivateKeyPEM = string(EncodePrivateKeyPEM(priv))
	}
	zeroSeed(priv)
	return out, nil
}

// GetCertificate returns a stored certificate record.
func (e *Engine) GetCertificate(ctx context.Context, serial string) (store.Certificate, error) {
	rec, err := e.st.GetCertificate(ctx, strings.ToLower(serial))
	if err != nil {
		return store.Certificate{}, wrapStoreErr(err)
	}
	return rec, nil
}

// Revoke marks a certificate revoked with an RFC 5280 reason code.
func (e *Engine) Revoke(ctx context.Context, serial string, reason int) error {
	if reason < 0 || reason > 10 || reason == 7 {
		return fmt.Errorf("%w: %d is not an RFC 5280 CRLReason", ErrConstraintViolation, reason)
	}
	serial = strings.ToLower(serial)
	rec, err := e.st.GetCertificate(ctx, serial)
	if err != nil {
		return wrapStoreErr(err)
	}
	if err := e.st.RevokeCertificate(ctx, serial, e.now().UTC().Truncate(time.Second), reason); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return fmt.Errorf("%w: %s", ErrAlreadyRevoked, serial)
		}
		return wrapStoreErr(err)
	}
	e.invalidateCRL(rec.CAID)
	return nil
}

// EncodePrivateKeyPEM wraps a private key seed in a pqtrust-specific PEM block.
// PKCS#8 for ML-DSA arrives with the Phase 2 CSR work.
func EncodePrivateKeyPEM(priv pqx509.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:    "PQTRUST ML-DSA PRIVATE KEY",
		Headers: map[string]string{"Algorithm": priv.Algorithm.String()},
		Bytes:   priv.Seed,
	})
}

// SerialHex renders a serial number as lowercase hexadecimal.
func SerialHex(serial *big.Int) string {
	return strings.ToLower(serial.Text(16))
}

func sansString(s pqx509.SANs) string {
	var parts []string
	parts = append(parts, s.DNSNames...)
	for _, ip := range s.IPAddresses {
		parts = append(parts, ip.String())
	}
	parts = append(parts, s.EmailAddresses...)
	return strings.Join(parts, ",")
}

func parseCertPEM(certPEM string) (*pqx509.Certificate, error) {
	der, err := pqx509.DecodeCertificatePEM([]byte(certPEM))
	if err != nil {
		return nil, fmt.Errorf("ca: decoding stored certificate: %w", err)
	}
	cert, err := pqx509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("ca: parsing stored certificate: %w", err)
	}
	return cert, nil
}

func wrapStoreErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrNotFound):
		return fmt.Errorf("%w: %w", ErrNotFound, err)
	default:
		return err
	}
}

func zeroSeed(priv pqx509.PrivateKey) {
	for i := range priv.Seed {
		priv.Seed[i] = 0
	}
}
