package api

import (
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/fgpelaez/pqtrust/internal/ca"
	"github.com/fgpelaez/pqtrust/internal/pqx509"
)

type issueRequest struct {
	CAID           string      `json:"ca_id"`
	Passphrase     string      `json:"passphrase"`
	Subject        subjectJSON `json:"subject"`
	DNSNames       []string    `json:"dns_names"`
	IPAddresses    []string    `json:"ip_addresses"`
	EmailAddresses []string    `json:"email_addresses"`
	Algorithm      string      `json:"algorithm"`
	ValidityDays   int         `json:"validity_days"`
	ExtKeyUsage    []string    `json:"ext_key_usage"`
	StoreKey       bool        `json:"store_key"`
	CSRPEM         string      `json:"csr_pem"`
}

type issueResponse struct {
	Serial         string    `json:"serial"`
	CertificatePEM string    `json:"certificate_pem"`
	ChainPEM       string    `json:"chain_pem"`
	PrivateKeyPEM  string    `json:"private_key_pem,omitempty"`
	NotBefore      time.Time `json:"not_before"`
	NotAfter       time.Time `json:"not_after"`
}

type certificateResponse struct {
	Serial           string     `json:"serial"`
	CAID             string     `json:"ca_id"`
	SubjectDN        string     `json:"subject_dn"`
	SANs             []string   `json:"sans"`
	Algorithm        string     `json:"algorithm"`
	Status           string     `json:"status"`
	CertificatePEM   string     `json:"certificate_pem"`
	NotBefore        time.Time  `json:"not_before"`
	NotAfter         time.Time  `json:"not_after"`
	RevokedAt        *time.Time `json:"revoked_at"`
	RevocationReason *int       `json:"revocation_reason"`
}

type revokeRequest struct {
	Reason int `json:"reason"`
}

// parseCSRPEM decodes a PEM-encoded PKCS#10 CSR and verifies its
// self-signature. Any failure is a client-input problem.
func parseCSRPEM(pemStr string) (*pqx509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("csr_pem: no PEM block found")
	}
	if block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("csr_pem: PEM block type is %q, want %q", block.Type, "CERTIFICATE REQUEST")
	}
	csr, err := pqx509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, err
	}
	return csr, nil
}

// csrForbiddenField names the first request field that must be empty when
// csr_pem is set, or "" when none violates the XOR.
func csrForbiddenField(req issueRequest) string {
	switch {
	case !req.Subject.empty():
		return "subject"
	case len(req.DNSNames) > 0:
		return "dns_names"
	case len(req.IPAddresses) > 0:
		return "ip_addresses"
	case len(req.EmailAddresses) > 0:
		return "email_addresses"
	case req.Algorithm != "":
		return "algorithm"
	case req.StoreKey:
		return "store_key"
	default:
		return ""
	}
}

func (s *Server) handleIssueCertificate(w http.ResponseWriter, r *http.Request) {
	var req issueRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	var csr *pqx509.CertificateRequest
	if req.CSRPEM != "" {
		parsed, err := parseCSRPEM(req.CSRPEM)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, typeInvalidRequest, "Invalid request", err.Error())
			return
		}
		if field := csrForbiddenField(req); field != "" {
			writeProblem(w, http.StatusBadRequest, typeInvalidRequest, "Invalid request",
				fmt.Sprintf("field %q must be empty when csr_pem is set", field))
			return
		}
		csr = parsed
	}
	engineReq := ca.IssueRequest{
		CAID:         req.CAID,
		CAPassphrase: []byte(req.Passphrase),
		Subject:      req.Subject.toName(),
		ValidityDays: req.ValidityDays,
		StoreKey:     req.StoreKey,
		CSR:          csr,
	}
	if req.Algorithm != "" {
		alg, err := pqx509.ParseAlgorithm(req.Algorithm)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, typeInvalidRequest, "Invalid request", err.Error())
			return
		}
		engineReq.Algorithm = alg
	}
	if len(req.ExtKeyUsage) > 0 {
		ekus, err := pqx509.ParseExtKeyUsages(req.ExtKeyUsage)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, typeInvalidRequest, "Invalid request", err.Error())
			return
		}
		engineReq.ExtKeyUsage = ekus
	}
	sans := pqx509.SANs{DNSNames: req.DNSNames, EmailAddresses: req.EmailAddresses}
	for _, raw := range req.IPAddresses {
		ip := net.ParseIP(raw)
		if ip == nil {
			writeProblem(w, http.StatusBadRequest, typeInvalidRequest, "Invalid request", "not an IP address: "+raw)
			return
		}
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		sans.IPAddresses = append(sans.IPAddresses, ip)
	}
	engineReq.SANs = sans

	res, err := s.engine.IssueCertificate(r.Context(), engineReq)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, issueResponse{
		Serial:         res.Serial,
		CertificatePEM: res.CertPEM,
		ChainPEM:       res.ChainPEM,
		PrivateKeyPEM:  res.PrivateKeyPEM,
		NotBefore:      res.Certificate.NotBefore,
		NotAfter:       res.Certificate.NotAfter,
	})
}

func (s *Server) handleGetCertificate(w http.ResponseWriter, r *http.Request) {
	rec, err := s.engine.GetCertificate(r.Context(), r.PathValue("serial"))
	if err != nil {
		writeError(w, err)
		return
	}
	var sans []string
	if rec.SANs != "" {
		sans = strings.Split(rec.SANs, ",")
	}
	writeJSON(w, http.StatusOK, certificateResponse{
		Serial:           rec.Serial,
		CAID:             rec.CAID,
		SubjectDN:        rec.SubjectDN,
		SANs:             sans,
		Algorithm:        rec.Algorithm,
		Status:           rec.Status,
		CertificatePEM:   rec.CertPEM,
		NotBefore:        rec.NotBefore,
		NotAfter:         rec.NotAfter,
		RevokedAt:        rec.RevokedAt,
		RevocationReason: rec.RevocationReason,
	})
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	var req revokeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	serial := r.PathValue("serial")
	if err := s.engine.Revoke(r.Context(), serial, req.Reason); err != nil {
		writeError(w, err)
		return
	}
	rec, err := s.engine.GetCertificate(r.Context(), serial)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"serial":     rec.Serial,
		"status":     rec.Status,
		"revoked_at": rec.RevokedAt,
		"reason":     rec.RevocationReason,
	})
}
