package api

import (
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/fernando/pqtrust/internal/ca"
	"github.com/fernando/pqtrust/internal/pqx509"
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

func (s *Server) handleIssueCertificate(w http.ResponseWriter, r *http.Request) {
	var req issueRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	engineReq := ca.IssueRequest{
		CAID:         req.CAID,
		CAPassphrase: []byte(req.Passphrase),
		Subject:      req.Subject.toName(),
		ValidityDays: req.ValidityDays,
		StoreKey:     req.StoreKey,
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