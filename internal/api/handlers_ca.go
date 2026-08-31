package api

import (
	"net/http"
	"time"

	"github.com/fgpelaez/pqtrust/internal/ca"
	"github.com/fgpelaez/pqtrust/internal/pqx509"
)

type subjectJSON struct {
	CommonName         string   `json:"common_name"`
	Organization       []string `json:"organization"`
	OrganizationalUnit []string `json:"organizational_unit"`
	Country            []string `json:"country"`
	Locality           []string `json:"locality"`
	Province           []string `json:"province"`
}

func (s subjectJSON) toName() pqx509.Name {
	return pqx509.Name{
		CommonName:         s.CommonName,
		Organization:       s.Organization,
		OrganizationalUnit: s.OrganizationalUnit,
		Country:            s.Country,
		Locality:           s.Locality,
		Province:           s.Province,
	}
}

type createCARequest struct {
	Name             string      `json:"name"`
	ParentID         *string     `json:"parent_id"`
	Algorithm        string      `json:"algorithm"`
	Subject          subjectJSON `json:"subject"`
	ValidityDays     int         `json:"validity_days"`
	Passphrase       string      `json:"passphrase"`
	ParentPassphrase *string     `json:"parent_passphrase"`
}

type caResponse struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	ParentID       *string   `json:"parent_id"`
	Algorithm      string    `json:"algorithm"`
	CertificatePEM string    `json:"certificate_pem"`
	ChainPEM       string    `json:"chain_pem"`
	SubjectDN      string    `json:"subject_dn"`
	NotBefore      time.Time `json:"not_before"`
	NotAfter       time.Time `json:"not_after"`
	CreatedAt      time.Time `json:"created_at"`
}

func toCAResponse(res ca.CAResult) caResponse {
	var parent *string
	if res.ParentID != "" {
		p := res.ParentID
		parent = &p
	}
	return caResponse{
		ID:             res.ID,
		Name:           res.Name,
		ParentID:       parent,
		Algorithm:      res.Algorithm.String(),
		CertificatePEM: res.CertPEM,
		ChainPEM:       res.ChainPEM,
		SubjectDN:      res.Certificate.Subject.String(),
		NotBefore:      res.Certificate.NotBefore,
		NotAfter:       res.Certificate.NotAfter,
		CreatedAt:      res.CreatedAt,
	}
}

func (s *Server) handleCreateCA(w http.ResponseWriter, r *http.Request) {
	var req createCARequest
	if !decodeJSON(w, r, &req) {
		return
	}
	alg, err := pqx509.ParseAlgorithm(req.Algorithm)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, typeInvalidRequest, "Invalid request", err.Error())
		return
	}
	if req.Passphrase == "" {
		writeProblem(w, http.StatusBadRequest, typeInvalidRequest, "Invalid request", "passphrase is required")
		return
	}
	engineReq := ca.CreateCARequest{
		Name:         req.Name,
		Algorithm:    alg,
		Subject:      req.Subject.toName(),
		ValidityDays: req.ValidityDays,
		Passphrase:   []byte(req.Passphrase),
	}
	if req.ParentID != nil {
		engineReq.ParentID = *req.ParentID
	}
	if req.ParentPassphrase != nil {
		engineReq.ParentPassphrase = []byte(*req.ParentPassphrase)
	}
	res, err := s.engine.CreateCA(r.Context(), engineReq)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, toCAResponse(res))
}

func (s *Server) handleListCAs(w http.ResponseWriter, r *http.Request) {
	list, err := s.engine.ListCAs(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	out := make([]caResponse, 0, len(list))
	for _, res := range list {
		out = append(out, toCAResponse(res))
	}
	writeJSON(w, http.StatusOK, map[string]any{"cas": out})
}

func (s *Server) handleGetCA(w http.ResponseWriter, r *http.Request) {
	res, err := s.engine.GetCA(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toCAResponse(res))
}

func (s *Server) handleGetCRL(w http.ResponseWriter, r *http.Request) {
	passphrase := r.Header.Get("X-PQTrust-Passphrase")
	der, err := s.engine.CRL(r.Context(), r.PathValue("id"), []byte(passphrase))
	if err != nil {
		writeError(w, err)
		return
	}
	if accept := r.Header.Get("Accept"); accept == "application/x-pem-file" {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(pqx509.EncodeCRLPEM(der)) //nolint:gosec // certificate PEM is not interpreted as HTML
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(der) //nolint:gosec // DER certificate bytes are not interpreted as HTML
}
