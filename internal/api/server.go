package api

import (
	"fmt"
	"net/http"

	"github.com/fgpelaez/pqtrust/internal/ca"
	"github.com/fgpelaez/pqtrust/internal/store"
)

// Server routes pqtrust's HTTP API.
type Server struct {
	engine *ca.Engine
	store  *store.Store
	mux    *http.ServeMux
}

// NewServer wires the routes.
func NewServer(engine *ca.Engine, st *store.Store) (*Server, error) {
	if engine == nil || st == nil {
		return nil, fmt.Errorf("api: engine and store are required")
	}
	s := &Server{engine: engine, store: st, mux: http.NewServeMux()}

	s.mux.HandleFunc("GET /v1/health", s.handleHealth)

	authed := map[string]http.HandlerFunc{
		"POST /v1/ca":                           s.handleCreateCA,
		"GET /v1/ca":                            s.handleListCAs,
		"GET /v1/ca/{id}":                       s.handleGetCA,
		"GET /v1/ca/{id}/crl":                   s.handleGetCRL,
		"POST /v1/certificates":                 s.handleIssueCertificate,
		"GET /v1/certificates/{serial}":         s.handleGetCertificate,
		"POST /v1/certificates/{serial}/revoke": s.handleRevoke,
	}
	for pattern, handler := range authed {
		s.mux.Handle(pattern, s.requireToken(handler))
	}
	return s, nil
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}