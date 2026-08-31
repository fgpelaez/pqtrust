package api

import (
	"net/http"

	"github.com/fgpelaez/pqtrust/internal/version"
)

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"version": version.Version,
	})
}