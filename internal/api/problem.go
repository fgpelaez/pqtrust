// Package api exposes pqtrust's REST interface. It validates requests, performs
// bearer-token authentication and maps domain errors to RFC 7807 problems.
package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/fernando/pqtrust/internal/ca"
	"github.com/fernando/pqtrust/internal/keystore"
	"github.com/fernando/pqtrust/internal/pqx509"
)

// Problem type URNs.
const (
	typeInvalidRequest      = "urn:pqtrust:error:invalid-request"
	typeUnauthorized        = "urn:pqtrust:error:unauthorized"
	typeNotFound            = "urn:pqtrust:error:not-found"
	typeConflict            = "urn:pqtrust:error:conflict"
	typeWrongPassphrase     = "urn:pqtrust:error:wrong-passphrase"
	typeConstraintViolation = "urn:pqtrust:error:constraint-violation"
	typeInternal            = "urn:pqtrust:error:internal"
)

type problem struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail"`
}

func writeProblem(w http.ResponseWriter, status int, typeURN, title, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(problem{Type: typeURN, Title: title, Status: status, Detail: detail}); err != nil {
		slog.Error("writing problem response", "error", err)
	}
}

func problemForError(err error) (int, string, string) {
	switch {
	case errors.Is(err, ca.ErrNotFound):
		return http.StatusNotFound, typeNotFound, "Not found"
	case errors.Is(err, ca.ErrAlreadyRevoked):
		return http.StatusConflict, typeConflict, "Conflict"
	case errors.Is(err, keystore.ErrWrongPassphrase):
		return http.StatusForbidden, typeWrongPassphrase, "Wrong passphrase"
	case errors.Is(err, ca.ErrConstraintViolation):
		return http.StatusUnprocessableEntity, typeConstraintViolation, "Constraint violation"
	case errors.Is(err, pqx509.ErrUnknownAlgorithm):
		return http.StatusBadRequest, typeInvalidRequest, "Invalid request"
	default:
		return http.StatusInternalServerError, typeInternal, "Internal server error"
	}
}

// writeError maps err to a problem response, logging 500s with the real cause.
func writeError(w http.ResponseWriter, err error) {
	status, typeURN, title := problemForError(err)
	detail := err.Error()
	if status == http.StatusInternalServerError {
		slog.Error("request failed", "error", err)
		detail = "an internal error occurred"
	}
	writeProblem(w, status, typeURN, title, detail)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("writing JSON response", "error", err)
	}
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeProblem(w, http.StatusBadRequest, typeInvalidRequest, "Invalid request", "malformed request body: "+err.Error())
		return false
	}
	return true
}