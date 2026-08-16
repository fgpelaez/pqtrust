package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/fernando/pqtrust/internal/store"
)

// GenerateToken returns a new 256-bit API token in base64url form.
func GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("api: generating token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashToken returns the hex SHA-256 of a token; only hashes are ever stored.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// requireToken authenticates a bearer token against the tokens table.
func (s *Server) requireToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		token, ok := bearerToken(header)
		if !ok {
			writeProblem(w, http.StatusUnauthorized, typeUnauthorized, "Unauthorized",
				"a bearer token is required in the Authorization header")
			return
		}
		if _, err := s.store.TokenByHash(r.Context(), HashToken(token)); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeProblem(w, http.StatusUnauthorized, typeUnauthorized, "Unauthorized", "the bearer token is not recognized")
				return
			}
			writeError(w, err)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func bearerToken(header string) (string, bool) {
	const prefix = "Bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", false
	}
	token := strings.TrimSpace(header[len(prefix):])
	if token == "" {
		return "", false
	}
	return token, true
}