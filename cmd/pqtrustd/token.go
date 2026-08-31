package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/fgpelaez/pqtrust/internal/api"
	"github.com/fgpelaez/pqtrust/internal/keystore"
	"github.com/fgpelaez/pqtrust/internal/store"
)

func ensureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("pqtrustd: creating %s: %w", dir, err)
	}
	return nil
}

// runTokenCreate mints an API token, stores its hash and writes the token to out.
func runTokenCreate(configPath, name string, out io.Writer) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("pqtrustd: -name is required")
	}
	a, cleanup, err := newApp(configPath)
	if err != nil {
		return err
	}
	defer cleanup()

	token, err := api.GenerateToken()
	if err != nil {
		return err
	}
	id, err := keystore.NewKeyID()
	if err != nil {
		return err
	}
	if err := a.store.CreateToken(context.Background(), store.Token{
		ID:        id,
		Name:      name,
		TokenHash: api.HashToken(token),
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(out, token); err != nil {
		return fmt.Errorf("pqtrustd: writing token: %w", err)
	}
	return nil
}
