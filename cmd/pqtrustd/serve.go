package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"time"

	"github.com/fernando/pqtrust/internal/api"
	"github.com/fernando/pqtrust/internal/ca"
	"github.com/fernando/pqtrust/internal/config"
	"github.com/fernando/pqtrust/internal/keystore"
	"github.com/fernando/pqtrust/internal/store"
)

type app struct {
	cfg    config.Config
	store  *store.Store
	server *api.Server
}

// newApp loads configuration and wires every layer.
func newApp(configPath string) (*app, func(), error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, nil, err
	}
	if dir := filepath.Dir(cfg.Database.Path); dir != "" {
		if err := ensureDir(dir); err != nil {
			return nil, nil, err
		}
	}
	st, err := store.Open(cfg.Database.Path)
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() { _ = st.Close() }

	ks, err := keystore.NewFileBackend(cfg.Keystore.Dir)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	engine, err := ca.New(st, ks, ca.Options{
		MaxValidity: time.Duration(cfg.Issuance.MaxValidityDays) * 24 * time.Hour,
		CRLValidity: time.Duration(cfg.Issuance.CRLValidityHours) * time.Hour,
	})
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	srv, err := api.NewServer(engine, st)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	return &app{cfg: cfg, store: st, server: srv}, cleanup, nil
}

// serveOnListener runs the API on ln until ctx is cancelled.
func serveOnListener(ctx context.Context, configPath string, ln net.Listener) error {
	a, cleanup, err := newApp(configPath)
	if err != nil {
		return err
	}
	defer cleanup()

	tlsCfg, err := a.tlsConfig()
	if err != nil {
		return err
	}
	httpSrv := &http.Server{
		Handler:           a.server,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("pqtrustd listening", "address", ln.Addr().String())
		err := httpSrv.ServeTLS(ln, "", "")
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpSrv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("pqtrustd: shutting down: %w", err)
		}
		return <-errCh
	}
}

// serve resolves the configured listen address and serves until ctx is done.
func serve(ctx context.Context, configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", cfg.Server.Listen)
	if err != nil {
		return fmt.Errorf("pqtrustd: listening on %s: %w", cfg.Server.Listen, err)
	}
	return serveOnListener(ctx, configPath, ln)
}

func (a *app) tlsConfig() (*tls.Config, error) {
	// Leaving CurvePreferences unset keeps Go's default, which negotiates the
	// hybrid X25519MLKEM768 key exchange first.
	cfg := &tls.Config{MinVersion: tls.VersionTLS13}
	if a.cfg.Server.TLS.AutoSelfSigned {
		cert, err := selfSignedTLSCert(a.cfg.Server.TLS.Hostname)
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{cert}
		return cfg, nil
	}
	cert, err := tls.LoadX509KeyPair(a.cfg.Server.TLS.CertFile, a.cfg.Server.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("pqtrustd: loading TLS key pair: %w", err)
	}
	cfg.Certificates = []tls.Certificate{cert}
	return cfg, nil
}
