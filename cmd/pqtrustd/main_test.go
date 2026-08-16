package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSelfSignedTLSCert(t *testing.T) {
	cert, err := selfSignedTLSCert("pqtrust.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Certificate) != 1 {
		t.Fatalf("got %d certificates, want 1", len(cert.Certificate))
	}
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if parsed.PublicKeyAlgorithm != x509.ECDSA {
		t.Errorf("public key algorithm = %v, want ECDSA", parsed.PublicKeyAlgorithm)
	}
	if err := parsed.VerifyHostname("pqtrust.test"); err != nil {
		t.Errorf("VerifyHostname: %v", err)
	}
	foundLoopback := false
	for _, ip := range parsed.IPAddresses {
		if ip.IsLoopback() {
			foundLoopback = true
		}
	}
	if !foundLoopback {
		t.Error("the self-signed certificate must cover loopback addresses")
	}
	if !parsed.NotAfter.After(time.Now().AddDate(0, 11, 0)) {
		t.Errorf("NotAfter = %v, want about a year out", parsed.NotAfter)
	}
}

func TestTokenCreateThenServeAndAuthenticate(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	cfgYAML := "server:\n" +
		"  listen: \"127.0.0.1:0\"\n" +
		"  tls:\n" +
		"    auto_self_signed: true\n" +
		"    hostname: localhost\n" +
		"database:\n" +
		"  path: " + filepath.Join(dir, "pqtrust.db") + "\n" +
		"keystore:\n" +
		"  dir: " + filepath.Join(dir, "keys") + "\n"
	if err := os.WriteFile(configPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	// token create writes the token to stdout.
	var out strings.Builder
	if err := runTokenCreate(configPath, "ci", &out); err != nil {
		t.Fatalf("runTokenCreate: %v", err)
	}
	token := strings.TrimSpace(out.String())
	if len(token) < 40 {
		t.Fatalf("token output = %q", out.String())
	}

	// Serve on an ephemeral port and hit /v1/health and an authenticated route.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- serveOnListener(ctx, configPath, ln) }()

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // self-signed test certificate
	}}
	base := "https://" + ln.Addr().String()

	deadline := time.Now().Add(10 * time.Second)
	var resp *http.Response
	for time.Now().Before(deadline) {
		resp, err = client.Get(base + "/v1/health")
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("health request never succeeded: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health = %d %s", resp.StatusCode, body)
	}
	var health map[string]string
	if err := json.Unmarshal(body, &health); err != nil {
		t.Fatal(err)
	}
	if health["status"] != "ok" {
		t.Errorf("health = %v", health)
	}
	// The connection must use the hybrid post-quantum key exchange.
	if resp.TLS != nil && resp.TLS.CurveID != tls.X25519MLKEM768 {
		t.Errorf("negotiated curve = %v, want X25519MLKEM768", resp.TLS.CurveID)
	}

	// Authenticated route with the created token.
	req, err := http.NewRequest(http.MethodGet, base+"/v1/ca", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp2, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp2.Body)
		t.Fatalf("list CAs = %d %s", resp2.StatusCode, b)
	}

	// A bogus token must be rejected.
	req.Header.Set("Authorization", "Bearer bogus")
	resp3, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusUnauthorized {
		t.Errorf("bogus token = %d, want 401", resp3.StatusCode)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("serveOnListener returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Error("server did not shut down within 10 seconds")
	}
}
