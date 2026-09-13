package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fgpelaez/pqtrust/internal/ca"
	"github.com/fgpelaez/pqtrust/internal/keystore"
	"github.com/fgpelaez/pqtrust/internal/pqx509"
	"github.com/fgpelaez/pqtrust/internal/store"
)

const testPassphrase = "test-passphrase"

type harness struct {
	srv   *Server
	token string
	st    *store.Store
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "pqtrust.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ks, err := keystore.NewFileBackend(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := ca.New(st, ks, ca.Options{})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(engine, st)
	if err != nil {
		t.Fatal(err)
	}
	token, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateToken(context.Background(), store.Token{
		ID: "t1", Name: "test", TokenHash: HashToken(token), CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	return &harness{srv: srv, token: token, st: st}
}

func (h *harness) do(t *testing.T, method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(data)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+h.token)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.srv.ServeHTTP(rec, req)
	return rec
}

func decode(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		t.Fatalf("decoding response %q: %v", rec.Body.String(), err)
	}
}

func (h *harness) createRoot(t *testing.T) string {
	t.Helper()
	rec := h.do(t, http.MethodPost, "/v1/ca", map[string]any{
		"name":       "Root",
		"algorithm":  "ML-DSA-87",
		"subject":    map[string]any{"common_name": "pqtrust Root CA", "organization": []string{"pqtrust"}},
		"passphrase": testPassphrase,
	}, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create root: %d %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	decode(t, rec, &out)
	return out["id"].(string)
}

func (h *harness) createIntermediate(t *testing.T, rootID string) string {
	t.Helper()
	rec := h.do(t, http.MethodPost, "/v1/ca", map[string]any{
		"name":              "Issuing",
		"parent_id":         rootID,
		"algorithm":         "ML-DSA-65",
		"subject":           map[string]any{"common_name": "pqtrust Issuing CA"},
		"passphrase":        testPassphrase,
		"parent_passphrase": testPassphrase,
	}, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create intermediate: %d %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	decode(t, rec, &out)
	return out["id"].(string)
}

func TestHealthNeedsNoAuth(t *testing.T) {
	h := newHarness(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	rec := httptest.NewRecorder()
	h.srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("health = %d %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	decode(t, rec, &out)
	if out["status"] != "ok" {
		t.Errorf("health body = %v", out)
	}
}

func TestAuthFailures(t *testing.T) {
	h := newHarness(t)
	cases := []struct {
		name   string
		header string
	}{
		{"missing", ""},
		{"wrong scheme", "Token " + h.token},
		{"unknown token", "Bearer not-a-real-token"},
		{"empty bearer", "Bearer "},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/ca", nil)
			if c.header != "" {
				req.Header.Set("Authorization", c.header)
			}
			rec := httptest.NewRecorder()
			h.srv.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401 (%s)", rec.Code, rec.Body.String())
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
				t.Errorf("Content-Type = %q", ct)
			}
			var p map[string]any
			decode(t, rec, &p)
			if p["type"] != "urn:pqtrust:error:unauthorized" || p["status"] != float64(401) {
				t.Errorf("problem = %v", p)
			}
			if p["title"] == nil || p["detail"] == nil {
				t.Errorf("problem must carry title and detail: %v", p)
			}
		})
	}
}

func TestFullIssuanceAndRevocationFlow(t *testing.T) {
	h := newHarness(t)
	rootID := h.createRoot(t)
	interID := h.createIntermediate(t, rootID)

	rec := h.do(t, http.MethodGet, "/v1/ca", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list CAs = %d %s", rec.Code, rec.Body.String())
	}
	var list struct {
		CAs []map[string]any `json:"cas"`
	}
	decode(t, rec, &list)
	if len(list.CAs) != 2 {
		t.Fatalf("got %d CAs, want 2", len(list.CAs))
	}

	rec = h.do(t, http.MethodGet, "/v1/ca/"+interID, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get CA = %d %s", rec.Code, rec.Body.String())
	}
	var caOut map[string]any
	decode(t, rec, &caOut)
	if strings.Count(caOut["chain_pem"].(string), "BEGIN CERTIFICATE") != 2 {
		t.Error("intermediate chain must contain two certificates")
	}

	rec = h.do(t, http.MethodPost, "/v1/certificates", map[string]any{
		"ca_id":         interID,
		"passphrase":    testPassphrase,
		"subject":       map[string]any{"common_name": "api.example.com"},
		"dns_names":     []string{"api.example.com"},
		"ip_addresses":  []string{"192.0.2.10"},
		"ext_key_usage": []string{"serverAuth", "clientAuth"},
	}, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("issue = %d %s", rec.Code, rec.Body.String())
	}
	var issued struct {
		Serial         string `json:"serial"`
		CertificatePEM string `json:"certificate_pem"`
		ChainPEM       string `json:"chain_pem"`
		PrivateKeyPEM  string `json:"private_key_pem"`
	}
	decode(t, rec, &issued)
	if issued.Serial == "" || issued.PrivateKeyPEM == "" {
		t.Fatalf("issued = %+v", issued)
	}
	der, err := pqx509.DecodeCertificatePEM([]byte(issued.CertificatePEM))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := pqx509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != "api.example.com" {
		t.Errorf("CN = %q", leaf.Subject.CommonName)
	}
	if len(leaf.ExtKeyUsage) != 2 {
		t.Errorf("EKU = %v", leaf.ExtKeyUsage)
	}
	if len(leaf.SANs.IPAddresses) != 1 {
		t.Errorf("IP SANs = %v", leaf.SANs.IPAddresses)
	}

	rec = h.do(t, http.MethodGet, "/v1/certificates/"+issued.Serial, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get certificate = %d %s", rec.Code, rec.Body.String())
	}
	var fetched map[string]any
	decode(t, rec, &fetched)
	if fetched["status"] != "valid" || fetched["subject_dn"] != "CN=api.example.com" {
		t.Errorf("fetched = %v", fetched)
	}

	rec = h.do(t, http.MethodGet, "/v1/ca/"+interID+"/crl", nil, map[string]string{"X-PQTrust-Passphrase": testPassphrase})
	if rec.Code != http.StatusOK {
		t.Fatalf("CRL = %d %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/pkix-crl" {
		t.Errorf("CRL Content-Type = %q", ct)
	}
	crl, err := pqx509.ParseRevocationList(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("parsing CRL: %v", err)
	}
	if len(crl.Entries) != 0 {
		t.Errorf("CRL has %d entries, want 0", len(crl.Entries))
	}

	rec = h.do(t, http.MethodPost, "/v1/certificates/"+issued.Serial+"/revoke", map[string]any{"reason": 1}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke = %d %s", rec.Code, rec.Body.String())
	}
	var revoked map[string]any
	decode(t, rec, &revoked)
	if revoked["status"] != "revoked" || revoked["reason"] != float64(1) {
		t.Errorf("revoke response = %v", revoked)
	}

	rec = h.do(t, http.MethodPost, "/v1/certificates/"+issued.Serial+"/revoke", map[string]any{"reason": 1}, nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("second revoke = %d %s", rec.Code, rec.Body.String())
	}
	var p map[string]any
	decode(t, rec, &p)
	if p["type"] != "urn:pqtrust:error:conflict" {
		t.Errorf("problem type = %v", p["type"])
	}

	rec = h.do(t, http.MethodGet, "/v1/ca/"+interID+"/crl", nil, map[string]string{
		"X-PQTrust-Passphrase": testPassphrase,
		"Accept":               "application/x-pem-file",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("CRL PEM = %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "BEGIN X509 CRL") {
		t.Errorf("expected a PEM CRL, got %q", rec.Body.String()[:40])
	}
}

func TestErrorMapping(t *testing.T) {
	h := newHarness(t)
	rootID := h.createRoot(t)
	interID := h.createIntermediate(t, rootID)

	t.Run("malformed JSON is 400", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/ca", strings.NewReader("{not json"))
		req.Header.Set("Authorization", "Bearer "+h.token)
		rec := httptest.NewRecorder()
		h.srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d", rec.Code)
		}
		var p map[string]any
		decode(t, rec, &p)
		if p["type"] != "urn:pqtrust:error:invalid-request" {
			t.Errorf("type = %v", p["type"])
		}
	})

	t.Run("unknown certificate is 404", func(t *testing.T) {
		rec := h.do(t, http.MethodGet, "/v1/certificates/deadbeef", nil, nil)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("unknown CA is 404", func(t *testing.T) {
		rec := h.do(t, http.MethodGet, "/v1/ca/nope", nil, nil)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d", rec.Code)
		}
	})

	t.Run("wrong passphrase is 403", func(t *testing.T) {
		rec := h.do(t, http.MethodPost, "/v1/certificates", map[string]any{
			"ca_id":      interID,
			"passphrase": "wrong",
			"subject":    map[string]any{"common_name": "x.example.com"},
			"dns_names":  []string{"x.example.com"},
		}, nil)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d %s", rec.Code, rec.Body.String())
		}
		var p map[string]any
		decode(t, rec, &p)
		if p["type"] != "urn:pqtrust:error:wrong-passphrase" {
			t.Errorf("type = %v", p["type"])
		}
	})

	t.Run("policy violation is 422", func(t *testing.T) {
		rec := h.do(t, http.MethodPost, "/v1/certificates", map[string]any{
			"ca_id":         interID,
			"passphrase":    testPassphrase,
			"subject":       map[string]any{"common_name": "long.example.com"},
			"dns_names":     []string{"long.example.com"},
			"validity_days": 5000,
		}, nil)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d %s", rec.Code, rec.Body.String())
		}
		var p map[string]any
		decode(t, rec, &p)
		if p["type"] != "urn:pqtrust:error:constraint-violation" {
			t.Errorf("type = %v", p["type"])
		}
	})

	t.Run("bad algorithm name is 400", func(t *testing.T) {
		rec := h.do(t, http.MethodPost, "/v1/certificates", map[string]any{
			"ca_id":      interID,
			"passphrase": testPassphrase,
			"subject":    map[string]any{"common_name": "x.example.com"},
			"dns_names":  []string{"x.example.com"},
			"algorithm":  "RSA-2048",
		}, nil)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("bad IP address is 400", func(t *testing.T) {
		rec := h.do(t, http.MethodPost, "/v1/certificates", map[string]any{
			"ca_id":        interID,
			"passphrase":   testPassphrase,
			"subject":      map[string]any{"common_name": "x.example.com"},
			"ip_addresses": []string{"not-an-ip"},
		}, nil)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("bad revocation reason is 422 or 400", func(t *testing.T) {
		rec := h.do(t, http.MethodPost, "/v1/certificates", map[string]any{
			"ca_id":      interID,
			"passphrase": testPassphrase,
			"subject":    map[string]any{"common_name": "reason.example.com"},
			"dns_names":  []string{"reason.example.com"},
		}, nil)
		if rec.Code != http.StatusCreated {
			t.Fatalf("issue = %d %s", rec.Code, rec.Body.String())
		}
		var issued map[string]any
		decode(t, rec, &issued)
		rec = h.do(t, http.MethodPost, "/v1/certificates/"+issued["serial"].(string)+"/revoke", map[string]any{"reason": 99}, nil)
		if rec.Code != http.StatusUnprocessableEntity && rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("unknown route is 404", func(t *testing.T) {
		rec := h.do(t, http.MethodGet, "/v1/nope", nil, nil)
		if rec.Code != http.StatusNotFound {
			t.Errorf("status = %d", rec.Code)
		}
	})

	t.Run("wrong method is 405", func(t *testing.T) {
		rec := h.do(t, http.MethodDelete, "/v1/ca", nil, nil)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("status = %d", rec.Code)
		}
	})
}

func TestTokenHelpers(t *testing.T) {
	a, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("tokens must be unique")
	}
	if len(a) < 40 {
		t.Errorf("token %q is too short", a)
	}
	if HashToken(a) == a {
		t.Error("HashToken must not return the token itself")
	}
	if len(HashToken(a)) != 64 {
		t.Errorf("HashToken length = %d, want 64 hex characters", len(HashToken(a)))
	}
	if HashToken(a) != HashToken(string([]byte(a))) {
		t.Error("HashToken must be deterministic")
	}
}

func makeCSRPEM(t *testing.T, subj pqx509.Name, sans pqx509.SANs) string {
	t.Helper()
	pub, priv, err := pqx509.GenerateKey(rand.Reader, pqx509.MLDSA44)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := priv.Signer()
	if err != nil {
		t.Fatal(err)
	}
	der, err := pqx509.CreateCertificateRequest(rand.Reader, subj, pub, signer, sans)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func TestIssueFromCSRHappyPath(t *testing.T) {
	h := newHarness(t)
	rootID := h.createRoot(t)
	interID := h.createIntermediate(t, rootID)

	csrPEM := makeCSRPEM(t,
		pqx509.Name{CommonName: "csr.example.com", Organization: []string{"pqtrust"}},
		pqx509.SANs{DNSNames: []string{"csr.example.com"}})

	rec := h.do(t, http.MethodPost, "/v1/certificates", map[string]any{
		"ca_id":         interID,
		"passphrase":    testPassphrase,
		"csr_pem":       csrPEM,
		"validity_days": 30,
		"ext_key_usage": []string{"serverAuth", "clientAuth"},
	}, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("issue from CSR: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Serial         string `json:"serial"`
		CertificatePEM string `json:"certificate_pem"`
		ChainPEM       string `json:"chain_pem"`
		PrivateKeyPEM  string `json:"private_key_pem"`
	}
	decode(t, rec, &out)
	if out.PrivateKeyPEM != "" {
		t.Error("CSR issuance must not return a private key")
	}
	if out.CertificatePEM == "" || !strings.Contains(out.ChainPEM, out.CertificatePEM) {
		t.Error("response must carry the certificate and its chain")
	}
	der, err := pqx509.DecodeCertificatePEM([]byte(out.CertificatePEM))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := pqx509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "csr.example.com" {
		t.Errorf("CN = %q", cert.Subject.CommonName)
	}
	if len(cert.SANs.DNSNames) != 1 || cert.SANs.DNSNames[0] != "csr.example.com" {
		t.Errorf("DNSNames = %v", cert.SANs.DNSNames)
	}
	if len(cert.ExtKeyUsage) != 2 {
		t.Errorf("EKU = %v, want serverAuth+clientAuth from the request", cert.ExtKeyUsage)
	}
}

func TestIssueFromCSRRejectsForbiddenFields(t *testing.T) {
	h := newHarness(t)
	rootID := h.createRoot(t)
	interID := h.createIntermediate(t, rootID)
	csrPEM := makeCSRPEM(t, pqx509.Name{CommonName: "x.example.com"}, pqx509.SANs{DNSNames: []string{"x.example.com"}})

	cases := []struct {
		name  string
		extra map[string]any
	}{
		{"subject", map[string]any{"subject": map[string]any{"common_name": "x"}}},
		{"dns_names", map[string]any{"dns_names": []string{"x.example.com"}}},
		{"ip_addresses", map[string]any{"ip_addresses": []string{"127.0.0.1"}}},
		{"email_addresses", map[string]any{"email_addresses": []string{"a@b.c"}}},
		{"algorithm", map[string]any{"algorithm": "ML-DSA-44"}},
		{"store_key", map[string]any{"store_key": true}},
	}
	for _, tc := range cases {
		body := map[string]any{
			"ca_id":      interID,
			"passphrase": testPassphrase,
			"csr_pem":    csrPEM,
		}
		for k, v := range tc.extra {
			body[k] = v
		}
		rec := h.do(t, http.MethodPost, "/v1/certificates", body, nil)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: got %d %s", tc.name, rec.Code, rec.Body.String())
			continue
		}
		if !strings.Contains(rec.Body.String(), tc.name) {
			t.Errorf("%s: problem detail must name the field, got %s", tc.name, rec.Body.String())
		}
	}
}

func TestIssueFromCSRTampered(t *testing.T) {
	h := newHarness(t)
	rootID := h.createRoot(t)
	interID := h.createIntermediate(t, rootID)

	csrPEM := makeCSRPEM(t, pqx509.Name{CommonName: "x.example.com"}, pqx509.SANs{DNSNames: []string{"x.example.com"}})
	block, _ := pem.Decode([]byte(csrPEM))
	block.Bytes[len(block.Bytes)-1] ^= 0xFF
	tampered := string(pem.EncodeToMemory(block))

	rec := h.do(t, http.MethodPost, "/v1/certificates", map[string]any{
		"ca_id": interID, "passphrase": testPassphrase, "csr_pem": tampered,
	}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("tampered CSR: got %d %s", rec.Code, rec.Body.String())
	}
}

func TestIssueKeygenReturnsPKCS8PEM(t *testing.T) {
	h := newHarness(t)
	rootID := h.createRoot(t)
	interID := h.createIntermediate(t, rootID)

	rec := h.do(t, http.MethodPost, "/v1/certificates", map[string]any{
		"ca_id":      interID,
		"passphrase": testPassphrase,
		"subject":    map[string]any{"common_name": "keygen.example.com"},
		"dns_names":  []string{"keygen.example.com"},
	}, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("keygen issue: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		PrivateKeyPEM string `json:"private_key_pem"`
	}
	decode(t, rec, &out)
	if !strings.HasPrefix(out.PrivateKeyPEM, "-----BEGIN PRIVATE KEY-----") {
		t.Fatalf("private_key_pem = %q, want PKCS#8 PEM", out.PrivateKeyPEM[:min(40, len(out.PrivateKeyPEM))])
	}
	if _, err := pqx509.DecodePrivateKeyPEM([]byte(out.PrivateKeyPEM)); err != nil {
		t.Errorf("private_key_pem must decode: %v", err)
	}
}
