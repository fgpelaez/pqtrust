# pqtrust Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build Phase 1 of pqtrust: a Go service that issues post-quantum ML-DSA X.509 certificates from a two-level CA hierarchy over a REST API, with revocation and CRL publication, proven correct by NIST ACVP vectors and an OpenSSL 3.5 interop job.

**Architecture:** Six independent internal packages stacked bottom-up: `pqx509` (pure DER build/parse/verify for ML-DSA certificates and CRLs, no I/O), `keystore` (key generation + AES-256-GCM sealed storage behind a `Backend` interface), `store` (SQLite persistence + migrations), `config` (YAML + env), `ca` (domain logic: profiles, hierarchy rules, issuance, revocation, CRL caching), `api` (HTTP handlers, bearer auth, RFC 7807 errors). `cmd/pqtrustd` wires them together. Each package depends only on packages below it and is tested in isolation.

**Tech Stack:** Go 1.24+, `github.com/cloudflare/circl/sign/mldsa/*` (ML-DSA per FIPS 204), `encoding/asn1`, `modernc.org/sqlite` (pure Go), `golang.org/x/crypto/argon2`, stdlib `net/http` + `crypto/tls`, `gopkg.in/yaml.v3`, `golangci-lint`, `govulncheck`.

**Spec:** `docs/superpowers/specs/2026-08-16-pqtrust-design.md`

## Global Constraints

- Go 1.24 or newer (`go.mod` declares `go 1.24`). `crypto/mlkem` and default `X25519MLKEM768` TLS curve preference require it.
- Module path: `github.com/fernando/pqtrust` (change only if the user provides a different canonical path; if changed, change it everywhere in one commit).
- `CGO_ENABLED=0` for every build and test invocation. Pure-Go dependencies only — never add a dependency that requires cgo.
- License: **AGPL-3.0**. Every new `.go` file starts with no license header (license lives in `LICENSE` only) — do not add per-file headers.
- All PQC signature `AlgorithmIdentifier`s encode with `parameters` **ABSENT** (not `NULL`), per `draft-ietf-lamps-dilithium-certificates`.
- ML-DSA public keys go **raw** into the `SubjectPublicKeyInfo` BIT STRING (no inner OCTET STRING wrapper). Pure-sign mode only: no pre-hash, empty ML-DSA context string.
- OIDs (NIST CSOR), used verbatim: ML-DSA-44 `2.16.840.1.101.3.4.3.17`, ML-DSA-65 `2.16.840.1.101.3.4.3.18`, ML-DSA-87 `2.16.840.1.101.3.4.3.19`.
- Key/signature sizes (FIPS 204), used verbatim in tests: ML-DSA-44 pk 1312 B / sig 2420 B; ML-DSA-65 pk 1952 B / sig 3309 B; ML-DSA-87 pk 2592 B / sig 4627 B. Private key material is handled as a 32-byte seed.
- Serial numbers: 128-bit random **positive** integers.
- SKID and AKID key identifiers: RFC 7093 §2 method 1 — SHA-256 over the SPKI BIT STRING bits, truncated to the leftmost 160 bits (20 bytes).
- Validity: root 10 years, intermediate 5 years, end-entity max 397 days.
- Strictness: malformed DER, unknown **critical** extensions, algorithm/profile mismatches and `pathLenConstraint` violations are always hard errors, never warnings.
- Every package defines sentinel errors; callers wrap with `%w`. Never return bare `errors.New` from an exported function that a caller must classify.
- Argon2id parameters, used verbatim: `t=3, m=64*1024 KiB, p=2, keyLen=32`, 16-byte random salt.
- Out of scope for this plan (Phase 2/3 per spec §12): PKCS#10 CSR flow, `cmd/pqtrust` CLI, SLH-DSA, composite certificates, Dockerfile/compose, CRLDistributionPoints, dashboard, OCSP, metrics.

---

## File Structure

| Path | Responsibility |
|---|---|
| `go.mod`, `go.sum` | Module definition, pinned deps |
| `Makefile` | `build`, `test`, `lint`, `vuln`, `cover` targets |
| `LICENSE` | AGPL-3.0 text |
| `.golangci.yml` | Lint config |
| `internal/pqx509/errors.go` | Sentinel errors for the DER layer |
| `internal/pqx509/algorithm.go` | `Algorithm` enum, OID table, sizes, name strings |
| `internal/pqx509/keys.go` | `PublicKey`, `PrivateKey`, `Signer`, SPKI marshal/parse, key IDs |
| `internal/pqx509/asn1types.go` | Raw ASN.1 struct definitions (certificate, CRL, algorithm identifier) |
| `internal/pqx509/name.go` | Distinguished-name build/parse + string form |
| `internal/pqx509/time.go` | RFC 5280 UTCTime/GeneralizedTime encode/decode |
| `internal/pqx509/extensions.go` | Supported extension marshal/unmarshal + critical-unknown rejection |
| `internal/pqx509/certificate.go` | `Certificate`, `CreateCertificate`, `ParseCertificate` |
| `internal/pqx509/verify.go` | `VerifySignatureFrom`, `Verify` (RFC 5280 §6 subset) |
| `internal/pqx509/crl.go` | `RevocationList`, `CreateRevocationList`, `ParseRevocationList` |
| `internal/pqx509/pem.go` | PEM helpers for certificates and CRLs |
| `internal/keystore/keystore.go` | `Backend` interface, `Generate`, `Load`, `Delete` |
| `internal/keystore/seal.go` | Argon2id + AES-256-GCM seal/unseal envelope |
| `internal/keystore/filebackend.go` | Filesystem-backed sealed key storage |
| `internal/store/store.go` | `Store` type, open/close, sentinel errors |
| `internal/store/migrate.go` | Embedded SQL migrations applied at startup |
| `internal/store/migrations/0001_init.sql` | Initial schema |
| `internal/store/cas.go`, `certificates.go`, `tokens.go` | CRUD + transactional issuance/revocation |
| `internal/config/config.go` | YAML + env load, defaults, validation |
| `internal/ca/profiles.go` | Issuance profiles and constraint checks |
| `internal/ca/engine.go` | `Engine`: CreateCA, IssueCertificate, Revoke, chain assembly |
| `internal/ca/crl.go` | CRL generation with cache invalidation |
| `internal/api/problem.go` | RFC 7807 problem+json writer + domain-error mapping |
| `internal/api/auth.go` | Bearer-token middleware (SHA-256 hash lookup) |
| `internal/api/server.go` | `http.ServeMux` routes |
| `internal/api/handlers_ca.go`, `handlers_certs.go`, `handlers_misc.go` | Handlers |
| `cmd/pqtrustd/main.go` | Flag/subcommand dispatch (`serve`, `token create`) |
| `cmd/pqtrustd/serve.go` | Wiring + TLS server + graceful shutdown |
| `cmd/pqtrustd/token.go` | `token create` subcommand |
| `cmd/pqtrustd/selfsigned.go` | ECDSA P-256 self-signed TLS cert generation |
| `testdata/acvp/` | NIST ACVP ML-DSA vectors |
| `testdata/golden/` | Golden DER fixtures |
| `.github/workflows/ci.yml` | test / lint / vuln jobs |
| `.github/workflows/interop.yml` | OpenSSL 3.5 interop job |
| `scripts/interop.sh` | Interop script (also runnable locally) |
| `README.md`, `LIMITATIONS.md`, `SECURITY.md` | Docs |

---

### Task 0: Toolchain and repository bootstrap

Go is **not installed** on this machine. This task ends with `make test` running a real (trivial) test.

**Files:**
- Create: `go.mod`, `Makefile`, `LICENSE`, `.golangci.yml`, `internal/version/version.go`, `internal/version/version_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: module path `github.com/fernando/pqtrust`; `version.Version` (string constant, `"0.1.0-dev"`); `make test`, `make lint`, `make build`, `make vuln`, `make cover`.

- [ ] **Step 1: Install Go 1.24+**

```bash
# If `go version` already prints go1.24 or newer, skip this step.
GO_TARBALL=go1.24.6.linux-amd64.tar.gz
curl -fsSLO "https://go.dev/dl/${GO_TARBALL}"
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf "${GO_TARBALL}"
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
go version
```

Expected: `go version go1.24.x linux/amd64` or newer. If `go.dev/dl` is unreachable, `sudo snap install go --classic` is an acceptable fallback — verify the version is ≥ 1.24 afterwards.

- [ ] **Step 2: Initialize the module**

```bash
go mod init github.com/fernando/pqtrust
```

- [ ] **Step 3: Write the failing test**

`internal/version/version_test.go`:

```go
package version

import "testing"

func TestVersionIsSet(t *testing.T) {
	if Version == "" {
		t.Fatal("Version must not be empty")
	}
}
```

- [ ] **Step 4: Run it and confirm it fails**

Run: `CGO_ENABLED=0 go test ./internal/version/ -v`
Expected: FAIL — `undefined: Version`.

- [ ] **Step 5: Implement**

`internal/version/version.go`:

```go
// Package version exposes the pqtrust build version.
package version

// Version is the pqtrust release version.
const Version = "0.1.0-dev"
```

- [ ] **Step 6: Run it and confirm it passes**

Run: `CGO_ENABLED=0 go test ./internal/version/ -v`
Expected: PASS.

- [ ] **Step 7: Add the Makefile**

```makefile
GO ?= go
export CGO_ENABLED = 0

.PHONY: build test cover lint vuln tidy

build:
	$(GO) build -trimpath -o bin/pqtrustd ./cmd/pqtrustd

test:
	$(GO) test ./... -count=1

race:
	CGO_ENABLED=1 $(GO) test -race ./... -count=1

cover:
	$(GO) test ./... -count=1 -coverprofile=coverage.out
	$(GO) tool cover -func=coverage.out | tail -n 1

lint:
	golangci-lint run ./...

vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

tidy:
	$(GO) mod tidy
```

Note: the `race` target is the one exception to `CGO_ENABLED=0` — the race detector needs cgo. Production builds stay pure Go.

- [ ] **Step 8: Add `.golangci.yml`**

```yaml
version: "2"
linters:
  enable:
    - errcheck
    - govet
    - ineffassign
    - staticcheck
    - unused
    - errorlint
    - gosec
    - misspell
    - revive
issues:
  max-issues-per-linter: 0
  max-same-issues: 0
```

- [ ] **Step 9: Add the AGPL-3.0 license**

```bash
curl -fsSL https://www.gnu.org/licenses/agpl-3.0.txt -o LICENSE
head -3 LICENSE   # must read "GNU AFFERO GENERAL PUBLIC LICENSE / Version 3, 19 November 2007"
```

- [ ] **Step 10: Verify and commit**

```bash
make test
git add go.mod Makefile LICENSE .golangci.yml internal/version
git commit -m "chore: bootstrap Go module, Makefile, lint config and AGPL-3.0 license"
```

---

### Task 1: pqx509 algorithms, keys and SPKI encoding

**Files:**
- Create: `internal/pqx509/errors.go`, `internal/pqx509/algorithm.go`, `internal/pqx509/keys.go`, `internal/pqx509/asn1types.go`
- Test: `internal/pqx509/algorithm_test.go`, `internal/pqx509/keys_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces — every later task uses these names exactly:
  - `type Algorithm int`; constants `MLDSA44`, `MLDSA65`, `MLDSA87`.
  - `func (a Algorithm) String() string` → `"ML-DSA-44"`, `"ML-DSA-65"`, `"ML-DSA-87"`.
  - `func ParseAlgorithm(s string) (Algorithm, error)` — accepts the `String()` forms case-insensitively.
  - `func (a Algorithm) OID() asn1.ObjectIdentifier`, `func algorithmFromOID(oid asn1.ObjectIdentifier) (Algorithm, error)`.
  - `func (a Algorithm) PublicKeySize() int`, `SignatureSize() int`, `SeedSize() int` (always 32).
  - `type PublicKey struct { Algorithm Algorithm; Bytes []byte }`
  - `type PrivateKey struct { Algorithm Algorithm; Seed []byte }` (32-byte seed)
  - `func GenerateKey(rand io.Reader, a Algorithm) (PublicKey, PrivateKey, error)`
  - `func (k PrivateKey) Signer() (Signer, error)`
  - `type Signer interface { Public() PublicKey; Sign(rand io.Reader, msg []byte) ([]byte, error); Algorithm() Algorithm }`
  - `func Verify(pub PublicKey, msg, sig []byte) error`
  - `func MarshalPKIXPublicKey(pub PublicKey) ([]byte, error)` → DER `SubjectPublicKeyInfo`
  - `func ParsePKIXPublicKey(der []byte) (PublicKey, error)`
  - `func KeyIdentifier(pub PublicKey) ([]byte, error)` — 20 bytes, RFC 7093 method 1
  - Sentinels: `ErrUnknownAlgorithm`, `ErrMalformedDER`, `ErrTrailingData`, `ErrBadSignature`, `ErrUnsupportedCriticalExtension`, `ErrInvalidKeySize`
  - `type algorithmIdentifier struct { Algorithm asn1.ObjectIdentifier; Parameters asn1.RawValue `asn1:"optional"` }` (unexported, in `asn1types.go`)
  - `type subjectPublicKeyInfo struct { Algorithm algorithmIdentifier; PublicKey asn1.BitString }` (unexported)

- [ ] **Step 1: Add the CIRCL dependency**

```bash
go get github.com/cloudflare/circl@latest
go mod tidy
```

- [ ] **Step 2: Write the failing tests**

`internal/pqx509/algorithm_test.go`:

```go
package pqx509

import (
	"encoding/asn1"
	"testing"
)

func TestAlgorithmOIDsAndSizes(t *testing.T) {
	cases := []struct {
		alg     Algorithm
		name    string
		oid     string
		pkSize  int
		sigSize int
	}{
		{MLDSA44, "ML-DSA-44", "2.16.840.1.101.3.4.3.17", 1312, 2420},
		{MLDSA65, "ML-DSA-65", "2.16.840.1.101.3.4.3.18", 1952, 3309},
		{MLDSA87, "ML-DSA-87", "2.16.840.1.101.3.4.3.19", 2592, 4627},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.alg.String(); got != c.name {
				t.Errorf("String() = %q, want %q", got, c.name)
			}
			if got := c.alg.OID().String(); got != c.oid {
				t.Errorf("OID() = %s, want %s", got, c.oid)
			}
			if got := c.alg.PublicKeySize(); got != c.pkSize {
				t.Errorf("PublicKeySize() = %d, want %d", got, c.pkSize)
			}
			if got := c.alg.SignatureSize(); got != c.sigSize {
				t.Errorf("SignatureSize() = %d, want %d", got, c.sigSize)
			}
			back, err := algorithmFromOID(c.alg.OID())
			if err != nil || back != c.alg {
				t.Errorf("algorithmFromOID round-trip = %v, %v", back, err)
			}
			parsed, err := ParseAlgorithm(c.name)
			if err != nil || parsed != c.alg {
				t.Errorf("ParseAlgorithm(%q) = %v, %v", c.name, parsed, err)
			}
		})
	}
}

func TestUnknownAlgorithm(t *testing.T) {
	if _, err := ParseAlgorithm("ML-DSA-99"); err == nil {
		t.Error("ParseAlgorithm should reject unknown names")
	}
	// RSA encryption OID must not resolve.
	if _, err := algorithmFromOID(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}); err == nil {
		t.Error("algorithmFromOID should reject non-ML-DSA OIDs")
	}
}
```

`internal/pqx509/keys_test.go`:

```go
package pqx509

import (
	"bytes"
	"crypto/rand"
	"encoding/asn1"
	"testing"
)

func TestGenerateSignVerify(t *testing.T) {
	for _, alg := range []Algorithm{MLDSA44, MLDSA65, MLDSA87} {
		t.Run(alg.String(), func(t *testing.T) {
			pub, priv, err := GenerateKey(rand.Reader, alg)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			if len(pub.Bytes) != alg.PublicKeySize() {
				t.Fatalf("public key size = %d, want %d", len(pub.Bytes), alg.PublicKeySize())
			}
			if len(priv.Seed) != 32 {
				t.Fatalf("seed size = %d, want 32", len(priv.Seed))
			}
			signer, err := priv.Signer()
			if err != nil {
				t.Fatalf("Signer: %v", err)
			}
			if !bytes.Equal(signer.Public().Bytes, pub.Bytes) {
				t.Fatal("signer public key does not match generated public key")
			}
			msg := []byte("pqtrust test message")
			sig, err := signer.Sign(rand.Reader, msg)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if len(sig) != alg.SignatureSize() {
				t.Fatalf("signature size = %d, want %d", len(sig), alg.SignatureSize())
			}
			if err := Verify(pub, msg, sig); err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if err := Verify(pub, []byte("other message"), sig); err == nil {
				t.Fatal("Verify must fail on a different message")
			}
			sig[0] ^= 0xff
			if err := Verify(pub, msg, sig); err == nil {
				t.Fatal("Verify must fail on a corrupted signature")
			}
		})
	}
}

func TestSPKIRoundTripAndEncoding(t *testing.T) {
	pub, _, err := GenerateKey(rand.Reader, MLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	der, err := MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatal(err)
	}
	if back.Algorithm != pub.Algorithm || !bytes.Equal(back.Bytes, pub.Bytes) {
		t.Fatal("SPKI round-trip mismatch")
	}

	// The AlgorithmIdentifier must carry NO parameters (not even NULL).
	var spki subjectPublicKeyInfo
	rest, err := asn1.Unmarshal(der, &spki)
	if err != nil || len(rest) != 0 {
		t.Fatalf("unmarshal spki: %v, rest=%d", err, len(rest))
	}
	if len(spki.Algorithm.Parameters.FullBytes) != 0 {
		t.Errorf("AlgorithmIdentifier.parameters must be absent, got % x", spki.Algorithm.Parameters.FullBytes)
	}
	// The public key must be raw in the BIT STRING, with no unused bits.
	if !bytes.Equal(spki.PublicKey.Bytes, pub.Bytes) {
		t.Error("public key must sit raw in the SPKI BIT STRING")
	}
	if spki.PublicKey.BitLength != len(pub.Bytes)*8 {
		t.Errorf("BitLength = %d, want %d", spki.PublicKey.BitLength, len(pub.Bytes)*8)
	}
}

func TestParsePKIXRejectsTrailingData(t *testing.T) {
	pub, _, _ := GenerateKey(rand.Reader, MLDSA44)
	der, _ := MarshalPKIXPublicKey(pub)
	if _, err := ParsePKIXPublicKey(append(der, 0x00)); err == nil {
		t.Error("ParsePKIXPublicKey must reject trailing data")
	}
}

func TestKeyIdentifierIs20BytesAndStable(t *testing.T) {
	pub, _, _ := GenerateKey(rand.Reader, MLDSA44)
	a, err := KeyIdentifier(pub)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 20 {
		t.Fatalf("KeyIdentifier length = %d, want 20", len(a))
	}
	b, _ := KeyIdentifier(pub)
	if !bytes.Equal(a, b) {
		t.Fatal("KeyIdentifier must be deterministic")
	}
	other, _, _ := GenerateKey(rand.Reader, MLDSA44)
	c, _ := KeyIdentifier(other)
	if bytes.Equal(a, c) {
		t.Fatal("different keys must produce different identifiers")
	}
}
```

- [ ] **Step 3: Run the tests and confirm they fail**

Run: `CGO_ENABLED=0 go test ./internal/pqx509/ -v`
Expected: compile failure — undefined identifiers.

- [ ] **Step 4: Implement `errors.go`**

```go
// Package pqx509 builds, parses and verifies X.509 certificates and CRLs that
// carry post-quantum (ML-DSA, FIPS 204) signature algorithms. It performs no
// I/O and holds no state.
package pqx509

import "errors"

var (
	// ErrUnknownAlgorithm reports an unrecognized signature algorithm name or OID.
	ErrUnknownAlgorithm = errors.New("pqx509: unknown algorithm")
	// ErrMalformedDER reports input that is not valid DER for the expected structure.
	ErrMalformedDER = errors.New("pqx509: malformed DER")
	// ErrTrailingData reports valid DER followed by unexpected bytes.
	ErrTrailingData = errors.New("pqx509: trailing data after DER structure")
	// ErrBadSignature reports a signature that does not verify.
	ErrBadSignature = errors.New("pqx509: signature verification failed")
	// ErrUnsupportedCriticalExtension reports a critical extension pqtrust does not implement.
	ErrUnsupportedCriticalExtension = errors.New("pqx509: unsupported critical extension")
	// ErrInvalidKeySize reports key material whose length does not match its algorithm.
	ErrInvalidKeySize = errors.New("pqx509: invalid key size")
)
```

- [ ] **Step 5: Implement `algorithm.go`**

```go
package pqx509

import (
	"encoding/asn1"
	"fmt"
	"strings"
)

// Algorithm identifies a post-quantum signature algorithm.
type Algorithm int

// Supported signature algorithms.
const (
	MLDSA44 Algorithm = iota + 1
	MLDSA65
	MLDSA87
)

type algorithmInfo struct {
	name    string
	oid     asn1.ObjectIdentifier
	pkSize  int
	sigSize int
}

var algorithms = map[Algorithm]algorithmInfo{
	MLDSA44: {"ML-DSA-44", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}, 1312, 2420},
	MLDSA65: {"ML-DSA-65", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}, 1952, 3309},
	MLDSA87: {"ML-DSA-87", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}, 2592, 4627},
}

// String returns the canonical FIPS 204 name, e.g. "ML-DSA-65".
func (a Algorithm) String() string {
	if info, ok := algorithms[a]; ok {
		return info.name
	}
	return fmt.Sprintf("Algorithm(%d)", int(a))
}

// OID returns the NIST CSOR signature algorithm OID.
func (a Algorithm) OID() asn1.ObjectIdentifier { return algorithms[a].oid }

// PublicKeySize returns the encoded public key length in bytes.
func (a Algorithm) PublicKeySize() int { return algorithms[a].pkSize }

// SignatureSize returns the signature length in bytes.
func (a Algorithm) SignatureSize() int { return algorithms[a].sigSize }

// SeedSize returns the private key seed length in bytes.
func (a Algorithm) SeedSize() int { return 32 }

// Valid reports whether a is a supported algorithm.
func (a Algorithm) Valid() bool { _, ok := algorithms[a]; return ok }

// ParseAlgorithm resolves a canonical algorithm name, case-insensitively.
func ParseAlgorithm(s string) (Algorithm, error) {
	for alg, info := range algorithms {
		if strings.EqualFold(s, info.name) {
			return alg, nil
		}
	}
	return 0, fmt.Errorf("%w: %q", ErrUnknownAlgorithm, s)
}

func algorithmFromOID(oid asn1.ObjectIdentifier) (Algorithm, error) {
	for alg, info := range algorithms {
		if info.oid.Equal(oid) {
			return alg, nil
		}
	}
	return 0, fmt.Errorf("%w: OID %s", ErrUnknownAlgorithm, oid)
}
```

- [ ] **Step 6: Implement `asn1types.go`**

These structures are the single source of truth for the DER layout; later tasks extend this file.

```go
package pqx509

import (
	"encoding/asn1"
	"math/big"
)

// algorithmIdentifier encodes an AlgorithmIdentifier whose parameters field is
// optional so that it can be, and for ML-DSA always is, absent.
type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type subjectPublicKeyInfo struct {
	Algorithm algorithmIdentifier
	PublicKey asn1.BitString
}

type extension struct {
	ID       asn1.ObjectIdentifier
	Critical bool `asn1:"optional"`
	Value    []byte
}

type validity struct {
	NotBefore asn1.RawValue
	NotAfter  asn1.RawValue
}

type tbsCertificate struct {
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm algorithmIdentifier
	Issuer             asn1.RawValue
	Validity           validity
	Subject            asn1.RawValue
	PublicKey          subjectPublicKeyInfo
	Extensions         []extension `asn1:"optional,explicit,tag:3"`
}

type certificateDER struct {
	TBSCertificate     asn1.RawValue
	SignatureAlgorithm algorithmIdentifier
	SignatureValue     asn1.BitString
}
```

- [ ] **Step 7: Implement `keys.go`**

```go
package pqx509

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// PublicKey is an algorithm-tagged ML-DSA public key in its FIPS 204 encoding.
type PublicKey struct {
	Algorithm Algorithm
	Bytes     []byte
}

// PrivateKey is an algorithm-tagged ML-DSA private key, held as its 32-byte seed.
type PrivateKey struct {
	Algorithm Algorithm
	Seed      []byte
}

// Signer signs messages with a post-quantum private key. keystore-loaded keys
// implement it, which lets a future HSM backend sign without exposing key bytes.
type Signer interface {
	Public() PublicKey
	Sign(rand io.Reader, msg []byte) ([]byte, error)
	Algorithm() Algorithm
}

// GenerateKey generates a key pair for alg using entropy from rand.
func GenerateKey(rand io.Reader, alg Algorithm) (PublicKey, PrivateKey, error) {
	if !alg.Valid() {
		return PublicKey{}, PrivateKey{}, fmt.Errorf("%w: %v", ErrUnknownAlgorithm, alg)
	}
	var seed [32]byte
	if _, err := io.ReadFull(rand, seed[:]); err != nil {
		return PublicKey{}, PrivateKey{}, fmt.Errorf("pqx509: reading seed: %w", err)
	}
	priv := PrivateKey{Algorithm: alg, Seed: seed[:]}
	signer, err := priv.Signer()
	if err != nil {
		return PublicKey{}, PrivateKey{}, err
	}
	return signer.Public(), priv, nil
}

type circlSigner struct {
	alg  Algorithm
	pub  PublicKey
	sign func(msg []byte) ([]byte, error)
}

func (s *circlSigner) Public() PublicKey     { return s.pub }
func (s *circlSigner) Algorithm() Algorithm  { return s.alg }
func (s *circlSigner) Sign(_ io.Reader, msg []byte) ([]byte, error) {
	return s.sign(msg)
}

// Signer expands the seed and returns a Signer. The returned Signer signs in
// pure mode with an empty ML-DSA context string, as X.509 requires.
func (k PrivateKey) Signer() (Signer, error) {
	if len(k.Seed) != 32 {
		return nil, fmt.Errorf("%w: seed is %d bytes, want 32", ErrInvalidKeySize, len(k.Seed))
	}
	var seed [32]byte
	copy(seed[:], k.Seed)

	switch k.Algorithm {
	case MLDSA44:
		pub, sk := mldsa44.NewKeyFromSeed(&seed)
		return &circlSigner{alg: k.Algorithm, pub: PublicKey{k.Algorithm, pub.Bytes()}, sign: func(msg []byte) ([]byte, error) {
			return sk.Sign(nil, msg, crypto.Hash(0))
		}}, nil
	case MLDSA65:
		pub, sk := mldsa65.NewKeyFromSeed(&seed)
		return &circlSigner{alg: k.Algorithm, pub: PublicKey{k.Algorithm, pub.Bytes()}, sign: func(msg []byte) ([]byte, error) {
			return sk.Sign(nil, msg, crypto.Hash(0))
		}}, nil
	case MLDSA87:
		pub, sk := mldsa87.NewKeyFromSeed(&seed)
		return &circlSigner{alg: k.Algorithm, pub: PublicKey{k.Algorithm, pub.Bytes()}, sign: func(msg []byte) ([]byte, error) {
			return sk.Sign(nil, msg, crypto.Hash(0))
		}}, nil
	default:
		return nil, fmt.Errorf("%w: %v", ErrUnknownAlgorithm, k.Algorithm)
	}
}

// Verify checks a pure-mode ML-DSA signature with an empty context string.
func Verify(pub PublicKey, msg, sig []byte) error {
	if len(pub.Bytes) != pub.Algorithm.PublicKeySize() {
		return fmt.Errorf("%w: public key is %d bytes, want %d", ErrInvalidKeySize, len(pub.Bytes), pub.Algorithm.PublicKeySize())
	}
	var ok bool
	switch pub.Algorithm {
	case MLDSA44:
		var k mldsa44.PublicKey
		if err := k.UnmarshalBinary(pub.Bytes); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidKeySize, err)
		}
		ok = mldsa44.Verify(&k, msg, nil, sig)
	case MLDSA65:
		var k mldsa65.PublicKey
		if err := k.UnmarshalBinary(pub.Bytes); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidKeySize, err)
		}
		ok = mldsa65.Verify(&k, msg, nil, sig)
	case MLDSA87:
		var k mldsa87.PublicKey
		if err := k.UnmarshalBinary(pub.Bytes); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidKeySize, err)
		}
		ok = mldsa87.Verify(&k, msg, nil, sig)
	default:
		return fmt.Errorf("%w: %v", ErrUnknownAlgorithm, pub.Algorithm)
	}
	if !ok {
		return ErrBadSignature
	}
	return nil
}

// MarshalPKIXPublicKey encodes pub as a DER SubjectPublicKeyInfo, with the raw
// key in the BIT STRING and no AlgorithmIdentifier parameters.
func MarshalPKIXPublicKey(pub PublicKey) ([]byte, error) {
	if !pub.Algorithm.Valid() {
		return nil, fmt.Errorf("%w: %v", ErrUnknownAlgorithm, pub.Algorithm)
	}
	if len(pub.Bytes) != pub.Algorithm.PublicKeySize() {
		return nil, fmt.Errorf("%w: public key is %d bytes, want %d", ErrInvalidKeySize, len(pub.Bytes), pub.Algorithm.PublicKeySize())
	}
	der, err := asn1.Marshal(subjectPublicKeyInfo{
		Algorithm: algorithmIdentifier{Algorithm: pub.Algorithm.OID()},
		PublicKey: asn1.BitString{Bytes: pub.Bytes, BitLength: len(pub.Bytes) * 8},
	})
	if err != nil {
		return nil, fmt.Errorf("pqx509: marshaling SPKI: %w", err)
	}
	return der, nil
}

// ParsePKIXPublicKey decodes a DER SubjectPublicKeyInfo.
func ParsePKIXPublicKey(der []byte) (PublicKey, error) {
	var spki subjectPublicKeyInfo
	rest, err := asn1.Unmarshal(der, &spki)
	if err != nil {
		return PublicKey{}, fmt.Errorf("%w: SPKI: %w", ErrMalformedDER, err)
	}
	if len(rest) != 0 {
		return PublicKey{}, fmt.Errorf("%w: %d bytes after SPKI", ErrTrailingData, len(rest))
	}
	return publicKeyFromSPKI(spki)
}

func publicKeyFromSPKI(spki subjectPublicKeyInfo) (PublicKey, error) {
	alg, err := algorithmFromOID(spki.Algorithm.Algorithm)
	if err != nil {
		return PublicKey{}, err
	}
	if len(spki.Algorithm.Parameters.FullBytes) != 0 {
		return PublicKey{}, fmt.Errorf("%w: ML-DSA AlgorithmIdentifier must omit parameters", ErrMalformedDER)
	}
	if spki.PublicKey.BitLength%8 != 0 {
		return PublicKey{}, fmt.Errorf("%w: SPKI BIT STRING has unused bits", ErrMalformedDER)
	}
	if len(spki.PublicKey.Bytes) != alg.PublicKeySize() {
		return PublicKey{}, fmt.Errorf("%w: %s public key is %d bytes, want %d", ErrInvalidKeySize, alg, len(spki.PublicKey.Bytes), alg.PublicKeySize())
	}
	return PublicKey{Algorithm: alg, Bytes: bytes.Clone(spki.PublicKey.Bytes)}, nil
}

// KeyIdentifier computes an RFC 7093 section 2 method 1 key identifier: the
// leftmost 160 bits of SHA-256 over the SPKI BIT STRING bits.
func KeyIdentifier(pub PublicKey) ([]byte, error) {
	if len(pub.Bytes) != pub.Algorithm.PublicKeySize() {
		return nil, fmt.Errorf("%w: public key is %d bytes, want %d", ErrInvalidKeySize, len(pub.Bytes), pub.Algorithm.PublicKeySize())
	}
	sum := sha256.Sum256(pub.Bytes)
	return sum[:20], nil
}
```

- [ ] **Step 8: Run the tests and confirm they pass**

Run: `CGO_ENABLED=0 go test ./internal/pqx509/ -v`
Expected: PASS, all subtests.

- [ ] **Step 9: Commit**

```bash
git add internal/pqx509 go.mod go.sum
git commit -m "feat(pqx509): ML-DSA algorithms, keys, SPKI encoding and key identifiers"
```

---

### Task 2: Distinguished names and RFC 5280 time encoding

**Files:**
- Create: `internal/pqx509/name.go`, `internal/pqx509/time.go`
- Test: `internal/pqx509/name_test.go`, `internal/pqx509/time_test.go`

**Interfaces:**
- Consumes: `ErrMalformedDER`, `ErrTrailingData` (Task 1).
- Produces:
  - `type Name struct { Country, Organization, OrganizationalUnit []string; Locality, Province []string; CommonName string }`
  - `func (n Name) ToRDNSequence() ([]byte, error)` — DER `RDNSequence`
  - `func ParseName(der []byte) (Name, error)`
  - `func (n Name) String() string` — RFC 4514-ish, `CN=x,O=y,C=z` order
  - `func ParseNameString(s string) (Name, error)` — parses the `String()` form; used by `api` to accept `subject_dn`
  - `func marshalTime(t time.Time) (asn1.RawValue, error)`, `func parseTime(rv asn1.RawValue) (time.Time, error)`

- [ ] **Step 1: Write the failing tests**

`internal/pqx509/time_test.go`:

```go
package pqx509

import (
	"testing"
	"time"
)

func TestMarshalTimeChoosesEncodingByYear(t *testing.T) {
	cases := []struct {
		in      time.Time
		wantTag int // 23 = UTCTime, 24 = GeneralizedTime
	}{
		{time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC), 23},
		{time.Date(2049, 12, 31, 23, 59, 59, 0, time.UTC), 23},
		{time.Date(2050, 1, 1, 0, 0, 0, 0, time.UTC), 24},
		{time.Date(2075, 6, 1, 0, 0, 0, 0, time.UTC), 24},
	}
	for _, c := range cases {
		rv, err := marshalTime(c.in)
		if err != nil {
			t.Fatalf("marshalTime(%v): %v", c.in, err)
		}
		if rv.Tag != c.wantTag {
			t.Errorf("marshalTime(%v) tag = %d, want %d", c.in, rv.Tag, c.wantTag)
		}
		back, err := parseTime(rv)
		if err != nil {
			t.Fatalf("parseTime: %v", err)
		}
		if !back.Equal(c.in) {
			t.Errorf("round-trip = %v, want %v", back, c.in)
		}
	}
}

func TestMarshalTimeTruncatesSubSecondAndNormalizesZone(t *testing.T) {
	loc := time.FixedZone("UTC+2", 2*3600)
	in := time.Date(2030, 3, 4, 5, 6, 7, 999_000_000, loc)
	rv, err := marshalTime(in)
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseTime(rv)
	if err != nil {
		t.Fatal(err)
	}
	want := in.Truncate(time.Second).UTC()
	if !got.Equal(want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if got.Location() != time.UTC {
		t.Errorf("parsed time must be UTC, got %v", got.Location())
	}
}
```

`internal/pqx509/name_test.go`:

```go
package pqx509

import (
	"reflect"
	"testing"
)

func TestNameRoundTrip(t *testing.T) {
	n := Name{
		Country:            []string{"ES"},
		Organization:       []string{"pqtrust"},
		OrganizationalUnit: []string{"PKI"},
		Locality:           []string{"Madrid"},
		Province:           []string{"Madrid"},
		CommonName:         "pqtrust Root CA",
	}
	der, err := n.ToRDNSequence()
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseName(der)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(n, back) {
		t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", back, n)
	}
}

func TestNameStringRoundTrip(t *testing.T) {
	n := Name{Country: []string{"ES"}, Organization: []string{"pqtrust"}, CommonName: "api.example.com"}
	s := n.String()
	if s != "CN=api.example.com,O=pqtrust,C=ES" {
		t.Fatalf("String() = %q", s)
	}
	back, err := ParseNameString(s)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(n, back) {
		t.Errorf("ParseNameString mismatch:\n got %+v\nwant %+v", back, n)
	}
}

func TestEmptyNameEncodesAsEmptySequence(t *testing.T) {
	der, err := Name{}.ToRDNSequence()
	if err != nil {
		t.Fatal(err)
	}
	if len(der) != 2 || der[0] != 0x30 || der[1] != 0x00 {
		t.Errorf("empty name DER = % x, want 30 00", der)
	}
}

func TestParseNameRejectsTrailingData(t *testing.T) {
	der, _ := Name{CommonName: "x"}.ToRDNSequence()
	if _, err := ParseName(append(der, 0x00)); err == nil {
		t.Error("ParseName must reject trailing data")
	}
}

func TestParseNameStringRejectsMalformed(t *testing.T) {
	for _, s := range []string{"CN", "=value", "XX=unsupported"} {
		if _, err := ParseNameString(s); err == nil {
			t.Errorf("ParseNameString(%q) must fail", s)
		}
	}
}
```

- [ ] **Step 2: Run and confirm failure**

Run: `CGO_ENABLED=0 go test ./internal/pqx509/ -run 'Name|Time' -v`
Expected: compile failure — undefined identifiers.

- [ ] **Step 3: Implement `time.go`**

```go
package pqx509

import (
	"encoding/asn1"
	"fmt"
	"time"
)

const (
	tagUTCTime         = 23
	tagGeneralizedTime = 24
)

// marshalTime encodes t per RFC 5280 4.1.2.5: UTCTime through 2049,
// GeneralizedTime from 2050 on. Seconds are always present; the zone is Z.
func marshalTime(t time.Time) (asn1.RawValue, error) {
	u := t.UTC().Truncate(time.Second)
	var der []byte
	var err error
	if u.Year() < 2050 {
		der, err = asn1.MarshalWithParams(u, "utc")
	} else {
		der, err = asn1.MarshalWithParams(u, "generalized")
	}
	if err != nil {
		return asn1.RawValue{}, fmt.Errorf("pqx509: marshaling time %v: %w", t, err)
	}
	var rv asn1.RawValue
	if _, err := asn1.Unmarshal(der, &rv); err != nil {
		return asn1.RawValue{}, fmt.Errorf("pqx509: re-reading marshaled time: %w", err)
	}
	return rv, nil
}

// parseTime decodes a UTCTime or GeneralizedTime raw value into a UTC time.
func parseTime(rv asn1.RawValue) (time.Time, error) {
	var t time.Time
	var params string
	switch rv.Tag {
	case tagUTCTime:
		params = "utc"
	case tagGeneralizedTime:
		params = "generalized"
	default:
		return time.Time{}, fmt.Errorf("%w: time has tag %d, want 23 or 24", ErrMalformedDER, rv.Tag)
	}
	rest, err := asn1.UnmarshalWithParams(rv.FullBytes, &t, params)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: time: %w", ErrMalformedDER, err)
	}
	if len(rest) != 0 {
		return time.Time{}, fmt.Errorf("%w: %d bytes after time", ErrTrailingData, len(rest))
	}
	return t.UTC(), nil
}
```

- [ ] **Step 4: Implement `name.go`**

`ParseName` keeps only the attribute types pqtrust supports and rejects nothing else — unknown attribute types in a parsed name are dropped from the struct, but `ParseName` never invents data, and issuance only ever emits the supported set. Note the DER SET OF ordering requirement does not arise because every RDN pqtrust emits is single-valued.

```go
package pqx509

import (
	"encoding/asn1"
	"fmt"
	"strings"
)

var (
	oidCountry            = asn1.ObjectIdentifier{2, 5, 4, 6}
	oidOrganization       = asn1.ObjectIdentifier{2, 5, 4, 10}
	oidOrganizationalUnit = asn1.ObjectIdentifier{2, 5, 4, 11}
	oidCommonName         = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidLocality           = asn1.ObjectIdentifier{2, 5, 4, 7}
	oidProvince           = asn1.ObjectIdentifier{2, 5, 4, 8}
)

// Name is the subset of X.501 Name attributes pqtrust supports.
type Name struct {
	Country            []string
	Organization       []string
	OrganizationalUnit []string
	Locality           []string
	Province           []string
	CommonName         string
}

type attributeTypeAndValue struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue
}

// ToRDNSequence encodes n as a DER RDNSequence. Attribute order is
// C, ST, L, O, OU, CN — most general to most specific, as X.500 expects.
func (n Name) ToRDNSequence() ([]byte, error) {
	var rdns []([]attributeTypeAndValue)
	add := func(oid asn1.ObjectIdentifier, values []string) error {
		for _, v := range values {
			rv, err := marshalDirectoryString(v)
			if err != nil {
				return err
			}
			rdns = append(rdns, []attributeTypeAndValue{{Type: oid, Value: rv}})
		}
		return nil
	}
	for _, part := range []struct {
		oid    asn1.ObjectIdentifier
		values []string
	}{
		{oidCountry, n.Country},
		{oidProvince, n.Province},
		{oidLocality, n.Locality},
		{oidOrganization, n.Organization},
		{oidOrganizationalUnit, n.OrganizationalUnit},
	} {
		if err := add(part.oid, part.values); err != nil {
			return nil, err
		}
	}
	if n.CommonName != "" {
		if err := add(oidCommonName, []string{n.CommonName}); err != nil {
			return nil, err
		}
	}
	der, err := asn1.Marshal(rdns)
	if err != nil {
		return nil, fmt.Errorf("pqx509: marshaling name: %w", err)
	}
	return der, nil
}

func marshalDirectoryString(s string) (asn1.RawValue, error) {
	// PrintableString when possible (widest interoperability), else UTF8String.
	params := "utf8"
	if isPrintableString(s) {
		params = "printable"
	}
	der, err := asn1.MarshalWithParams(s, params)
	if err != nil {
		return asn1.RawValue{}, fmt.Errorf("pqx509: marshaling %q: %w", s, err)
	}
	var rv asn1.RawValue
	if _, err := asn1.Unmarshal(der, &rv); err != nil {
		return asn1.RawValue{}, fmt.Errorf("pqx509: re-reading marshaled string: %w", err)
	}
	return rv, nil
}

func isPrintableString(s string) bool {
	const extra = " '()+,-./:=?"
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune(extra, r):
		default:
			return false
		}
	}
	return true
}

// ParseName decodes a DER RDNSequence, keeping the attribute types pqtrust supports.
func ParseName(der []byte) (Name, error) {
	var rdns []([]attributeTypeAndValue)
	rest, err := asn1.Unmarshal(der, &rdns)
	if err != nil {
		return Name{}, fmt.Errorf("%w: name: %w", ErrMalformedDER, err)
	}
	if len(rest) != 0 {
		return Name{}, fmt.Errorf("%w: %d bytes after name", ErrTrailingData, len(rest))
	}
	var n Name
	for _, rdn := range rdns {
		for _, atv := range rdn {
			value, err := parseDirectoryString(atv.Value)
			if err != nil {
				return Name{}, err
			}
			switch {
			case atv.Type.Equal(oidCountry):
				n.Country = append(n.Country, value)
			case atv.Type.Equal(oidProvince):
				n.Province = append(n.Province, value)
			case atv.Type.Equal(oidLocality):
				n.Locality = append(n.Locality, value)
			case atv.Type.Equal(oidOrganization):
				n.Organization = append(n.Organization, value)
			case atv.Type.Equal(oidOrganizationalUnit):
				n.OrganizationalUnit = append(n.OrganizationalUnit, value)
			case atv.Type.Equal(oidCommonName):
				n.CommonName = value
			}
		}
	}
	return n, nil
}

func parseDirectoryString(rv asn1.RawValue) (string, error) {
	switch rv.Tag {
	case asn1.TagPrintableString, asn1.TagUTF8String, asn1.TagIA5String, asn1.TagT61String:
		return string(rv.Bytes), nil
	default:
		return "", fmt.Errorf("%w: unsupported directory string tag %d", ErrMalformedDER, rv.Tag)
	}
}

// String renders n as a comma-separated RFC 4514-style DN, most specific first.
func (n Name) String() string {
	var parts []string
	if n.CommonName != "" {
		parts = append(parts, "CN="+n.CommonName)
	}
	for _, v := range n.OrganizationalUnit {
		parts = append(parts, "OU="+v)
	}
	for _, v := range n.Organization {
		parts = append(parts, "O="+v)
	}
	for _, v := range n.Locality {
		parts = append(parts, "L="+v)
	}
	for _, v := range n.Province {
		parts = append(parts, "ST="+v)
	}
	for _, v := range n.Country {
		parts = append(parts, "C="+v)
	}
	return strings.Join(parts, ",")
}

// ParseNameString parses the form String produces. Unknown attribute types are
// a hard error so that a typo in an API request never silently drops a field.
func ParseNameString(s string) (Name, error) {
	var n Name
	if strings.TrimSpace(s) == "" {
		return n, fmt.Errorf("pqx509: empty distinguished name")
	}
	for _, part := range strings.Split(s, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || key == "" || value == "" {
			return Name{}, fmt.Errorf("pqx509: malformed DN component %q", part)
		}
		switch strings.ToUpper(key) {
		case "CN":
			n.CommonName = value
		case "OU":
			n.OrganizationalUnit = append(n.OrganizationalUnit, value)
		case "O":
			n.Organization = append(n.Organization, value)
		case "L":
			n.Locality = append(n.Locality, value)
		case "ST":
			n.Province = append(n.Province, value)
		case "C":
			n.Country = append(n.Country, value)
		default:
			return Name{}, fmt.Errorf("pqx509: unsupported DN attribute %q", key)
		}
	}
	return n, nil
}
```

- [ ] **Step 5: Run the tests and confirm they pass**

Run: `CGO_ENABLED=0 go test ./internal/pqx509/ -v`
Expected: PASS. If `TestNameStringRoundTrip` fails on ordering, fix `String()`, not the test — `CN=...,O=...,C=...` is the required output.

- [ ] **Step 6: Commit**

```bash
git add internal/pqx509
git commit -m "feat(pqx509): distinguished names and RFC 5280 time encoding"
```

---

### Task 3: Certificate extensions

**Files:**
- Create: `internal/pqx509/extensions.go`
- Test: `internal/pqx509/extensions_test.go`

**Interfaces:**
- Consumes: `extension` struct, `ErrMalformedDER`, `ErrUnsupportedCriticalExtension` (Task 1).
- Produces:
  - `type KeyUsage uint16` with `KeyUsageDigitalSignature`, `KeyUsageKeyCertSign`, `KeyUsageCRLSign` (bit values per RFC 5280: digitalSignature = bit 0, keyCertSign = bit 5, cRLSign = bit 6).
  - `type ExtKeyUsage int` with `ExtKeyUsageServerAuth`, `ExtKeyUsageClientAuth`.
  - `type BasicConstraints struct { IsCA bool; MaxPathLen int; MaxPathLenSet bool }`
  - `type SANs struct { DNSNames []string; EmailAddresses []string; IPAddresses []net.IP }`
  - `func marshalBasicConstraints(bc BasicConstraints) ([]byte, error)` / `parseBasicConstraints([]byte) (BasicConstraints, error)`
  - `func marshalKeyUsage(ku KeyUsage) ([]byte, error)` / `parseKeyUsage([]byte) (KeyUsage, error)`
  - `func marshalExtKeyUsage([]ExtKeyUsage) ([]byte, error)` / `parseExtKeyUsage([]byte) ([]ExtKeyUsage, error)`
  - `func marshalKeyID(id []byte) ([]byte, error)` / `parseSubjectKeyID([]byte) ([]byte, error)`
  - `func marshalAuthorityKeyID(id []byte) ([]byte, error)` / `parseAuthorityKeyID([]byte) ([]byte, error)`
  - `func marshalSANs(s SANs) ([]byte, error)` / `parseSANs([]byte) (SANs, error)`
  - `func marshalCRLReason(reason int) ([]byte, error)` / `parseCRLReason([]byte) (int, error)`
  - `func marshalCRLNumber(n *big.Int) ([]byte, error)`
  - OID vars: `oidExtBasicConstraints`, `oidExtKeyUsage`, `oidExtExtendedKeyUsage`, `oidExtSubjectKeyID`, `oidExtAuthorityKeyID`, `oidExtSubjectAltName`, `oidExtCRLReason`, `oidExtCRLNumber`
  - `func isSupportedExtension(oid asn1.ObjectIdentifier) bool`
  - `func (ku KeyUsage) Strings() []string`, `func ParseKeyUsages([]string) (KeyUsage, error)`, `func (e ExtKeyUsage) String() string`, `func ParseExtKeyUsages([]string) ([]ExtKeyUsage, error)` — used by `api`/`ca` for JSON round-tripping. Accepted strings: `"digitalSignature"`, `"keyCertSign"`, `"cRLSign"`, `"serverAuth"`, `"clientAuth"`.

- [ ] **Step 1: Write the failing tests**

`internal/pqx509/extensions_test.go`:

```go
package pqx509

import (
	"encoding/asn1"
	"math/big"
	"net"
	"reflect"
	"testing"
)

func TestBasicConstraintsRoundTrip(t *testing.T) {
	for _, bc := range []BasicConstraints{
		{IsCA: false},
		{IsCA: true},
		{IsCA: true, MaxPathLen: 0, MaxPathLenSet: true},
		{IsCA: true, MaxPathLen: 1, MaxPathLenSet: true},
	} {
		der, err := marshalBasicConstraints(bc)
		if err != nil {
			t.Fatalf("%+v: %v", bc, err)
		}
		back, err := parseBasicConstraints(der)
		if err != nil {
			t.Fatalf("%+v: %v", bc, err)
		}
		if !reflect.DeepEqual(bc, back) {
			t.Errorf("round-trip: got %+v, want %+v", back, bc)
		}
	}
}

func TestBasicConstraintsCAFalseOmitsDefault(t *testing.T) {
	der, err := marshalBasicConstraints(BasicConstraints{IsCA: false})
	if err != nil {
		t.Fatal(err)
	}
	// DER must omit cA when FALSE (it is DEFAULT FALSE): empty SEQUENCE.
	if len(der) != 2 || der[0] != 0x30 || der[1] != 0x00 {
		t.Errorf("got % x, want 30 00", der)
	}
}

func TestKeyUsageRoundTripAndMinimalEncoding(t *testing.T) {
	ku := KeyUsageKeyCertSign | KeyUsageCRLSign
	der, err := marshalKeyUsage(ku)
	if err != nil {
		t.Fatal(err)
	}
	back, err := parseKeyUsage(der)
	if err != nil {
		t.Fatal(err)
	}
	if back != ku {
		t.Errorf("round-trip = %b, want %b", back, ku)
	}
	// keyCertSign (bit 5) + cRLSign (bit 6): one content octet, 1 unused bit.
	var bs asn1.BitString
	if _, err := asn1.Unmarshal(der, &bs); err != nil {
		t.Fatal(err)
	}
	if len(bs.Bytes) != 1 || bs.BitLength != 7 {
		t.Errorf("BIT STRING = % x (BitLength %d), want 1 byte / BitLength 7", bs.Bytes, bs.BitLength)
	}
	if bs.Bytes[0] != 0x06 {
		t.Errorf("content octet = %#x, want 0x06", bs.Bytes[0])
	}
}

func TestKeyUsageDigitalSignatureOnly(t *testing.T) {
	der, err := marshalKeyUsage(KeyUsageDigitalSignature)
	if err != nil {
		t.Fatal(err)
	}
	var bs asn1.BitString
	if _, err := asn1.Unmarshal(der, &bs); err != nil {
		t.Fatal(err)
	}
	if len(bs.Bytes) != 1 || bs.Bytes[0] != 0x80 || bs.BitLength != 1 {
		t.Errorf("got % x BitLength %d, want 80 / 1", bs.Bytes, bs.BitLength)
	}
}

func TestKeyUsageStringsRoundTrip(t *testing.T) {
	ku := KeyUsageKeyCertSign | KeyUsageCRLSign
	got := ku.Strings()
	want := []string{"keyCertSign", "cRLSign"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Strings() = %v, want %v", got, want)
	}
	back, err := ParseKeyUsages(want)
	if err != nil || back != ku {
		t.Errorf("ParseKeyUsages = %b, %v", back, err)
	}
	if _, err := ParseKeyUsages([]string{"nonRepudiation"}); err == nil {
		t.Error("unsupported key usage must be rejected")
	}
}

func TestExtKeyUsageRoundTrip(t *testing.T) {
	in := []ExtKeyUsage{ExtKeyUsageServerAuth, ExtKeyUsageClientAuth}
	der, err := marshalExtKeyUsage(in)
	if err != nil {
		t.Fatal(err)
	}
	back, err := parseExtKeyUsage(der)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in, back) {
		t.Errorf("got %v, want %v", back, in)
	}
	parsed, err := ParseExtKeyUsages([]string{"serverAuth", "clientAuth"})
	if err != nil || !reflect.DeepEqual(parsed, in) {
		t.Errorf("ParseExtKeyUsages = %v, %v", parsed, err)
	}
	if _, err := ParseExtKeyUsages([]string{"codeSigning"}); err == nil {
		t.Error("unsupported EKU must be rejected")
	}
}

func TestKeyIDExtensionsRoundTrip(t *testing.T) {
	id := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	skidDER, err := marshalKeyID(id)
	if err != nil {
		t.Fatal(err)
	}
	gotSKID, err := parseSubjectKeyID(skidDER)
	if err != nil || !reflect.DeepEqual(gotSKID, id) {
		t.Errorf("SKID round-trip = % x, %v", gotSKID, err)
	}
	akidDER, err := marshalAuthorityKeyID(id)
	if err != nil {
		t.Fatal(err)
	}
	gotAKID, err := parseAuthorityKeyID(akidDER)
	if err != nil || !reflect.DeepEqual(gotAKID, id) {
		t.Errorf("AKID round-trip = % x, %v", gotAKID, err)
	}
}

func TestSANsRoundTrip(t *testing.T) {
	in := SANs{
		DNSNames:       []string{"api.example.com", "example.com"},
		EmailAddresses: []string{"pki@example.com"},
		IPAddresses:    []net.IP{net.ParseIP("192.0.2.10").To4(), net.ParseIP("2001:db8::1")},
	}
	der, err := marshalSANs(in)
	if err != nil {
		t.Fatal(err)
	}
	back, err := parseSANs(der)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in.DNSNames, back.DNSNames) {
		t.Errorf("DNS: got %v, want %v", back.DNSNames, in.DNSNames)
	}
	if !reflect.DeepEqual(in.EmailAddresses, back.EmailAddresses) {
		t.Errorf("email: got %v, want %v", back.EmailAddresses, in.EmailAddresses)
	}
	if len(back.IPAddresses) != 2 || !back.IPAddresses[0].Equal(in.IPAddresses[0]) || !back.IPAddresses[1].Equal(in.IPAddresses[1]) {
		t.Errorf("IP: got %v, want %v", back.IPAddresses, in.IPAddresses)
	}
}

func TestCRLExtensionHelpers(t *testing.T) {
	der, err := marshalCRLReason(1) // keyCompromise
	if err != nil {
		t.Fatal(err)
	}
	reason, err := parseCRLReason(der)
	if err != nil || reason != 1 {
		t.Errorf("CRL reason round-trip = %d, %v", reason, err)
	}
	if _, err := marshalCRLNumber(big.NewInt(7)); err != nil {
		t.Fatal(err)
	}
}

func TestIsSupportedExtension(t *testing.T) {
	if !isSupportedExtension(oidExtBasicConstraints) {
		t.Error("basicConstraints must be supported")
	}
	if isSupportedExtension(asn1.ObjectIdentifier{2, 5, 29, 30}) { // nameConstraints
		t.Error("nameConstraints must not be supported")
	}
}
```

- [ ] **Step 2: Run and confirm failure**

Run: `CGO_ENABLED=0 go test ./internal/pqx509/ -run Extension -v`
Expected: compile failure.

- [ ] **Step 3: Implement `extensions.go`**

```go
package pqx509

import (
	"encoding/asn1"
	"fmt"
	"math/big"
	"net"
)

var (
	oidExtSubjectKeyID     = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidExtKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtSubjectAltName   = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidExtBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidExtCRLNumber        = asn1.ObjectIdentifier{2, 5, 29, 20}
	oidExtCRLReason        = asn1.ObjectIdentifier{2, 5, 29, 21}
	oidExtAuthorityKeyID   = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidExtExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
)

func isSupportedExtension(oid asn1.ObjectIdentifier) bool {
	for _, known := range []asn1.ObjectIdentifier{
		oidExtSubjectKeyID, oidExtKeyUsage, oidExtSubjectAltName,
		oidExtBasicConstraints, oidExtCRLNumber, oidExtCRLReason,
		oidExtAuthorityKeyID, oidExtExtendedKeyUsage,
	} {
		if known.Equal(oid) {
			return true
		}
	}
	return false
}

// KeyUsage is a bitmask of RFC 5280 key usages. Only the usages pqtrust issues
// are named; parsing preserves every bit so that round-trips are lossless.
type KeyUsage uint16

// Supported key usages, positioned by their RFC 5280 bit numbers.
const (
	KeyUsageDigitalSignature KeyUsage = 1 << 0
	KeyUsageKeyCertSign      KeyUsage = 1 << 5
	KeyUsageCRLSign          KeyUsage = 1 << 6
)

var keyUsageNames = []struct {
	ku   KeyUsage
	name string
}{
	{KeyUsageDigitalSignature, "digitalSignature"},
	{KeyUsageKeyCertSign, "keyCertSign"},
	{KeyUsageCRLSign, "cRLSign"},
}

// Strings renders ku as canonical RFC 5280 names, in bit order.
func (ku KeyUsage) Strings() []string {
	var out []string
	for _, e := range keyUsageNames {
		if ku&e.ku != 0 {
			out = append(out, e.name)
		}
	}
	return out
}

// ParseKeyUsages resolves canonical names, rejecting anything pqtrust cannot issue.
func ParseKeyUsages(names []string) (KeyUsage, error) {
	var ku KeyUsage
	for _, n := range names {
		found := false
		for _, e := range keyUsageNames {
			if e.name == n {
				ku |= e.ku
				found = true
				break
			}
		}
		if !found {
			return 0, fmt.Errorf("pqx509: unsupported key usage %q", n)
		}
	}
	return ku, nil
}

// bit number in the DER BIT STRING for KeyUsage bit i of our mask
func marshalKeyUsage(ku KeyUsage) ([]byte, error) {
	// Build the BIT STRING with the minimum number of octets and strip
	// trailing zero bits, as DER requires for named bit lists.
	var bytesOut [2]byte
	highest := -1
	for bit := 0; bit < 16; bit++ {
		if ku&(1<<uint(bit)) != 0 {
			bytesOut[bit/8] |= 0x80 >> uint(bit%8)
			highest = bit
		}
	}
	if highest < 0 {
		return nil, fmt.Errorf("pqx509: key usage must not be empty")
	}
	n := highest/8 + 1
	bs := asn1.BitString{Bytes: bytesOut[:n], BitLength: highest + 1}
	der, err := asn1.Marshal(bs)
	if err != nil {
		return nil, fmt.Errorf("pqx509: marshaling key usage: %w", err)
	}
	return der, nil
}

func parseKeyUsage(der []byte) (KeyUsage, error) {
	var bs asn1.BitString
	rest, err := asn1.Unmarshal(der, &bs)
	if err != nil {
		return 0, fmt.Errorf("%w: key usage: %w", ErrMalformedDER, err)
	}
	if len(rest) != 0 {
		return 0, fmt.Errorf("%w: after key usage", ErrTrailingData)
	}
	var ku KeyUsage
	for bit := 0; bit < 16 && bit < bs.BitLength; bit++ {
		if bs.At(bit) == 1 {
			ku |= 1 << uint(bit)
		}
	}
	return ku, nil
}

// ExtKeyUsage is a supported extended key usage.
type ExtKeyUsage int

// Supported extended key usages.
const (
	ExtKeyUsageServerAuth ExtKeyUsage = iota + 1
	ExtKeyUsageClientAuth
)

var extKeyUsages = []struct {
	eku  ExtKeyUsage
	name string
	oid  asn1.ObjectIdentifier
}{
	{ExtKeyUsageServerAuth, "serverAuth", asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}},
	{ExtKeyUsageClientAuth, "clientAuth", asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}},
}

// String returns the canonical name, e.g. "serverAuth".
func (e ExtKeyUsage) String() string {
	for _, x := range extKeyUsages {
		if x.eku == e {
			return x.name
		}
	}
	return fmt.Sprintf("ExtKeyUsage(%d)", int(e))
}

// ParseExtKeyUsages resolves canonical EKU names.
func ParseExtKeyUsages(names []string) ([]ExtKeyUsage, error) {
	var out []ExtKeyUsage
	for _, n := range names {
		found := false
		for _, x := range extKeyUsages {
			if x.name == n {
				out = append(out, x.eku)
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("pqx509: unsupported extended key usage %q", n)
		}
	}
	return out, nil
}

func marshalExtKeyUsage(ekus []ExtKeyUsage) ([]byte, error) {
	oids := make([]asn1.ObjectIdentifier, 0, len(ekus))
	for _, e := range ekus {
		found := false
		for _, x := range extKeyUsages {
			if x.eku == e {
				oids = append(oids, x.oid)
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("pqx509: unsupported extended key usage %v", e)
		}
	}
	der, err := asn1.Marshal(oids)
	if err != nil {
		return nil, fmt.Errorf("pqx509: marshaling extended key usage: %w", err)
	}
	return der, nil
}

func parseExtKeyUsage(der []byte) ([]ExtKeyUsage, error) {
	var oids []asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(der, &oids)
	if err != nil {
		return nil, fmt.Errorf("%w: extended key usage: %w", ErrMalformedDER, err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: after extended key usage", ErrTrailingData)
	}
	var out []ExtKeyUsage
	for _, oid := range oids {
		for _, x := range extKeyUsages {
			if x.oid.Equal(oid) {
				out = append(out, x.eku)
			}
		}
	}
	return out, nil
}

// BasicConstraints is the RFC 5280 basicConstraints extension.
type BasicConstraints struct {
	IsCA          bool
	MaxPathLen    int
	MaxPathLenSet bool
}

type basicConstraintsDER struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

func marshalBasicConstraints(bc BasicConstraints) ([]byte, error) {
	v := basicConstraintsDER{IsCA: bc.IsCA, MaxPathLen: -1}
	if bc.IsCA && bc.MaxPathLenSet {
		if bc.MaxPathLen < 0 {
			return nil, fmt.Errorf("pqx509: negative pathLenConstraint %d", bc.MaxPathLen)
		}
		v.MaxPathLen = bc.MaxPathLen
	}
	der, err := asn1.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("pqx509: marshaling basic constraints: %w", err)
	}
	return der, nil
}

func parseBasicConstraints(der []byte) (BasicConstraints, error) {
	v := basicConstraintsDER{MaxPathLen: -1}
	rest, err := asn1.Unmarshal(der, &v)
	if err != nil {
		return BasicConstraints{}, fmt.Errorf("%w: basic constraints: %w", ErrMalformedDER, err)
	}
	if len(rest) != 0 {
		return BasicConstraints{}, fmt.Errorf("%w: after basic constraints", ErrTrailingData)
	}
	bc := BasicConstraints{IsCA: v.IsCA}
	if v.MaxPathLen >= 0 {
		if !v.IsCA {
			return BasicConstraints{}, fmt.Errorf("%w: pathLenConstraint present on a non-CA certificate", ErrMalformedDER)
		}
		bc.MaxPathLen, bc.MaxPathLenSet = v.MaxPathLen, true
	}
	return bc, nil
}

func marshalKeyID(id []byte) ([]byte, error) {
	der, err := asn1.Marshal(id)
	if err != nil {
		return nil, fmt.Errorf("pqx509: marshaling key identifier: %w", err)
	}
	return der, nil
}

func parseSubjectKeyID(der []byte) ([]byte, error) {
	var id []byte
	rest, err := asn1.Unmarshal(der, &id)
	if err != nil {
		return nil, fmt.Errorf("%w: subject key identifier: %w", ErrMalformedDER, err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: after subject key identifier", ErrTrailingData)
	}
	return id, nil
}

type authorityKeyIDDER struct {
	KeyIdentifier []byte `asn1:"optional,tag:0"`
}

func marshalAuthorityKeyID(id []byte) ([]byte, error) {
	der, err := asn1.Marshal(authorityKeyIDDER{KeyIdentifier: id})
	if err != nil {
		return nil, fmt.Errorf("pqx509: marshaling authority key identifier: %w", err)
	}
	return der, nil
}

func parseAuthorityKeyID(der []byte) ([]byte, error) {
	var v authorityKeyIDDER
	rest, err := asn1.Unmarshal(der, &v)
	if err != nil {
		return nil, fmt.Errorf("%w: authority key identifier: %w", ErrMalformedDER, err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: after authority key identifier", ErrTrailingData)
	}
	return v.KeyIdentifier, nil
}

// SANs is the subset of GeneralName types pqtrust supports.
type SANs struct {
	DNSNames       []string
	EmailAddresses []string
	IPAddresses    []net.IP
}

// GeneralName context tags (RFC 5280 4.2.1.6).
const (
	sanTagEmail = 1
	sanTagDNS   = 2
	sanTagIP    = 7
)

// Empty reports whether s carries no names.
func (s SANs) Empty() bool {
	return len(s.DNSNames) == 0 && len(s.EmailAddresses) == 0 && len(s.IPAddresses) == 0
}

func marshalSANs(s SANs) ([]byte, error) {
	var names []asn1.RawValue
	for _, v := range s.DNSNames {
		names = append(names, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: sanTagDNS, Bytes: []byte(v)})
	}
	for _, v := range s.EmailAddresses {
		names = append(names, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: sanTagEmail, Bytes: []byte(v)})
	}
	for _, ip := range s.IPAddresses {
		b := ip
		if v4 := ip.To4(); v4 != nil {
			b = v4
		}
		names = append(names, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: sanTagIP, Bytes: b})
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("pqx509: subjectAltName must not be empty")
	}
	der, err := asn1.Marshal(names)
	if err != nil {
		return nil, fmt.Errorf("pqx509: marshaling subject alternative names: %w", err)
	}
	return der, nil
}

func parseSANs(der []byte) (SANs, error) {
	var names []asn1.RawValue
	rest, err := asn1.Unmarshal(der, &names)
	if err != nil {
		return SANs{}, fmt.Errorf("%w: subject alternative names: %w", ErrMalformedDER, err)
	}
	if len(rest) != 0 {
		return SANs{}, fmt.Errorf("%w: after subject alternative names", ErrTrailingData)
	}
	var s SANs
	for _, n := range names {
		switch n.Tag {
		case sanTagDNS:
			s.DNSNames = append(s.DNSNames, string(n.Bytes))
		case sanTagEmail:
			s.EmailAddresses = append(s.EmailAddresses, string(n.Bytes))
		case sanTagIP:
			if l := len(n.Bytes); l != 4 && l != 16 {
				return SANs{}, fmt.Errorf("%w: IP address SAN is %d bytes", ErrMalformedDER, l)
			}
			s.IPAddresses = append(s.IPAddresses, net.IP(n.Bytes))
		default:
			return SANs{}, fmt.Errorf("%w: unsupported GeneralName tag %d", ErrMalformedDER, n.Tag)
		}
	}
	return s, nil
}

func marshalCRLReason(reason int) ([]byte, error) {
	der, err := asn1.Marshal(asn1.Enumerated(reason))
	if err != nil {
		return nil, fmt.Errorf("pqx509: marshaling CRL reason: %w", err)
	}
	return der, nil
}

func parseCRLReason(der []byte) (int, error) {
	var e asn1.Enumerated
	rest, err := asn1.Unmarshal(der, &e)
	if err != nil {
		return 0, fmt.Errorf("%w: CRL reason: %w", ErrMalformedDER, err)
	}
	if len(rest) != 0 {
		return 0, fmt.Errorf("%w: after CRL reason", ErrTrailingData)
	}
	return int(e), nil
}

func marshalCRLNumber(n *big.Int) ([]byte, error) {
	der, err := asn1.Marshal(n)
	if err != nil {
		return nil, fmt.Errorf("pqx509: marshaling CRL number: %w", err)
	}
	return der, nil
}
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `CGO_ENABLED=0 go test ./internal/pqx509/ -v`
Expected: PASS. If `asn1.Marshal` on `asn1.Enumerated` or the SAN `RawValue` list misbehaves, fix the implementation — the expected DER shapes in the tests are the specification.

- [ ] **Step 5: Commit**

```bash
git add internal/pqx509
git commit -m "feat(pqx509): supported certificate and CRL extensions"
```

---

### Task 4: CreateCertificate and ParseCertificate

**Files:**
- Create: `internal/pqx509/certificate.go`, `internal/pqx509/pem.go`
- Test: `internal/pqx509/certificate_test.go`, `internal/pqx509/pem_test.go`

**Interfaces:**
- Consumes: everything from Tasks 1–3.
- Produces:
  - ```go
    type Certificate struct {
        Raw                []byte // full DER
        RawTBSCertificate  []byte
        Version            int
        SerialNumber       *big.Int
        SignatureAlgorithm Algorithm
        Signature          []byte
        Issuer             Name
        RawIssuer          []byte
        Subject            Name
        RawSubject         []byte
        NotBefore          time.Time
        NotAfter           time.Time
        PublicKey          PublicKey
        BasicConstraints   BasicConstraints
        BasicConstraintsValid bool
        KeyUsage           KeyUsage
        ExtKeyUsage        []ExtKeyUsage
        SubjectKeyID       []byte
        AuthorityKeyID     []byte
        SANs               SANs
        UnhandledExtensions []Extension // non-critical unknown extensions, preserved on parse
    }
    type Extension struct { ID asn1.ObjectIdentifier; Critical bool; Value []byte }
    ```
  - `func CreateCertificate(rand io.Reader, template, parent *Certificate, pub PublicKey, signer Signer) ([]byte, error)`
  - `func ParseCertificate(der []byte) (*Certificate, error)`
  - `func GenerateSerialNumber(rand io.Reader) (*big.Int, error)` — 128-bit positive
  - `func EncodeCertificatePEM(der []byte) []byte`, `func DecodeCertificatePEM(pemBytes []byte) ([]byte, error)`, `func EncodeCRLPEM(der []byte) []byte`
  - `func (c *Certificate) IsSelfSigned() bool`

Semantics `CreateCertificate` must implement, because later tasks depend on them:
- If `parent == template`, the certificate is self-signed: issuer = template.Subject.
- Otherwise issuer = `parent.Subject` (use `parent.RawSubject` when present, so the issuer DN is byte-identical to the parent's subject DN — name chaining compares raw bytes).
- `template.SerialNumber` must be set by the caller; nil is an error.
- SKID is computed from `pub` if `template.SubjectKeyID` is empty.
- AKID is computed from the signer's public key if `template.AuthorityKeyID` is empty (omitted entirely for self-signed certificates only if the caller leaves it empty *and* `parent == template`; in that case still emit it — RFC 5280 recommends AKID on self-signed CAs, and OpenSSL accepts it).
- Extensions are emitted in this fixed order, skipping absent ones: basicConstraints (critical), keyUsage (critical), extKeyUsage (non-critical), subjectKeyIdentifier (non-critical), authorityKeyIdentifier (non-critical), subjectAltName (critical iff Subject is empty).
- Version is always 3 (`Version` field encodes as integer 2).
- `NotAfter` must be after `NotBefore`, else error.

- [ ] **Step 1: Write the failing tests**

`internal/pqx509/certificate_test.go`:

```go
package pqx509

import (
	"bytes"
	"crypto/rand"
	"encoding/asn1"
	"math/big"
	"net"
	"testing"
	"time"
)

// testCA builds a self-signed CA certificate for use across tests.
func testCA(t *testing.T, alg Algorithm, pathLen int) (*Certificate, Signer) {
	t.Helper()
	pub, priv, err := GenerateKey(rand.Reader, alg)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := priv.Signer()
	if err != nil {
		t.Fatal(err)
	}
	serial, err := GenerateSerialNumber(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &Certificate{
		SerialNumber:          serial,
		SignatureAlgorithm:    alg,
		Subject:               Name{CommonName: "pqtrust Test Root", Organization: []string{"pqtrust"}},
		NotBefore:             time.Now().Add(-time.Hour).UTC().Truncate(time.Second),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour).UTC().Truncate(time.Second),
		BasicConstraints:      BasicConstraints{IsCA: true, MaxPathLen: pathLen, MaxPathLenSet: true},
		BasicConstraintsValid: true,
		KeyUsage:              KeyUsageKeyCertSign | KeyUsageCRLSign,
	}
	der, err := CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, signer
}

func TestCreateParseSelfSignedRoundTrip(t *testing.T) {
	cert, _ := testCA(t, MLDSA87, 1)

	if cert.Version != 3 {
		t.Errorf("Version = %d, want 3", cert.Version)
	}
	if cert.SignatureAlgorithm != MLDSA87 {
		t.Errorf("SignatureAlgorithm = %v, want ML-DSA-87", cert.SignatureAlgorithm)
	}
	if len(cert.Signature) != MLDSA87.SignatureSize() {
		t.Errorf("signature length = %d, want %d", len(cert.Signature), MLDSA87.SignatureSize())
	}
	if cert.Subject.CommonName != "pqtrust Test Root" || cert.Issuer.CommonName != "pqtrust Test Root" {
		t.Errorf("self-signed issuer/subject mismatch: %+v / %+v", cert.Issuer, cert.Subject)
	}
	if !cert.IsSelfSigned() {
		t.Error("IsSelfSigned must be true")
	}
	if !cert.BasicConstraints.IsCA || !cert.BasicConstraints.MaxPathLenSet || cert.BasicConstraints.MaxPathLen != 1 {
		t.Errorf("basic constraints = %+v", cert.BasicConstraints)
	}
	if cert.KeyUsage != KeyUsageKeyCertSign|KeyUsageCRLSign {
		t.Errorf("key usage = %b", cert.KeyUsage)
	}
	if len(cert.SubjectKeyID) != 20 {
		t.Errorf("SKID length = %d, want 20", len(cert.SubjectKeyID))
	}
	if !bytes.Equal(cert.SubjectKeyID, cert.AuthorityKeyID) {
		t.Error("self-signed certificate must have AKID == SKID")
	}
	if err := Verify(cert.PublicKey, cert.RawTBSCertificate, cert.Signature); err != nil {
		t.Errorf("self-signature does not verify: %v", err)
	}
	// Re-parsing the raw bytes must be byte-stable.
	again, err := ParseCertificate(cert.Raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again.Raw, cert.Raw) || !bytes.Equal(again.RawTBSCertificate, cert.RawTBSCertificate) {
		t.Error("re-parse is not byte-stable")
	}
}

func TestCreateEndEntityUnderCA(t *testing.T) {
	ca, caSigner := testCA(t, MLDSA65, 0)
	pub, _, err := GenerateKey(rand.Reader, MLDSA44)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := GenerateSerialNumber(rand.Reader)
	tmpl := &Certificate{
		SerialNumber:          serial,
		SignatureAlgorithm:    MLDSA65, // the CA's algorithm signs
		Subject:               Name{CommonName: "api.example.com"},
		NotBefore:             time.Now().Add(-time.Minute).UTC().Truncate(time.Second),
		NotAfter:              time.Now().Add(397 * 24 * time.Hour).UTC().Truncate(time.Second),
		BasicConstraints:      BasicConstraints{IsCA: false},
		BasicConstraintsValid: true,
		KeyUsage:              KeyUsageDigitalSignature,
		ExtKeyUsage:           []ExtKeyUsage{ExtKeyUsageServerAuth},
		SANs:                  SANs{DNSNames: []string{"api.example.com"}, IPAddresses: []net.IP{net.ParseIP("192.0.2.10").To4()}},
	}
	der, err := CreateCertificate(rand.Reader, tmpl, ca, pub, caSigner)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(leaf.RawIssuer, ca.RawSubject) {
		t.Error("leaf issuer bytes must equal the CA subject bytes")
	}
	if leaf.PublicKey.Algorithm != MLDSA44 {
		t.Errorf("subject key algorithm = %v, want ML-DSA-44", leaf.PublicKey.Algorithm)
	}
	if leaf.SignatureAlgorithm != MLDSA65 {
		t.Errorf("signature algorithm = %v, want ML-DSA-65", leaf.SignatureAlgorithm)
	}
	if !bytes.Equal(leaf.AuthorityKeyID, ca.SubjectKeyID) {
		t.Error("leaf AKID must equal CA SKID")
	}
	if leaf.BasicConstraints.IsCA {
		t.Error("leaf must not be a CA")
	}
	if len(leaf.SANs.DNSNames) != 1 || leaf.SANs.DNSNames[0] != "api.example.com" {
		t.Errorf("SAN DNS names = %v", leaf.SANs.DNSNames)
	}
	if err := Verify(ca.PublicKey, leaf.RawTBSCertificate, leaf.Signature); err != nil {
		t.Errorf("leaf signature does not verify under the CA key: %v", err)
	}
}

func TestCreateCertificateValidation(t *testing.T) {
	ca, signer := testCA(t, MLDSA65, 0)
	pub, _, _ := GenerateKey(rand.Reader, MLDSA44)
	now := time.Now().UTC().Truncate(time.Second)
	serial, _ := GenerateSerialNumber(rand.Reader)

	t.Run("nil serial", func(t *testing.T) {
		tmpl := &Certificate{SignatureAlgorithm: MLDSA65, NotBefore: now, NotAfter: now.Add(time.Hour), Subject: Name{CommonName: "x"}}
		if _, err := CreateCertificate(rand.Reader, tmpl, ca, pub, signer); err == nil {
			t.Error("missing serial number must be an error")
		}
	})
	t.Run("inverted validity", func(t *testing.T) {
		tmpl := &Certificate{SerialNumber: serial, SignatureAlgorithm: MLDSA65, NotBefore: now, NotAfter: now.Add(-time.Hour), Subject: Name{CommonName: "x"}}
		if _, err := CreateCertificate(rand.Reader, tmpl, ca, pub, signer); err == nil {
			t.Error("NotAfter before NotBefore must be an error")
		}
	})
	t.Run("algorithm mismatch with signer", func(t *testing.T) {
		tmpl := &Certificate{SerialNumber: serial, SignatureAlgorithm: MLDSA87, NotBefore: now, NotAfter: now.Add(time.Hour), Subject: Name{CommonName: "x"}}
		if _, err := CreateCertificate(rand.Reader, tmpl, ca, pub, signer); err == nil {
			t.Error("template signature algorithm must match the signer's algorithm")
		}
	})
	t.Run("empty subject without SANs", func(t *testing.T) {
		tmpl := &Certificate{SerialNumber: serial, SignatureAlgorithm: MLDSA65, NotBefore: now, NotAfter: now.Add(time.Hour)}
		if _, err := CreateCertificate(rand.Reader, tmpl, ca, pub, signer); err == nil {
			t.Error("an empty subject requires subjectAltName")
		}
	})
}

func TestParseCertificateRejectsBadInput(t *testing.T) {
	ca, _ := testCA(t, MLDSA44, 0)

	t.Run("trailing data", func(t *testing.T) {
		if _, err := ParseCertificate(append(bytes.Clone(ca.Raw), 0x00)); err == nil {
			t.Error("trailing data must be rejected")
		}
	})
	t.Run("truncated", func(t *testing.T) {
		if _, err := ParseCertificate(ca.Raw[:len(ca.Raw)/2]); err == nil {
			t.Error("truncated DER must be rejected")
		}
	})
	t.Run("empty", func(t *testing.T) {
		if _, err := ParseCertificate(nil); err == nil {
			t.Error("empty input must be rejected")
		}
	})
}

func TestParseCertificateRejectsUnknownCriticalExtension(t *testing.T) {
	// Craft a certificate carrying a critical nameConstraints extension by
	// re-signing a template with an injected unhandled critical extension.
	ca, signer := testCA(t, MLDSA44, 0)
	pub, _, _ := GenerateKey(rand.Reader, MLDSA44)
	serial, _ := GenerateSerialNumber(rand.Reader)
	tmpl := &Certificate{
		SerialNumber:       serial,
		SignatureAlgorithm: MLDSA44,
		Subject:            Name{CommonName: "leaf"},
		NotBefore:          time.Now().Add(-time.Minute).UTC().Truncate(time.Second),
		NotAfter:           time.Now().Add(time.Hour).UTC().Truncate(time.Second),
		KeyUsage:           KeyUsageDigitalSignature,
		UnhandledExtensions: []Extension{
			{ID: asn1.ObjectIdentifier{2, 5, 29, 30}, Critical: true, Value: []byte{0x30, 0x00}},
		},
	}
	der, err := CreateCertificate(rand.Reader, tmpl, ca, pub, signer)
	if err != nil {
		t.Fatalf("CreateCertificate with injected extension: %v", err)
	}
	if _, err := ParseCertificate(der); err == nil {
		t.Fatal("a critical unknown extension must make parsing fail")
	}
}

func TestParsePreservesNonCriticalUnknownExtension(t *testing.T) {
	ca, signer := testCA(t, MLDSA44, 0)
	pub, _, _ := GenerateKey(rand.Reader, MLDSA44)
	serial, _ := GenerateSerialNumber(rand.Reader)
	oid := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}
	tmpl := &Certificate{
		SerialNumber:        serial,
		SignatureAlgorithm:  MLDSA44,
		Subject:             Name{CommonName: "leaf"},
		NotBefore:           time.Now().Add(-time.Minute).UTC().Truncate(time.Second),
		NotAfter:            time.Now().Add(time.Hour).UTC().Truncate(time.Second),
		KeyUsage:            KeyUsageDigitalSignature,
		UnhandledExtensions: []Extension{{ID: oid, Critical: false, Value: []byte{0x04, 0x01, 0x2a}}},
	}
	der, err := CreateCertificate(rand.Reader, tmpl, ca, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.UnhandledExtensions) != 1 || !cert.UnhandledExtensions[0].ID.Equal(oid) {
		t.Errorf("non-critical unknown extension not preserved: %+v", cert.UnhandledExtensions)
	}
}

func TestGenerateSerialNumberIsPositiveAnd128Bit(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		s, err := GenerateSerialNumber(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if s.Sign() <= 0 {
			t.Fatalf("serial must be positive, got %s", s)
		}
		if s.BitLen() > 128 {
			t.Fatalf("serial has %d bits, want <= 128", s.BitLen())
		}
		if len(s.Bytes()) > 20 {
			t.Fatalf("serial encodes to %d octets, want <= 20", len(s.Bytes()))
		}
		if seen[s.String()] {
			t.Fatal("duplicate serial number")
		}
		seen[s.String()] = true
	}
	_ = big.NewInt(0)
}

func TestValidityTimesSurviveRoundTrip(t *testing.T) {
	ca, _ := testCA(t, MLDSA44, 0)
	reparsed, err := ParseCertificate(ca.Raw)
	if err != nil {
		t.Fatal(err)
	}
	if !reparsed.NotBefore.Equal(ca.NotBefore) || !reparsed.NotAfter.Equal(ca.NotAfter) {
		t.Errorf("validity mismatch: %v/%v vs %v/%v", reparsed.NotBefore, reparsed.NotAfter, ca.NotBefore, ca.NotAfter)
	}
}
```

`internal/pqx509/pem_test.go`:

```go
package pqx509

import (
	"bytes"
	"strings"
	"testing"
)

func TestCertificatePEMRoundTrip(t *testing.T) {
	ca, _ := testCA(t, MLDSA44, 0)
	pemBytes := EncodeCertificatePEM(ca.Raw)
	if !strings.HasPrefix(string(pemBytes), "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("unexpected PEM header: %q", string(pemBytes[:40]))
	}
	der, err := DecodeCertificatePEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(der, ca.Raw) {
		t.Error("PEM round-trip changed the DER")
	}
}

func TestDecodeCertificatePEMRejectsWrongType(t *testing.T) {
	if _, err := DecodeCertificatePEM([]byte("-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n")); err == nil {
		t.Error("wrong PEM type must be rejected")
	}
	if _, err := DecodeCertificatePEM([]byte("not pem at all")); err == nil {
		t.Error("non-PEM input must be rejected")
	}
}
```

- [ ] **Step 2: Run and confirm failure**

Run: `CGO_ENABLED=0 go test ./internal/pqx509/ -v`
Expected: compile failure.

- [ ] **Step 3: Implement `certificate.go`**

```go
package pqx509

import (
	"bytes"
	"crypto/rand"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"time"
)

// Extension is a raw X.509 extension.
type Extension struct {
	ID       asn1.ObjectIdentifier
	Critical bool
	Value    []byte
}

// Certificate is a parsed or to-be-created X.509 certificate with a
// post-quantum signature algorithm.
type Certificate struct {
	Raw               []byte
	RawTBSCertificate []byte

	Version            int
	SerialNumber       *big.Int
	SignatureAlgorithm Algorithm
	Signature          []byte

	Issuer     Name
	RawIssuer  []byte
	Subject    Name
	RawSubject []byte

	NotBefore time.Time
	NotAfter  time.Time

	PublicKey PublicKey

	BasicConstraints      BasicConstraints
	BasicConstraintsValid bool
	KeyUsage              KeyUsage
	ExtKeyUsage           []ExtKeyUsage
	SubjectKeyID          []byte
	AuthorityKeyID        []byte
	SANs                  SANs

	// UnhandledExtensions carries extensions pqtrust does not interpret. On
	// parse only non-critical ones can appear (critical unknowns are errors).
	UnhandledExtensions []Extension
}

// IsSelfSigned reports whether issuer and subject DNs are byte-identical.
func (c *Certificate) IsSelfSigned() bool {
	return len(c.RawIssuer) > 0 && bytes.Equal(c.RawIssuer, c.RawSubject)
}

// GenerateSerialNumber returns a random positive 128-bit serial number.
func GenerateSerialNumber(r io.Reader) (*big.Int, error) {
	if r == nil {
		r = rand.Reader
	}
	limit := new(big.Int).Lsh(big.NewInt(1), 127)
	for i := 0; i < 8; i++ {
		n, err := rand.Int(r, limit)
		if err != nil {
			return nil, fmt.Errorf("pqx509: generating serial number: %w", err)
		}
		if n.Sign() > 0 {
			return n, nil
		}
	}
	return nil, fmt.Errorf("pqx509: could not generate a nonzero serial number")
}

// CreateCertificate builds and signs a certificate. Pass template as parent to
// create a self-signed certificate. pub is the subject public key; signer holds
// the issuer's private key.
func CreateCertificate(r io.Reader, template, parent *Certificate, pub PublicKey, signer Signer) ([]byte, error) {
	if template == nil || parent == nil || signer == nil {
		return nil, fmt.Errorf("pqx509: template, parent and signer are required")
	}
	if template.SerialNumber == nil {
		return nil, fmt.Errorf("pqx509: template.SerialNumber must be set")
	}
	if template.SerialNumber.Sign() <= 0 {
		return nil, fmt.Errorf("pqx509: serial number must be positive")
	}
	if !template.NotAfter.After(template.NotBefore) {
		return nil, fmt.Errorf("pqx509: NotAfter (%v) must be after NotBefore (%v)", template.NotAfter, template.NotBefore)
	}
	if template.SignatureAlgorithm != signer.Algorithm() {
		return nil, fmt.Errorf("pqx509: template signature algorithm %v does not match signer algorithm %v",
			template.SignatureAlgorithm, signer.Algorithm())
	}

	subjectDER := template.RawSubject
	if len(subjectDER) == 0 {
		var err error
		if subjectDER, err = template.Subject.ToRDNSequence(); err != nil {
			return nil, err
		}
	}
	subjectEmpty := bytes.Equal(subjectDER, []byte{0x30, 0x00})
	if subjectEmpty && template.SANs.Empty() {
		return nil, fmt.Errorf("pqx509: a certificate with an empty subject must carry subjectAltName")
	}

	var issuerDER []byte
	if parent == template {
		issuerDER = subjectDER
	} else {
		issuerDER = parent.RawSubject
		if len(issuerDER) == 0 {
			var err error
			if issuerDER, err = parent.Subject.ToRDNSequence(); err != nil {
				return nil, err
			}
		}
	}

	spki, err := MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	var spkiStruct subjectPublicKeyInfo
	if _, err := asn1.Unmarshal(spki, &spkiStruct); err != nil {
		return nil, fmt.Errorf("pqx509: re-reading SPKI: %w", err)
	}

	notBefore, err := marshalTime(template.NotBefore)
	if err != nil {
		return nil, err
	}
	notAfter, err := marshalTime(template.NotAfter)
	if err != nil {
		return nil, err
	}

	exts, err := buildExtensions(template, pub, signer, subjectEmpty)
	if err != nil {
		return nil, err
	}

	tbs := tbsCertificate{
		Version:            2, // v3
		SerialNumber:       template.SerialNumber,
		SignatureAlgorithm: algorithmIdentifier{Algorithm: template.SignatureAlgorithm.OID()},
		Issuer:             asn1.RawValue{FullBytes: issuerDER},
		Validity:           validity{NotBefore: notBefore, NotAfter: notAfter},
		Subject:            asn1.RawValue{FullBytes: subjectDER},
		PublicKey:          spkiStruct,
		Extensions:         exts,
	}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, fmt.Errorf("pqx509: marshaling TBSCertificate: %w", err)
	}

	sig, err := signer.Sign(r, tbsDER)
	if err != nil {
		return nil, fmt.Errorf("pqx509: signing certificate: %w", err)
	}

	certDER, err := asn1.Marshal(certificateDER{
		TBSCertificate:     asn1.RawValue{FullBytes: tbsDER},
		SignatureAlgorithm: algorithmIdentifier{Algorithm: template.SignatureAlgorithm.OID()},
		SignatureValue:     asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	})
	if err != nil {
		return nil, fmt.Errorf("pqx509: marshaling certificate: %w", err)
	}
	return certDER, nil
}

func buildExtensions(template *Certificate, pub PublicKey, signer Signer, subjectEmpty bool) ([]extension, error) {
	var exts []extension

	if template.BasicConstraintsValid {
		v, err := marshalBasicConstraints(template.BasicConstraints)
		if err != nil {
			return nil, err
		}
		exts = append(exts, extension{ID: oidExtBasicConstraints, Critical: true, Value: v})
	}
	if template.KeyUsage != 0 {
		v, err := marshalKeyUsage(template.KeyUsage)
		if err != nil {
			return nil, err
		}
		exts = append(exts, extension{ID: oidExtKeyUsage, Critical: true, Value: v})
	}
	if len(template.ExtKeyUsage) > 0 {
		v, err := marshalExtKeyUsage(template.ExtKeyUsage)
		if err != nil {
			return nil, err
		}
		exts = append(exts, extension{ID: oidExtExtendedKeyUsage, Value: v})
	}

	skid := template.SubjectKeyID
	if len(skid) == 0 {
		var err error
		if skid, err = KeyIdentifier(pub); err != nil {
			return nil, err
		}
	}
	skidDER, err := marshalKeyID(skid)
	if err != nil {
		return nil, err
	}
	exts = append(exts, extension{ID: oidExtSubjectKeyID, Value: skidDER})

	akid := template.AuthorityKeyID
	if len(akid) == 0 {
		if akid, err = KeyIdentifier(signer.Public()); err != nil {
			return nil, err
		}
	}
	akidDER, err := marshalAuthorityKeyID(akid)
	if err != nil {
		return nil, err
	}
	exts = append(exts, extension{ID: oidExtAuthorityKeyID, Value: akidDER})

	if !template.SANs.Empty() {
		v, err := marshalSANs(template.SANs)
		if err != nil {
			return nil, err
		}
		exts = append(exts, extension{ID: oidExtSubjectAltName, Critical: subjectEmpty, Value: v})
	}

	for _, e := range template.UnhandledExtensions {
		exts = append(exts, extension{ID: e.ID, Critical: e.Critical, Value: e.Value})
	}
	return exts, nil
}

// ParseCertificate decodes a DER certificate. Malformed DER, trailing bytes and
// unknown critical extensions are hard errors.
func ParseCertificate(der []byte) (*Certificate, error) {
	var outer certificateDER
	rest, err := asn1.Unmarshal(der, &outer)
	if err != nil {
		return nil, fmt.Errorf("%w: certificate: %w", ErrMalformedDER, err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: %d bytes after certificate", ErrTrailingData, len(rest))
	}

	var tbs tbsCertificate
	if trailing, err := asn1.Unmarshal(outer.TBSCertificate.FullBytes, &tbs); err != nil {
		return nil, fmt.Errorf("%w: TBSCertificate: %w", ErrMalformedDER, err)
	} else if len(trailing) != 0 {
		return nil, fmt.Errorf("%w: after TBSCertificate", ErrTrailingData)
	}

	sigAlg, err := algorithmFromOID(outer.SignatureAlgorithm.Algorithm)
	if err != nil {
		return nil, err
	}
	if len(outer.SignatureAlgorithm.Parameters.FullBytes) != 0 {
		return nil, fmt.Errorf("%w: signature AlgorithmIdentifier must omit parameters", ErrMalformedDER)
	}
	if !tbs.SignatureAlgorithm.Algorithm.Equal(outer.SignatureAlgorithm.Algorithm) {
		return nil, fmt.Errorf("%w: inner and outer signature algorithms differ", ErrMalformedDER)
	}
	if outer.SignatureValue.BitLength%8 != 0 {
		return nil, fmt.Errorf("%w: signature BIT STRING has unused bits", ErrMalformedDER)
	}
	if len(outer.SignatureValue.Bytes) != sigAlg.SignatureSize() {
		return nil, fmt.Errorf("%w: %s signature is %d bytes, want %d", ErrMalformedDER, sigAlg, len(outer.SignatureValue.Bytes), sigAlg.SignatureSize())
	}
	if tbs.SerialNumber == nil || tbs.SerialNumber.Sign() <= 0 {
		return nil, fmt.Errorf("%w: serial number must be positive", ErrMalformedDER)
	}

	issuer, err := ParseName(tbs.Issuer.FullBytes)
	if err != nil {
		return nil, err
	}
	subject, err := ParseName(tbs.Subject.FullBytes)
	if err != nil {
		return nil, err
	}
	notBefore, err := parseTime(tbs.Validity.NotBefore)
	if err != nil {
		return nil, err
	}
	notAfter, err := parseTime(tbs.Validity.NotAfter)
	if err != nil {
		return nil, err
	}
	pub, err := publicKeyFromSPKI(tbs.PublicKey)
	if err != nil {
		return nil, err
	}

	cert := &Certificate{
		Raw:                bytes.Clone(der),
		RawTBSCertificate:  bytes.Clone(outer.TBSCertificate.FullBytes),
		Version:            tbs.Version + 1,
		SerialNumber:       tbs.SerialNumber,
		SignatureAlgorithm: sigAlg,
		Signature:          bytes.Clone(outer.SignatureValue.Bytes),
		Issuer:             issuer,
		RawIssuer:          bytes.Clone(tbs.Issuer.FullBytes),
		Subject:            subject,
		RawSubject:         bytes.Clone(tbs.Subject.FullBytes),
		NotBefore:          notBefore,
		NotAfter:           notAfter,
		PublicKey:          pub,
	}
	if cert.Version != 3 {
		return nil, fmt.Errorf("%w: certificate version %d, want 3", ErrMalformedDER, cert.Version)
	}

	seen := map[string]bool{}
	for _, e := range tbs.Extensions {
		if seen[e.ID.String()] {
			return nil, fmt.Errorf("%w: duplicate extension %s", ErrMalformedDER, e.ID)
		}
		seen[e.ID.String()] = true

		switch {
		case e.ID.Equal(oidExtBasicConstraints):
			bc, err := parseBasicConstraints(e.Value)
			if err != nil {
				return nil, err
			}
			cert.BasicConstraints, cert.BasicConstraintsValid = bc, true
		case e.ID.Equal(oidExtKeyUsage):
			if cert.KeyUsage, err = parseKeyUsage(e.Value); err != nil {
				return nil, err
			}
		case e.ID.Equal(oidExtExtendedKeyUsage):
			if cert.ExtKeyUsage, err = parseExtKeyUsage(e.Value); err != nil {
				return nil, err
			}
		case e.ID.Equal(oidExtSubjectKeyID):
			if cert.SubjectKeyID, err = parseSubjectKeyID(e.Value); err != nil {
				return nil, err
			}
		case e.ID.Equal(oidExtAuthorityKeyID):
			if cert.AuthorityKeyID, err = parseAuthorityKeyID(e.Value); err != nil {
				return nil, err
			}
		case e.ID.Equal(oidExtSubjectAltName):
			if cert.SANs, err = parseSANs(e.Value); err != nil {
				return nil, err
			}
		default:
			if e.Critical {
				return nil, fmt.Errorf("%w: %s", ErrUnsupportedCriticalExtension, e.ID)
			}
			cert.UnhandledExtensions = append(cert.UnhandledExtensions, Extension{ID: e.ID, Critical: e.Critical, Value: bytes.Clone(e.Value)})
		}
	}
	return cert, nil
}
```

- [ ] **Step 4: Implement `pem.go`**

```go
package pqx509

import (
	"encoding/pem"
	"fmt"
)

// PEM block types pqtrust emits.
const (
	pemTypeCertificate = "CERTIFICATE"
	pemTypeCRL         = "X509 CRL"
)

// EncodeCertificatePEM wraps a DER certificate in a PEM block.
func EncodeCertificatePEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: pemTypeCertificate, Bytes: der})
}

// EncodeCRLPEM wraps a DER CRL in a PEM block.
func EncodeCRLPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: pemTypeCRL, Bytes: der})
}

// DecodeCertificatePEM extracts the DER from the first CERTIFICATE block.
func DecodeCertificatePEM(pemBytes []byte) ([]byte, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("pqx509: no PEM block found")
	}
	if block.Type != pemTypeCertificate {
		return nil, fmt.Errorf("pqx509: PEM block type is %q, want %q", block.Type, pemTypeCertificate)
	}
	return block.Bytes, nil
}
```

- [ ] **Step 5: Run the tests and confirm they pass**

Run: `CGO_ENABLED=0 go test ./internal/pqx509/ -v`
Expected: PASS.

Two failure modes to expect and how to resolve them:
- `asn1: structure error` marshaling `tbsCertificate` — the `Issuer`/`Subject` `asn1.RawValue` must be built with `FullBytes` set (Go emits `FullBytes` verbatim). Do not set `Bytes`.
- `TestCreateCertificateValidation/empty subject without SANs` failing — `Name{}.ToRDNSequence()` must produce exactly `30 00` (verified in Task 2).

- [ ] **Step 6: Add a golden DER fixture test**

`internal/pqx509/golden_test.go`:

```go
package pqx509

import (
	"crypto/rand"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "regenerate golden fixtures")

// TestGoldenSelfSignedRoot pins the parser against a stored certificate so that
// an accidental encoding change is caught even if create+parse still agree.
func TestGoldenSelfSignedRoot(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "golden", "root-mldsa87.der")

	if *update {
		pub, priv, err := GenerateKey(rand.Reader, MLDSA87)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := priv.Signer()
		if err != nil {
			t.Fatal(err)
		}
		serial, _ := GenerateSerialNumber(rand.Reader)
		tmpl := &Certificate{
			SerialNumber:          serial,
			SignatureAlgorithm:    MLDSA87,
			Subject:               Name{CommonName: "pqtrust Golden Root", Organization: []string{"pqtrust"}, Country: []string{"ES"}},
			NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:              time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC),
			BasicConstraints:      BasicConstraints{IsCA: true, MaxPathLen: 1, MaxPathLenSet: true},
			BasicConstraintsValid: true,
			KeyUsage:              KeyUsageKeyCertSign | KeyUsageCRLSign,
		}
		der, err := CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, der, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Log("golden fixture regenerated")
		return
	}

	der, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden fixture (run `go test ./internal/pqx509 -update` once to create it): %v", err)
	}
	cert, err := ParseCertificate(der)
	if err != nil {
		t.Fatalf("golden certificate must parse: %v", err)
	}
	if cert.Subject.CommonName != "pqtrust Golden Root" {
		t.Errorf("CN = %q", cert.Subject.CommonName)
	}
	if !cert.NotBefore.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("NotBefore = %v", cert.NotBefore)
	}
	if err := Verify(cert.PublicKey, cert.RawTBSCertificate, cert.Signature); err != nil {
		t.Errorf("golden self-signature must verify: %v", err)
	}
}
```

Generate the fixture, then verify the normal run passes:

```bash
CGO_ENABLED=0 go test ./internal/pqx509/ -run Golden -update
CGO_ENABLED=0 go test ./internal/pqx509/ -run Golden -v
```

- [ ] **Step 7: Commit**

```bash
git add internal/pqx509 testdata/golden
git commit -m "feat(pqx509): certificate creation, parsing, PEM helpers and golden fixture"
```

---

### Task 5: Path validation

**Files:**
- Create: `internal/pqx509/verify.go`
- Test: `internal/pqx509/verify_test.go`

**Interfaces:**
- Consumes: `Certificate`, `Verify`, `KeyUsage`, `BasicConstraints` (Tasks 1–4).
- Produces:
  - `func (c *Certificate) VerifySignatureFrom(parent *Certificate) error`
  - ```go
    type VerifyOptions struct {
        Roots         []*Certificate
        Intermediates []*Certificate
        CurrentTime   time.Time // zero means time.Now()
        // CheckRevocation, if non-nil, is called for each certificate in a
        // candidate chain with its issuer. A non-nil error rejects the chain.
        CheckRevocation func(cert, issuer *Certificate) error
    }
    ```
  - `func (c *Certificate) Verify(opts VerifyOptions) ([][]*Certificate, error)`
  - Sentinels added to `errors.go`: `ErrExpired`, `ErrNotYetValid`, `ErrUnknownAuthority`, `ErrNotACA`, `ErrPathLenExceeded`, `ErrKeyUsageNotPermitted`, `ErrRevoked`

Validation rules (RFC 5280 §6 subset — no policies, no name constraints):
1. Every certificate in the chain must satisfy `CurrentTime ∈ [NotBefore, NotAfter]`.
2. Name chaining compares `child.RawIssuer` to `parent.RawSubject` byte-for-byte.
3. Every non-leaf must have `BasicConstraintsValid && BasicConstraints.IsCA`.
4. Every non-leaf must have `KeyUsage == 0 || KeyUsage & KeyUsageKeyCertSign != 0`.
5. `pathLenConstraint` on a CA at position *i* limits the number of non-self-issued intermediates *below* it; a violation is `ErrPathLenExceeded`.
6. Each signature must verify under the parent's public key.
7. Chains are built depth-first over `Intermediates` then `Roots`; maximum depth 6 (loop guard). A certificate must not appear twice in a chain.
8. Returned chains start with `c` and end with a root.

- [ ] **Step 1: Write the failing tests**

`internal/pqx509/verify_test.go`:

```go
package pqx509

import (
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

type testHierarchy struct {
	root         *Certificate
	rootSigner   Signer
	inter        *Certificate
	interSigner  Signer
	leaf         *Certificate
}

func issue(t *testing.T, tmpl, parent *Certificate, pub PublicKey, signer Signer) *Certificate {
	t.Helper()
	der, err := CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

func buildHierarchy(t *testing.T) testHierarchy {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)

	root, rootSigner := testCA(t, MLDSA87, 1)

	interPub, interPriv, _ := GenerateKey(rand.Reader, MLDSA65)
	interSigner, err := interPriv.Signer()
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := GenerateSerialNumber(rand.Reader)
	inter := issue(t, &Certificate{
		SerialNumber:          serial,
		SignatureAlgorithm:    MLDSA87,
		Subject:               Name{CommonName: "pqtrust Test Intermediate"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(5 * 365 * 24 * time.Hour),
		BasicConstraints:      BasicConstraints{IsCA: true, MaxPathLen: 0, MaxPathLenSet: true},
		BasicConstraintsValid: true,
		KeyUsage:              KeyUsageKeyCertSign | KeyUsageCRLSign,
	}, root, interPub, rootSigner)

	leafPub, _, _ := GenerateKey(rand.Reader, MLDSA44)
	serial2, _ := GenerateSerialNumber(rand.Reader)
	leaf := issue(t, &Certificate{
		SerialNumber:          serial2,
		SignatureAlgorithm:    MLDSA65,
		Subject:               Name{CommonName: "api.example.com"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(397 * 24 * time.Hour),
		BasicConstraints:      BasicConstraints{IsCA: false},
		BasicConstraintsValid: true,
		KeyUsage:              KeyUsageDigitalSignature,
		ExtKeyUsage:           []ExtKeyUsage{ExtKeyUsageServerAuth},
		SANs:                  SANs{DNSNames: []string{"api.example.com"}},
	}, inter, leafPub, interSigner)

	return testHierarchy{root: root, rootSigner: rootSigner, inter: inter, interSigner: interSigner, leaf: leaf}
}

func TestVerifySignatureFrom(t *testing.T) {
	h := buildHierarchy(t)
	if err := h.leaf.VerifySignatureFrom(h.inter); err != nil {
		t.Errorf("leaf under intermediate: %v", err)
	}
	if err := h.inter.VerifySignatureFrom(h.root); err != nil {
		t.Errorf("intermediate under root: %v", err)
	}
	if err := h.root.VerifySignatureFrom(h.root); err != nil {
		t.Errorf("self-signed root: %v", err)
	}
	if err := h.leaf.VerifySignatureFrom(h.root); !errors.Is(err, ErrBadSignature) {
		t.Errorf("leaf under root should fail with ErrBadSignature, got %v", err)
	}
}

func TestVerifyBuildsFullChain(t *testing.T) {
	h := buildHierarchy(t)
	chains, err := h.leaf.Verify(VerifyOptions{
		Roots:         []*Certificate{h.root},
		Intermediates: []*Certificate{h.inter},
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(chains) != 1 {
		t.Fatalf("got %d chains, want 1", len(chains))
	}
	chain := chains[0]
	if len(chain) != 3 {
		t.Fatalf("chain length = %d, want 3", len(chain))
	}
	if chain[0] != h.leaf || chain[1] != h.inter || chain[2] != h.root {
		t.Error("chain must be leaf, intermediate, root")
	}
}

func TestVerifyUnknownAuthority(t *testing.T) {
	h := buildHierarchy(t)
	if _, err := h.leaf.Verify(VerifyOptions{Roots: []*Certificate{h.root}}); !errors.Is(err, ErrUnknownAuthority) {
		t.Errorf("missing intermediate should yield ErrUnknownAuthority, got %v", err)
	}
	other, _ := testCA(t, MLDSA87, 1)
	if _, err := h.inter.Verify(VerifyOptions{Roots: []*Certificate{other}}); err == nil {
		t.Error("an unrelated root must not validate the intermediate")
	}
}

func TestVerifyExpiredAndNotYetValid(t *testing.T) {
	h := buildHierarchy(t)
	opts := VerifyOptions{Roots: []*Certificate{h.root}, Intermediates: []*Certificate{h.inter}}

	past := opts
	past.CurrentTime = h.leaf.NotBefore.Add(-time.Hour)
	if _, err := h.leaf.Verify(past); !errors.Is(err, ErrNotYetValid) {
		t.Errorf("want ErrNotYetValid, got %v", err)
	}

	future := opts
	future.CurrentTime = h.leaf.NotAfter.Add(time.Hour)
	if _, err := h.leaf.Verify(future); !errors.Is(err, ErrExpired) {
		t.Errorf("want ErrExpired, got %v", err)
	}
}

func TestVerifyRejectsNonCAIssuer(t *testing.T) {
	h := buildHierarchy(t)
	now := time.Now().UTC().Truncate(time.Second)

	// The leaf (cA=FALSE) signs nothing legitimately; forge a chain where a
	// non-CA certificate is presented as an intermediate.
	badPub, badPriv, _ := GenerateKey(rand.Reader, MLDSA44)
	_ = badPub
	badSigner, _ := badPriv.Signer()

	// Re-issue the leaf so its public key matches badSigner, keeping cA=FALSE.
	serial, _ := GenerateSerialNumber(rand.Reader)
	nonCA := issue(t, &Certificate{
		SerialNumber:          serial,
		SignatureAlgorithm:    MLDSA65,
		Subject:               Name{CommonName: "not-a-ca"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		BasicConstraints:      BasicConstraints{IsCA: false},
		BasicConstraintsValid: true,
		KeyUsage:              KeyUsageDigitalSignature,
	}, h.inter, badSigner.Public(), h.interSigner)

	childPub, _, _ := GenerateKey(rand.Reader, MLDSA44)
	serial2, _ := GenerateSerialNumber(rand.Reader)
	child := issue(t, &Certificate{
		SerialNumber:          serial2,
		SignatureAlgorithm:    MLDSA44,
		Subject:               Name{CommonName: "child-of-non-ca"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		BasicConstraints:      BasicConstraints{IsCA: false},
		BasicConstraintsValid: true,
		KeyUsage:              KeyUsageDigitalSignature,
	}, nonCA, childPub, badSigner)

	_, err := child.Verify(VerifyOptions{
		Roots:         []*Certificate{h.root},
		Intermediates: []*Certificate{h.inter, nonCA},
	})
	if !errors.Is(err, ErrNotACA) && !errors.Is(err, ErrUnknownAuthority) {
		t.Errorf("want ErrNotACA (or ErrUnknownAuthority once the branch is pruned), got %v", err)
	}
}

func TestVerifyRejectsIssuerWithoutKeyCertSign(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	root, rootSigner := testCA(t, MLDSA87, 1)

	interPub, interPriv, _ := GenerateKey(rand.Reader, MLDSA65)
	interSigner, _ := interPriv.Signer()
	serial, _ := GenerateSerialNumber(rand.Reader)
	inter := issue(t, &Certificate{
		SerialNumber:          serial,
		SignatureAlgorithm:    MLDSA87,
		Subject:               Name{CommonName: "crl-only CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		BasicConstraints:      BasicConstraints{IsCA: true, MaxPathLen: 0, MaxPathLenSet: true},
		BasicConstraintsValid: true,
		KeyUsage:              KeyUsageCRLSign, // no keyCertSign
	}, root, interPub, rootSigner)

	leafPub, _, _ := GenerateKey(rand.Reader, MLDSA44)
	serial2, _ := GenerateSerialNumber(rand.Reader)
	leaf := issue(t, &Certificate{
		SerialNumber:          serial2,
		SignatureAlgorithm:    MLDSA65,
		Subject:               Name{CommonName: "leaf"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		BasicConstraints:      BasicConstraints{IsCA: false},
		BasicConstraintsValid: true,
		KeyUsage:              KeyUsageDigitalSignature,
	}, inter, leafPub, interSigner)

	_, err := leaf.Verify(VerifyOptions{Roots: []*Certificate{root}, Intermediates: []*Certificate{inter}})
	if !errors.Is(err, ErrKeyUsageNotPermitted) && !errors.Is(err, ErrUnknownAuthority) {
		t.Errorf("want ErrKeyUsageNotPermitted, got %v", err)
	}
}

func TestVerifyRejectsPathLenViolation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	// Root with pathlen=0 must not allow an intermediate to issue further CAs.
	root, rootSigner := testCA(t, MLDSA87, 0)

	interPub, interPriv, _ := GenerateKey(rand.Reader, MLDSA65)
	interSigner, _ := interPriv.Signer()
	s1, _ := GenerateSerialNumber(rand.Reader)
	inter := issue(t, &Certificate{
		SerialNumber:          s1,
		SignatureAlgorithm:    MLDSA87,
		Subject:               Name{CommonName: "inter-1"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		BasicConstraints:      BasicConstraints{IsCA: true, MaxPathLen: 0, MaxPathLenSet: true},
		BasicConstraintsValid: true,
		KeyUsage:              KeyUsageKeyCertSign | KeyUsageCRLSign,
	}, root, interPub, rootSigner)

	inter2Pub, inter2Priv, _ := GenerateKey(rand.Reader, MLDSA65)
	inter2Signer, _ := inter2Priv.Signer()
	s2, _ := GenerateSerialNumber(rand.Reader)
	inter2 := issue(t, &Certificate{
		SerialNumber:          s2,
		SignatureAlgorithm:    MLDSA65,
		Subject:               Name{CommonName: "inter-2"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		BasicConstraints:      BasicConstraints{IsCA: true},
		BasicConstraintsValid: true,
		KeyUsage:              KeyUsageKeyCertSign | KeyUsageCRLSign,
	}, inter, inter2Pub, interSigner)

	leafPub, _, _ := GenerateKey(rand.Reader, MLDSA44)
	s3, _ := GenerateSerialNumber(rand.Reader)
	leaf := issue(t, &Certificate{
		SerialNumber:          s3,
		SignatureAlgorithm:    MLDSA65,
		Subject:               Name{CommonName: "deep-leaf"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		BasicConstraints:      BasicConstraints{IsCA: false},
		BasicConstraintsValid: true,
		KeyUsage:              KeyUsageDigitalSignature,
	}, inter2, leafPub, inter2Signer)

	_, err := leaf.Verify(VerifyOptions{Roots: []*Certificate{root}, Intermediates: []*Certificate{inter, inter2}})
	if !errors.Is(err, ErrPathLenExceeded) && !errors.Is(err, ErrUnknownAuthority) {
		t.Errorf("want ErrPathLenExceeded, got %v", err)
	}
}

func TestVerifyCheckRevocationHook(t *testing.T) {
	h := buildHierarchy(t)
	called := 0
	_, err := h.leaf.Verify(VerifyOptions{
		Roots:         []*Certificate{h.root},
		Intermediates: []*Certificate{h.inter},
		CheckRevocation: func(cert, issuer *Certificate) error {
			called++
			if cert.Subject.CommonName == "api.example.com" {
				return ErrRevoked
			}
			return nil
		},
	})
	if !errors.Is(err, ErrRevoked) {
		t.Errorf("want ErrRevoked, got %v", err)
	}
	if called == 0 {
		t.Error("CheckRevocation was never called")
	}
}
```

- [ ] **Step 2: Run and confirm failure**

Run: `CGO_ENABLED=0 go test ./internal/pqx509/ -run Verify -v`
Expected: compile failure.

- [ ] **Step 3: Add the new sentinels to `errors.go`**

```go
var (
	// ErrExpired reports a certificate whose NotAfter has passed.
	ErrExpired = errors.New("pqx509: certificate has expired")
	// ErrNotYetValid reports a certificate whose NotBefore is in the future.
	ErrNotYetValid = errors.New("pqx509: certificate is not yet valid")
	// ErrUnknownAuthority reports that no chain to a configured root was found.
	ErrUnknownAuthority = errors.New("pqx509: unknown certificate authority")
	// ErrNotACA reports an issuer without basicConstraints cA=TRUE.
	ErrNotACA = errors.New("pqx509: issuer is not a CA")
	// ErrPathLenExceeded reports a chain longer than a pathLenConstraint allows.
	ErrPathLenExceeded = errors.New("pqx509: pathLenConstraint exceeded")
	// ErrKeyUsageNotPermitted reports an issuer lacking keyCertSign.
	ErrKeyUsageNotPermitted = errors.New("pqx509: key usage does not permit this operation")
	// ErrRevoked reports a certificate rejected by a revocation check.
	ErrRevoked = errors.New("pqx509: certificate has been revoked")
)
```

- [ ] **Step 4: Implement `verify.go`**

```go
package pqx509

import (
	"bytes"
	"errors"
	"fmt"
	"time"
)

const maxChainDepth = 6

// VerifySignatureFrom checks c's signature against parent's public key.
func (c *Certificate) VerifySignatureFrom(parent *Certificate) error {
	if parent == nil {
		return fmt.Errorf("pqx509: parent is required")
	}
	if c.SignatureAlgorithm != parent.PublicKey.Algorithm {
		return fmt.Errorf("%w: certificate is signed with %v but the issuer key is %v",
			ErrBadSignature, c.SignatureAlgorithm, parent.PublicKey.Algorithm)
	}
	if err := Verify(parent.PublicKey, c.RawTBSCertificate, c.Signature); err != nil {
		return err
	}
	return nil
}

// VerifyOptions configures path validation.
type VerifyOptions struct {
	Roots         []*Certificate
	Intermediates []*Certificate
	// CurrentTime defaults to time.Now when zero.
	CurrentTime time.Time
	// CheckRevocation, when set, is invoked for every certificate in a
	// candidate chain together with its issuer. A non-nil error rejects it.
	CheckRevocation func(cert, issuer *Certificate) error
}

// Verify performs a simplified RFC 5280 section 6 path validation and returns
// every chain from c to a configured root. Certificate policies and name
// constraints are not implemented.
func (c *Certificate) Verify(opts VerifyOptions) ([][]*Certificate, error) {
	now := opts.CurrentTime
	if now.IsZero() {
		now = time.Now()
	}
	if err := checkValidity(c, now); err != nil {
		return nil, err
	}

	var chains [][]*Certificate
	var firstErr error
	note := func(err error) {
		if firstErr == nil && err != nil {
			firstErr = err
		}
	}

	var walk func(chain []*Certificate) 
	walk = func(chain []*Certificate) {
		leaf := chain[len(chain)-1]

		for _, root := range opts.Roots {
			if !bytes.Equal(leaf.RawIssuer, root.RawSubject) {
				continue
			}
			candidate := append(append([]*Certificate{}, chain...), root)
			if err := checkLink(leaf, root, candidate, now, opts); err != nil {
				note(err)
				continue
			}
			chains = append(chains, candidate)
		}

		if len(chain) >= maxChainDepth {
			return
		}
		for _, inter := range opts.Intermediates {
			if !bytes.Equal(leaf.RawIssuer, inter.RawSubject) {
				continue
			}
			if contains(chain, inter) {
				continue
			}
			candidate := append(append([]*Certificate{}, chain...), inter)
			if err := checkLink(leaf, inter, candidate, now, opts); err != nil {
				note(err)
				continue
			}
			walk(candidate)
		}
	}
	walk([]*Certificate{c})

	if len(chains) == 0 {
		if firstErr != nil {
			return nil, firstErr
		}
		return nil, fmt.Errorf("%w: no chain to a trusted root for %q", ErrUnknownAuthority, c.Subject)
	}
	return chains, nil
}

// checkLink validates issuer as the signer of child within candidate. candidate
// is the chain including issuer, so its length gives the issuer's depth.
func checkLink(child, issuer *Certificate, candidate []*Certificate, now time.Time, opts VerifyOptions) error {
	if err := checkValidity(issuer, now); err != nil {
		return err
	}
	if !issuer.BasicConstraintsValid || !issuer.BasicConstraints.IsCA {
		return fmt.Errorf("%w: %q", ErrNotACA, issuer.Subject)
	}
	if issuer.KeyUsage != 0 && issuer.KeyUsage&KeyUsageKeyCertSign == 0 {
		return fmt.Errorf("%w: %q lacks keyCertSign", ErrKeyUsageNotPermitted, issuer.Subject)
	}
	// Certificates below issuer in the chain, excluding the leaf: these are the
	// intermediate CAs that pathLenConstraint limits.
	if issuer.BasicConstraints.MaxPathLenSet {
		below := len(candidate) - 2 // total minus issuer minus leaf
		if below > issuer.BasicConstraints.MaxPathLen {
			return fmt.Errorf("%w: %q allows %d intermediate CAs, chain has %d",
				ErrPathLenExceeded, issuer.Subject, issuer.BasicConstraints.MaxPathLen, below)
		}
	}
	if err := child.VerifySignatureFrom(issuer); err != nil {
		return err
	}
	if opts.CheckRevocation != nil {
		if err := opts.CheckRevocation(child, issuer); err != nil {
			if errors.Is(err, ErrRevoked) {
				return err
			}
			return fmt.Errorf("pqx509: revocation check failed: %w", err)
		}
	}
	return nil
}

func checkValidity(c *Certificate, now time.Time) error {
	if now.Before(c.NotBefore) {
		return fmt.Errorf("%w: %q is valid from %v", ErrNotYetValid, c.Subject, c.NotBefore)
	}
	if now.After(c.NotAfter) {
		return fmt.Errorf("%w: %q expired at %v", ErrExpired, c.Subject, c.NotAfter)
	}
	return nil
}

func contains(chain []*Certificate, c *Certificate) bool {
	for _, x := range chain {
		if x == c || bytes.Equal(x.Raw, c.Raw) {
			return true
		}
	}
	return false
}
```

- [ ] **Step 5: Run the tests and confirm they pass**

Run: `CGO_ENABLED=0 go test ./internal/pqx509/ -v`
Expected: PASS. If `TestVerifyRejectsPathLenViolation` reports `ErrUnknownAuthority` instead of `ErrPathLenExceeded`, the `firstErr` propagation in `Verify` is dropping the specific error — fix `note`, not the test.

- [ ] **Step 6: Check coverage of the package so far**

```bash
CGO_ENABLED=0 go test ./internal/pqx509/ -coverprofile=/tmp/pqx509.out
go tool cover -func=/tmp/pqx509.out | tail -n 1
```

Expected: ≥ 80% statement coverage (the spec's target for `pqx509`). If below, add table cases to the weakest file before moving on.

- [ ] **Step 7: Commit**

```bash
git add internal/pqx509
git commit -m "feat(pqx509): RFC 5280 path validation with revocation hook"
```

---

### Task 6: Certificate revocation lists

**Files:**
- Create: `internal/pqx509/crl.go`
- Modify: `internal/pqx509/asn1types.go` (append CRL structures)
- Test: `internal/pqx509/crl_test.go`

**Interfaces:**
- Consumes: Tasks 1–5.
- Produces:
  - ```go
    type RevocationEntry struct {
        SerialNumber   *big.Int
        RevocationTime time.Time
        ReasonCode     int // RFC 5280 5.3.1; 0 (unspecified) omits the extension
    }
    type RevocationList struct {
        Raw          []byte
        RawTBS       []byte
        Issuer       Name
        RawIssuer    []byte
        SignatureAlgorithm Algorithm
        Signature    []byte
        ThisUpdate   time.Time
        NextUpdate   time.Time
        Number       *big.Int
        AuthorityKeyID []byte
        Entries      []RevocationEntry
    }
    ```
  - `func CreateRevocationList(rand io.Reader, issuer *Certificate, signer Signer, number *big.Int, entries []RevocationEntry, thisUpdate, nextUpdate time.Time) ([]byte, error)`
  - `func ParseRevocationList(der []byte) (*RevocationList, error)`
  - `func (l *RevocationList) VerifySignatureFrom(issuer *Certificate) error`
  - `func (l *RevocationList) IsRevoked(serial *big.Int) (RevocationEntry, bool)`

Rules:
- `issuer` must have `KeyUsage == 0 || KeyUsage & KeyUsageCRLSign != 0`, else `ErrKeyUsageNotPermitted`.
- Version is v2 (encodes as integer 1) whenever extensions are present, which is always here (CRL number + AKID).
- `revokedCertificates` is omitted entirely when there are no entries.
- CRL extensions, in order: authorityKeyIdentifier, cRLNumber (both non-critical).
- Per-entry `crlEntryExtensions` carries only `reasonCode`, and only when non-zero.

- [ ] **Step 1: Write the failing tests**

`internal/pqx509/crl_test.go`:

```go
package pqx509

import (
	"bytes"
	"crypto/rand"
	"errors"
	"math/big"
	"testing"
	"time"
)

func TestCreateParseCRLRoundTrip(t *testing.T) {
	ca, signer := testCA(t, MLDSA65, 0)
	now := time.Now().UTC().Truncate(time.Second)
	entries := []RevocationEntry{
		{SerialNumber: big.NewInt(0x1234), RevocationTime: now.Add(-2 * time.Hour), ReasonCode: 1},
		{SerialNumber: big.NewInt(0x5678), RevocationTime: now.Add(-time.Hour), ReasonCode: 0},
	}
	der, err := CreateRevocationList(rand.Reader, ca, signer, big.NewInt(3), entries, now, now.Add(7*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	crl, err := ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	if crl.SignatureAlgorithm != MLDSA65 {
		t.Errorf("signature algorithm = %v", crl.SignatureAlgorithm)
	}
	if !bytes.Equal(crl.RawIssuer, ca.RawSubject) {
		t.Error("CRL issuer must equal the CA subject bytes")
	}
	if crl.Number == nil || crl.Number.Cmp(big.NewInt(3)) != 0 {
		t.Errorf("CRL number = %v, want 3", crl.Number)
	}
	if !bytes.Equal(crl.AuthorityKeyID, ca.SubjectKeyID) {
		t.Error("CRL AKID must equal the CA SKID")
	}
	if !crl.ThisUpdate.Equal(now) || !crl.NextUpdate.Equal(now.Add(7*24*time.Hour)) {
		t.Errorf("update times = %v / %v", crl.ThisUpdate, crl.NextUpdate)
	}
	if len(crl.Entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(crl.Entries))
	}
	if crl.Entries[0].SerialNumber.Cmp(big.NewInt(0x1234)) != 0 || crl.Entries[0].ReasonCode != 1 {
		t.Errorf("entry 0 = %+v", crl.Entries[0])
	}
	if crl.Entries[1].ReasonCode != 0 {
		t.Errorf("entry 1 reason = %d, want 0", crl.Entries[1].ReasonCode)
	}
	if !crl.Entries[0].RevocationTime.Equal(entries[0].RevocationTime) {
		t.Errorf("revocation time = %v, want %v", crl.Entries[0].RevocationTime, entries[0].RevocationTime)
	}
	if err := crl.VerifySignatureFrom(ca); err != nil {
		t.Errorf("CRL signature must verify: %v", err)
	}
}

func TestEmptyCRLIsValid(t *testing.T) {
	ca, signer := testCA(t, MLDSA44, 0)
	now := time.Now().UTC().Truncate(time.Second)
	der, err := CreateRevocationList(rand.Reader, ca, signer, big.NewInt(1), nil, now, now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	crl, err := ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(crl.Entries) != 0 {
		t.Errorf("got %d entries, want 0", len(crl.Entries))
	}
	if err := crl.VerifySignatureFrom(ca); err != nil {
		t.Errorf("empty CRL must verify: %v", err)
	}
}

func TestIsRevoked(t *testing.T) {
	ca, signer := testCA(t, MLDSA44, 0)
	now := time.Now().UTC().Truncate(time.Second)
	der, _ := CreateRevocationList(rand.Reader, ca, signer, big.NewInt(1),
		[]RevocationEntry{{SerialNumber: big.NewInt(42), RevocationTime: now, ReasonCode: 4}}, now, now.Add(time.Hour))
	crl, err := ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := crl.IsRevoked(big.NewInt(42))
	if !ok || entry.ReasonCode != 4 {
		t.Errorf("IsRevoked(42) = %+v, %v", entry, ok)
	}
	if _, ok := crl.IsRevoked(big.NewInt(43)); ok {
		t.Error("IsRevoked(43) must be false")
	}
}

func TestCreateRevocationListValidation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	t.Run("issuer lacks cRLSign", func(t *testing.T) {
		root, rootSigner := testCA(t, MLDSA87, 1)
		pub, priv, _ := GenerateKey(rand.Reader, MLDSA65)
		s, _ := GenerateSerialNumber(rand.Reader)
		noCRLSign := issue(t, &Certificate{
			SerialNumber:          s,
			SignatureAlgorithm:    MLDSA87,
			Subject:               Name{CommonName: "no-crl-sign"},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.Add(24 * time.Hour),
			BasicConstraints:      BasicConstraints{IsCA: true, MaxPathLen: 0, MaxPathLenSet: true},
			BasicConstraintsValid: true,
			KeyUsage:              KeyUsageKeyCertSign,
		}, root, pub, rootSigner)
		signer, _ := priv.Signer()
		if _, err := CreateRevocationList(rand.Reader, noCRLSign, signer, big.NewInt(1), nil, now, now.Add(time.Hour)); !errors.Is(err, ErrKeyUsageNotPermitted) {
			t.Errorf("want ErrKeyUsageNotPermitted, got %v", err)
		}
	})

	t.Run("nextUpdate before thisUpdate", func(t *testing.T) {
		ca, signer := testCA(t, MLDSA44, 0)
		if _, err := CreateRevocationList(rand.Reader, ca, signer, big.NewInt(1), nil, now, now.Add(-time.Hour)); err == nil {
			t.Error("nextUpdate before thisUpdate must be an error")
		}
	})

	t.Run("nil CRL number", func(t *testing.T) {
		ca, signer := testCA(t, MLDSA44, 0)
		if _, err := CreateRevocationList(rand.Reader, ca, signer, nil, nil, now, now.Add(time.Hour)); err == nil {
			t.Error("nil CRL number must be an error")
		}
	})
}

func TestParseRevocationListRejectsTrailingData(t *testing.T) {
	ca, signer := testCA(t, MLDSA44, 0)
	now := time.Now().UTC().Truncate(time.Second)
	der, _ := CreateRevocationList(rand.Reader, ca, signer, big.NewInt(1), nil, now, now.Add(time.Hour))
	if _, err := ParseRevocationList(append(der, 0x00)); err == nil {
		t.Error("trailing data must be rejected")
	}
}
```

- [ ] **Step 2: Run and confirm failure**

Run: `CGO_ENABLED=0 go test ./internal/pqx509/ -run CRL -v`
Expected: compile failure.

- [ ] **Step 3: Append the CRL ASN.1 structures to `asn1types.go`**

```go
type revokedCertificateDER struct {
	SerialNumber   *big.Int
	RevocationDate asn1.RawValue
	Extensions     []extension `asn1:"optional"`
}

type tbsCertList struct {
	Version             int // v2 == 1
	SignatureAlgorithm  algorithmIdentifier
	Issuer              asn1.RawValue
	ThisUpdate          asn1.RawValue
	NextUpdate          asn1.RawValue             `asn1:"optional"`
	RevokedCertificates []revokedCertificateDER   `asn1:"optional"`
	Extensions          []extension               `asn1:"optional,explicit,tag:0"`
}

type certificateListDER struct {
	TBSCertList        asn1.RawValue
	SignatureAlgorithm algorithmIdentifier
	SignatureValue     asn1.BitString
}
```

- [ ] **Step 4: Implement `crl.go`**

```go
package pqx509

import (
	"bytes"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"time"
)

// RevocationEntry is one revoked certificate on a CRL.
type RevocationEntry struct {
	SerialNumber   *big.Int
	RevocationTime time.Time
	// ReasonCode is an RFC 5280 5.3.1 CRLReason. Zero (unspecified) omits the extension.
	ReasonCode int
}

// RevocationList is a parsed or newly built RFC 5280 section 5 CRL.
type RevocationList struct {
	Raw    []byte
	RawTBS []byte

	Issuer             Name
	RawIssuer          []byte
	SignatureAlgorithm Algorithm
	Signature          []byte

	ThisUpdate time.Time
	NextUpdate time.Time

	Number         *big.Int
	AuthorityKeyID []byte
	Entries        []RevocationEntry
}

// CreateRevocationList builds and signs a v2 CRL for issuer.
func CreateRevocationList(r io.Reader, issuer *Certificate, signer Signer, number *big.Int, entries []RevocationEntry, thisUpdate, nextUpdate time.Time) ([]byte, error) {
	if issuer == nil || signer == nil {
		return nil, fmt.Errorf("pqx509: issuer and signer are required")
	}
	if number == nil || number.Sign() < 0 {
		return nil, fmt.Errorf("pqx509: CRL number must be a non-negative integer")
	}
	if !nextUpdate.After(thisUpdate) {
		return nil, fmt.Errorf("pqx509: nextUpdate (%v) must be after thisUpdate (%v)", nextUpdate, thisUpdate)
	}
	if issuer.KeyUsage != 0 && issuer.KeyUsage&KeyUsageCRLSign == 0 {
		return nil, fmt.Errorf("%w: %q lacks cRLSign", ErrKeyUsageNotPermitted, issuer.Subject)
	}
	if signer.Algorithm() != issuer.PublicKey.Algorithm {
		return nil, fmt.Errorf("pqx509: signer algorithm %v does not match the issuer key algorithm %v",
			signer.Algorithm(), issuer.PublicKey.Algorithm)
	}

	thisDER, err := marshalTime(thisUpdate)
	if err != nil {
		return nil, err
	}
	nextDER, err := marshalTime(nextUpdate)
	if err != nil {
		return nil, err
	}

	var revoked []revokedCertificateDER
	for _, e := range entries {
		if e.SerialNumber == nil || e.SerialNumber.Sign() <= 0 {
			return nil, fmt.Errorf("pqx509: revocation entry serial number must be positive")
		}
		when, err := marshalTime(e.RevocationTime)
		if err != nil {
			return nil, err
		}
		entry := revokedCertificateDER{SerialNumber: e.SerialNumber, RevocationDate: when}
		if e.ReasonCode != 0 {
			v, err := marshalCRLReason(e.ReasonCode)
			if err != nil {
				return nil, err
			}
			entry.Extensions = []extension{{ID: oidExtCRLReason, Value: v}}
		}
		revoked = append(revoked, entry)
	}

	akid, err := KeyIdentifier(issuer.PublicKey)
	if err != nil {
		return nil, err
	}
	akidDER, err := marshalAuthorityKeyID(akid)
	if err != nil {
		return nil, err
	}
	numberDER, err := marshalCRLNumber(number)
	if err != nil {
		return nil, err
	}

	issuerDER := issuer.RawSubject
	if len(issuerDER) == 0 {
		if issuerDER, err = issuer.Subject.ToRDNSequence(); err != nil {
			return nil, err
		}
	}

	tbs := tbsCertList{
		Version:            1, // v2
		SignatureAlgorithm: algorithmIdentifier{Algorithm: signer.Algorithm().OID()},
		Issuer:             asn1.RawValue{FullBytes: issuerDER},
		ThisUpdate:         thisDER,
		NextUpdate:         nextDER,
		RevokedCertificates: revoked,
		Extensions: []extension{
			{ID: oidExtAuthorityKeyID, Value: akidDER},
			{ID: oidExtCRLNumber, Value: numberDER},
		},
	}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, fmt.Errorf("pqx509: marshaling TBSCertList: %w", err)
	}
	sig, err := signer.Sign(r, tbsDER)
	if err != nil {
		return nil, fmt.Errorf("pqx509: signing CRL: %w", err)
	}
	der, err := asn1.Marshal(certificateListDER{
		TBSCertList:        asn1.RawValue{FullBytes: tbsDER},
		SignatureAlgorithm: algorithmIdentifier{Algorithm: signer.Algorithm().OID()},
		SignatureValue:     asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	})
	if err != nil {
		return nil, fmt.Errorf("pqx509: marshaling CRL: %w", err)
	}
	return der, nil
}

// ParseRevocationList decodes a DER CRL.
func ParseRevocationList(der []byte) (*RevocationList, error) {
	var outer certificateListDER
	rest, err := asn1.Unmarshal(der, &outer)
	if err != nil {
		return nil, fmt.Errorf("%w: CRL: %w", ErrMalformedDER, err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: %d bytes after CRL", ErrTrailingData, len(rest))
	}
	var tbs tbsCertList
	if trailing, err := asn1.Unmarshal(outer.TBSCertList.FullBytes, &tbs); err != nil {
		return nil, fmt.Errorf("%w: TBSCertList: %w", ErrMalformedDER, err)
	} else if len(trailing) != 0 {
		return nil, fmt.Errorf("%w: after TBSCertList", ErrTrailingData)
	}

	alg, err := algorithmFromOID(outer.SignatureAlgorithm.Algorithm)
	if err != nil {
		return nil, err
	}
	if len(outer.SignatureAlgorithm.Parameters.FullBytes) != 0 {
		return nil, fmt.Errorf("%w: CRL signature AlgorithmIdentifier must omit parameters", ErrMalformedDER)
	}
	issuer, err := ParseName(tbs.Issuer.FullBytes)
	if err != nil {
		return nil, err
	}
	thisUpdate, err := parseTime(tbs.ThisUpdate)
	if err != nil {
		return nil, err
	}
	l := &RevocationList{
		Raw:                bytes.Clone(der),
		RawTBS:             bytes.Clone(outer.TBSCertList.FullBytes),
		Issuer:             issuer,
		RawIssuer:          bytes.Clone(tbs.Issuer.FullBytes),
		SignatureAlgorithm: alg,
		Signature:          bytes.Clone(outer.SignatureValue.Bytes),
		ThisUpdate:         thisUpdate,
	}
	if len(tbs.NextUpdate.FullBytes) > 0 {
		if l.NextUpdate, err = parseTime(tbs.NextUpdate); err != nil {
			return nil, err
		}
	}
	for _, e := range tbs.Extensions {
		switch {
		case e.ID.Equal(oidExtAuthorityKeyID):
			if l.AuthorityKeyID, err = parseAuthorityKeyID(e.Value); err != nil {
				return nil, err
			}
		case e.ID.Equal(oidExtCRLNumber):
			var n *big.Int
			if trailing, err := asn1.Unmarshal(e.Value, &n); err != nil {
				return nil, fmt.Errorf("%w: CRL number: %w", ErrMalformedDER, err)
			} else if len(trailing) != 0 {
				return nil, fmt.Errorf("%w: after CRL number", ErrTrailingData)
			}
			l.Number = n
		default:
			if e.Critical {
				return nil, fmt.Errorf("%w: CRL extension %s", ErrUnsupportedCriticalExtension, e.ID)
			}
		}
	}
	for _, rc := range tbs.RevokedCertificates {
		when, err := parseTime(rc.RevocationDate)
		if err != nil {
			return nil, err
		}
		entry := RevocationEntry{SerialNumber: rc.SerialNumber, RevocationTime: when}
		for _, e := range rc.Extensions {
			switch {
			case e.ID.Equal(oidExtCRLReason):
				if entry.ReasonCode, err = parseCRLReason(e.Value); err != nil {
					return nil, err
				}
			default:
				if e.Critical {
					return nil, fmt.Errorf("%w: CRL entry extension %s", ErrUnsupportedCriticalExtension, e.ID)
				}
			}
		}
		l.Entries = append(l.Entries, entry)
	}
	return l, nil
}

// VerifySignatureFrom checks the CRL signature against issuer's public key.
func (l *RevocationList) VerifySignatureFrom(issuer *Certificate) error {
	if issuer == nil {
		return fmt.Errorf("pqx509: issuer is required")
	}
	if !bytes.Equal(l.RawIssuer, issuer.RawSubject) {
		return fmt.Errorf("%w: CRL issuer does not match certificate subject", ErrUnknownAuthority)
	}
	if l.SignatureAlgorithm != issuer.PublicKey.Algorithm {
		return fmt.Errorf("%w: CRL is signed with %v but the issuer key is %v",
			ErrBadSignature, l.SignatureAlgorithm, issuer.PublicKey.Algorithm)
	}
	return Verify(issuer.PublicKey, l.RawTBS, l.Signature)
}

// IsRevoked reports whether serial appears on the CRL.
func (l *RevocationList) IsRevoked(serial *big.Int) (RevocationEntry, bool) {
	for _, e := range l.Entries {
		if e.SerialNumber != nil && serial != nil && e.SerialNumber.Cmp(serial) == 0 {
			return e, true
		}
	}
	return RevocationEntry{}, false
}
```

- [ ] **Step 5: Run the tests and confirm they pass**

Run: `CGO_ENABLED=0 go test ./internal/pqx509/ -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/pqx509
git commit -m "feat(pqx509): CRL creation, parsing and verification"
```

---

### Task 7: NIST ACVP known-answer tests

**Files:**
- Create: `internal/pqx509/acvp_test.go`, `testdata/acvp/README.md`, `scripts/fetch-acvp.sh`
- Test: same file

**Interfaces:**
- Consumes: `GenerateKey`, `PrivateKey.Signer`, `Verify`, `Algorithm` (Task 1).
- Produces: no production code — this task is pure verification that our ML-DSA usage matches FIPS 204.

- [ ] **Step 1: Add the vector fetch script**

`scripts/fetch-acvp.sh`:

```bash
#!/usr/bin/env bash
# Downloads the NIST ACVP ML-DSA sigVer vectors used by internal/pqx509/acvp_test.go.
set -euo pipefail

dest="testdata/acvp"
mkdir -p "$dest"

base="https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files"

fetch() {
	local dir="$1" file="$2" out="$3"
	echo "fetching ${dir}/${file}"
	curl -fsSL "${base}/${dir}/${file}" -o "${dest}/${out}"
}

fetch "ML-DSA-sigVer-FIPS204" "prompt.json" "mldsa-sigver-prompt.json"
fetch "ML-DSA-sigVer-FIPS204" "expectedResults.json" "mldsa-sigver-expected.json"

echo "done; vectors in ${dest}"
```

```bash
chmod +x scripts/fetch-acvp.sh
./scripts/fetch-acvp.sh
ls -la testdata/acvp
```

If the upstream layout has changed and the download 404s, browse `https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files` and adjust the directory names in the script. Do not proceed with hand-written "vectors" — the point of this task is third-party data.

- [ ] **Step 2: Record where the data came from**

`testdata/acvp/README.md`:

```markdown
# ACVP test vectors

ML-DSA (FIPS 204) signature verification vectors from the NIST ACVP server
repository: <https://github.com/usnistgov/ACVP-Server> (`gen-val/json-files/`).

Refresh with `./scripts/fetch-acvp.sh`. These files are inputs to
`internal/pqx509/acvp_test.go` and are not covered by pqtrust's license.
```

- [ ] **Step 3: Write the failing test**

`internal/pqx509/acvp_test.go`:

```go
package pqx509

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The ACVP sigVer prompt/expectedResults pair: each test case gives a public
// key, message, signature and (in expectedResults) whether it must verify.
type acvpSigVerPrompt struct {
	TestGroups []struct {
		TgID          int    `json:"tgId"`
		ParameterSet  string `json:"parameterSet"`
		SignatureInterface string `json:"signatureInterface"`
		PreHash       string `json:"preHash"`
		PublicKey     string `json:"pk"`
		Tests         []struct {
			TcID      int    `json:"tcId"`
			PublicKey string `json:"pk"`
			Message   string `json:"message"`
			Signature string `json:"signature"`
			Context   string `json:"context"`
		} `json:"tests"`
	} `json:"testGroups"`
}

type acvpSigVerExpected struct {
	TestGroups []struct {
		TgID  int `json:"tgId"`
		Tests []struct {
			TcID       int  `json:"tcId"`
			TestPassed bool `json:"testPassed"`
		} `json:"tests"`
	} `json:"testGroups"`
}

func loadJSON(t *testing.T, name string, v any) {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "acvp", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("ACVP vectors missing (%v); run ./scripts/fetch-acvp.sh", err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("parsing %s: %v", name, err)
	}
}

func TestACVPMLDSASigVer(t *testing.T) {
	var prompt acvpSigVerPrompt
	var expected acvpSigVerExpected
	loadJSON(t, "mldsa-sigver-prompt.json", &prompt)
	loadJSON(t, "mldsa-sigver-expected.json", &expected)

	// tgId/tcId -> expected verdict
	verdict := map[[2]int]bool{}
	for _, g := range expected.TestGroups {
		for _, tc := range g.Tests {
			verdict[[2]int{g.TgID, tc.TcID}] = tc.TestPassed
		}
	}

	algByParamSet := map[string]Algorithm{
		"ML-DSA-44": MLDSA44,
		"ML-DSA-65": MLDSA65,
		"ML-DSA-87": MLDSA87,
	}

	checked := 0
	for _, g := range prompt.TestGroups {
		alg, ok := algByParamSet[g.ParameterSet]
		if !ok {
			continue
		}
		// pqtrust only ever uses pure, internal-interface-free signing with an
		// empty context, so skip groups that exercise other modes.
		if g.PreHash != "" && g.PreHash != "pure" {
			continue
		}
		if g.SignatureInterface != "" && g.SignatureInterface != "external" {
			continue
		}
		for _, tc := range g.Tests {
			want, haveVerdict := verdict[[2]int{g.TgID, tc.TcID}]
			if !haveVerdict {
				continue
			}
			if tc.Context != "" {
				continue // pqtrust always signs with an empty context
			}
			pkHex := tc.PublicKey
			if pkHex == "" {
				pkHex = g.PublicKey
			}
			pkBytes, err := hex.DecodeString(pkHex)
			if err != nil || len(pkBytes) != alg.PublicKeySize() {
				continue
			}
			msg, err := hex.DecodeString(tc.Message)
			if err != nil {
				continue
			}
			sig, err := hex.DecodeString(tc.Signature)
			if err != nil {
				continue
			}
			got := Verify(PublicKey{Algorithm: alg, Bytes: pkBytes}, msg, sig) == nil
			if got != want {
				t.Errorf("tgId %d tcId %d (%s): Verify = %v, want %v", g.TgID, tc.TcID, g.ParameterSet, got, want)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no ACVP cases were exercised; the JSON field mapping is wrong")
	}
	t.Logf("checked %d ACVP signature verification cases", checked)
}

func TestACVPSelfConsistencySignThenVerify(t *testing.T) {
	// A deterministic-seed check that our seed expansion matches CIRCL's, and
	// that sign/verify agree across all three parameter sets.
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i)
	}
	for _, alg := range []Algorithm{MLDSA44, MLDSA65, MLDSA87} {
		priv := PrivateKey{Algorithm: alg, Seed: seed[:]}
		signer, err := priv.Signer()
		if err != nil {
			t.Fatal(err)
		}
		msg := []byte("FIPS 204 pure mode, empty context")
		sig, err := signer.Sign(nil, msg)
		if err != nil {
			t.Fatal(err)
		}
		if err := Verify(signer.Public(), msg, sig); err != nil {
			t.Errorf("%v: %v", alg, err)
		}
	}
}
```

- [ ] **Step 4: Run the test**

Run: `CGO_ENABLED=0 go test ./internal/pqx509/ -run ACVP -v`
Expected: PASS with a log line like `checked 45 ACVP signature verification cases`.

If it fails with `no ACVP cases were exercised`, print one test group to inspect the real field names and fix the structs:

```bash
python3 -c "import json;d=json.load(open('testdata/acvp/mldsa-sigver-prompt.json'));g=d['testGroups'][0];print({k:v for k,v in g.items() if k!='tests'});print({k:(v[:64] if isinstance(v,str) else v) for k,v in g['tests'][0].items()})"
```

If individual cases mismatch, that is a real correctness bug in `Verify` — do not relax the test.

- [ ] **Step 5: Ignore the vectors' bulk but keep them reproducible**

Add to `.gitignore`:

```
# Large third-party ACVP vectors; refetch with ./scripts/fetch-acvp.sh
/testdata/acvp/*.json
```

Note the trade-off: CI must run `./scripts/fetch-acvp.sh` before `go test`. Task 14 adds that step. The test skips (not fails) when the files are absent, so a fresh clone still builds green.

- [ ] **Step 6: Commit**

```bash
git add internal/pqx509/acvp_test.go scripts/fetch-acvp.sh testdata/acvp/README.md .gitignore
git commit -m "test(pqx509): NIST ACVP ML-DSA signature verification vectors"
```

---

### Task 8: keystore — sealed private key storage

**Files:**
- Create: `internal/keystore/seal.go`, `internal/keystore/keystore.go`, `internal/keystore/filebackend.go`
- Test: `internal/keystore/seal_test.go`, `internal/keystore/filebackend_test.go`

**Interfaces:**
- Consumes: `pqx509.Algorithm`, `pqx509.GenerateKey`, `pqx509.PrivateKey`, `pqx509.PublicKey`, `pqx509.Signer`.
- Produces:
  - ```go
    type Backend interface {
        Generate(alg pqx509.Algorithm, passphrase []byte) (keyID string, pub pqx509.PublicKey, priv pqx509.PrivateKey, err error)
        Load(keyID string, passphrase []byte) (pqx509.Signer, error)
        Store(keyID string, priv pqx509.PrivateKey, passphrase []byte) error
        Delete(keyID string) error
        Has(keyID string) (bool, error)
    }
    ```
  - `func NewFileBackend(dir string) (*FileBackend, error)` — implements `Backend`
  - `func Seal(priv pqx509.PrivateKey, passphrase []byte) ([]byte, error)`
  - `func Unseal(sealed []byte, passphrase []byte) (pqx509.PrivateKey, error)`
  - Sentinels: `ErrWrongPassphrase`, `ErrKeyNotFound`, `ErrKeyExists`, `ErrEmptyPassphrase`
  - `func NewKeyID() (string, error)` — 32 lowercase hex characters (16 random bytes)

Sealed envelope format (JSON, so it is inspectable and versioned):

```json
{"v":1,"alg":"ML-DSA-65","kdf":"argon2id","t":3,"m":65536,"p":2,"salt":"<base64>","nonce":"<base64>","ct":"<base64>"}
```

The AES-256-GCM additional authenticated data is the ASCII string `pqtrust-sealed-key-v1|<alg>`, so a sealed ML-DSA-65 key cannot be silently reinterpreted as another algorithm.

- [ ] **Step 1: Write the failing tests**

`internal/keystore/seal_test.go`:

```go
package keystore

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"

	"github.com/fernando/pqtrust/internal/pqx509"
)

func TestSealUnsealRoundTrip(t *testing.T) {
	for _, alg := range []pqx509.Algorithm{pqx509.MLDSA44, pqx509.MLDSA65, pqx509.MLDSA87} {
		t.Run(alg.String(), func(t *testing.T) {
			_, priv, err := pqx509.GenerateKey(rand.Reader, alg)
			if err != nil {
				t.Fatal(err)
			}
			sealed, err := Seal(priv, []byte("correct horse battery staple"))
			if err != nil {
				t.Fatal(err)
			}
			// The seed must not appear anywhere in the sealed blob.
			if bytes.Contains(sealed, priv.Seed) {
				t.Fatal("sealed blob leaks the raw seed")
			}
			back, err := Unseal(sealed, []byte("correct horse battery staple"))
			if err != nil {
				t.Fatal(err)
			}
			if back.Algorithm != priv.Algorithm || !bytes.Equal(back.Seed, priv.Seed) {
				t.Error("unsealed key does not match the original")
			}
		})
	}
}

func TestUnsealWrongPassphrase(t *testing.T) {
	_, priv, _ := pqx509.GenerateKey(rand.Reader, pqx509.MLDSA44)
	sealed, err := Seal(priv, []byte("right"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Unseal(sealed, []byte("wrong")); !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("want ErrWrongPassphrase, got %v", err)
	}
}

func TestSealRejectsEmptyPassphrase(t *testing.T) {
	_, priv, _ := pqx509.GenerateKey(rand.Reader, pqx509.MLDSA44)
	if _, err := Seal(priv, nil); !errors.Is(err, ErrEmptyPassphrase) {
		t.Errorf("want ErrEmptyPassphrase, got %v", err)
	}
}

func TestSealUsesDistinctSaltAndNonce(t *testing.T) {
	_, priv, _ := pqx509.GenerateKey(rand.Reader, pqx509.MLDSA44)
	a, _ := Seal(priv, []byte("pw"))
	b, _ := Seal(priv, []byte("pw"))
	if bytes.Equal(a, b) {
		t.Fatal("sealing the same key twice must not produce identical output")
	}

	var ea, eb map[string]any
	if err := json.Unmarshal(a, &ea); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &eb); err != nil {
		t.Fatal(err)
	}
	if ea["salt"] == eb["salt"] {
		t.Error("salt must be random per seal")
	}
	if ea["nonce"] == eb["nonce"] {
		t.Error("nonce must be random per seal")
	}
	if ea["kdf"] != "argon2id" || ea["v"] != float64(1) {
		t.Errorf("unexpected envelope header: %v", ea)
	}
}

func TestUnsealDetectsTampering(t *testing.T) {
	_, priv, _ := pqx509.GenerateKey(rand.Reader, pqx509.MLDSA44)
	sealed, _ := Seal(priv, []byte("pw"))

	var env map[string]any
	if err := json.Unmarshal(sealed, &env); err != nil {
		t.Fatal(err)
	}
	// Claim a different algorithm: the AAD binding must make this fail.
	env["alg"] = "ML-DSA-87"
	tampered, _ := json.Marshal(env)
	if _, err := Unseal(tampered, []byte("pw")); err == nil {
		t.Error("tampering with the algorithm field must be detected")
	}
}

func TestUnsealRejectsGarbage(t *testing.T) {
	if _, err := Unseal([]byte("not json"), []byte("pw")); err == nil {
		t.Error("garbage input must be rejected")
	}
}
```

`internal/keystore/filebackend_test.go`:

```go
package keystore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/fernando/pqtrust/internal/pqx509"
)

func newTestBackend(t *testing.T) *FileBackend {
	t.Helper()
	b, err := NewFileBackend(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestFileBackendGenerateLoad(t *testing.T) {
	b := newTestBackend(t)
	pass := []byte("s3cret")

	keyID, pub, priv, err := b.Generate(pqx509.MLDSA65, pass)
	if err != nil {
		t.Fatal(err)
	}
	if len(keyID) != 32 {
		t.Errorf("key ID = %q, want 32 hex characters", keyID)
	}
	if priv.Algorithm != pqx509.MLDSA65 || len(priv.Seed) != 32 {
		t.Errorf("returned private key = %+v", priv.Algorithm)
	}

	ok, err := b.Has(keyID)
	if err != nil || !ok {
		t.Errorf("Has(%q) = %v, %v", keyID, ok, err)
	}

	signer, err := b.Load(keyID, pass)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(signer.Public().Bytes, pub.Bytes) {
		t.Error("loaded signer public key differs from the generated one")
	}
	if signer.Algorithm() != pqx509.MLDSA65 {
		t.Errorf("signer algorithm = %v", signer.Algorithm())
	}
	msg := []byte("sign me")
	sig, err := signer.Sign(nil, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := pqx509.Verify(pub, msg, sig); err != nil {
		t.Errorf("signature from a loaded key must verify: %v", err)
	}
}

func TestFileBackendWrongPassphrase(t *testing.T) {
	b := newTestBackend(t)
	keyID, _, _, err := b.Generate(pqx509.MLDSA44, []byte("right"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Load(keyID, []byte("wrong")); !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("want ErrWrongPassphrase, got %v", err)
	}
}

func TestFileBackendMissingKey(t *testing.T) {
	b := newTestBackend(t)
	if _, err := b.Load("0123456789abcdef0123456789abcdef", []byte("pw")); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("want ErrKeyNotFound, got %v", err)
	}
	ok, err := b.Has("0123456789abcdef0123456789abcdef")
	if err != nil || ok {
		t.Errorf("Has on a missing key = %v, %v", ok, err)
	}
}

func TestFileBackendStoreRejectsDuplicate(t *testing.T) {
	b := newTestBackend(t)
	_, _, priv, err := b.Generate(pqx509.MLDSA44, []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	id, err := NewKeyID()
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Store(id, priv, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	if err := b.Store(id, priv, []byte("pw")); !errors.Is(err, ErrKeyExists) {
		t.Errorf("want ErrKeyExists, got %v", err)
	}
}

func TestFileBackendDelete(t *testing.T) {
	b := newTestBackend(t)
	keyID, _, _, _ := b.Generate(pqx509.MLDSA44, []byte("pw"))
	if err := b.Delete(keyID); err != nil {
		t.Fatal(err)
	}
	if ok, _ := b.Has(keyID); ok {
		t.Error("key must be gone after Delete")
	}
	if err := b.Delete(keyID); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("deleting a missing key: want ErrKeyNotFound, got %v", err)
	}
}

func TestFileBackendFilePermissions(t *testing.T) {
	dir := t.TempDir()
	b, err := NewFileBackend(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	keyID, _, _, err := b.Generate(pqx509.MLDSA44, []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "keys", keyID+".key"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file mode = %#o, want 0600", perm)
	}
	dirInfo, err := os.Stat(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Errorf("key directory mode = %#o, want 0700", perm)
	}
}

func TestFileBackendRejectsUnsafeKeyID(t *testing.T) {
	b := newTestBackend(t)
	_, _, priv, _ := b.Generate(pqx509.MLDSA44, []byte("pw"))
	for _, id := range []string{"../escape", "with/slash", "", "UPPERCASE", "short"} {
		if err := b.Store(id, priv, []byte("pw")); err == nil {
			t.Errorf("Store(%q) must be rejected", id)
		}
	}
}
```

- [ ] **Step 2: Add dependencies and run to confirm failure**

```bash
go get golang.org/x/crypto@latest
CGO_ENABLED=0 go test ./internal/keystore/ -v
```

Expected: compile failure — undefined identifiers.

- [ ] **Step 3: Implement `seal.go`**

```go
// Package keystore generates post-quantum private keys and stores them sealed
// with AES-256-GCM under an Argon2id-derived key.
package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"

	"github.com/fernando/pqtrust/internal/pqx509"
)

var (
	// ErrWrongPassphrase reports that a sealed key could not be authenticated.
	ErrWrongPassphrase = errors.New("keystore: wrong passphrase or corrupted key material")
	// ErrKeyNotFound reports an unknown key ID.
	ErrKeyNotFound = errors.New("keystore: key not found")
	// ErrKeyExists reports an attempt to overwrite an existing key.
	ErrKeyExists = errors.New("keystore: key already exists")
	// ErrEmptyPassphrase reports a missing passphrase.
	ErrEmptyPassphrase = errors.New("keystore: passphrase must not be empty")
)

// Argon2id parameters. Changing these requires bumping envelopeVersion.
const (
	argonTime    uint32 = 3
	argonMemory  uint32 = 64 * 1024 // KiB
	argonThreads uint8  = 2
	argonKeyLen  uint32 = 32
	saltSize            = 16

	envelopeVersion = 1
)

type envelope struct {
	Version int    `json:"v"`
	Alg     string `json:"alg"`
	KDF     string `json:"kdf"`
	Time    uint32 `json:"t"`
	Memory  uint32 `json:"m"`
	Threads uint8  `json:"p"`
	Salt    []byte `json:"salt"`
	Nonce   []byte `json:"nonce"`
	Cipher  []byte `json:"ct"`
}

func aad(alg string) []byte {
	return []byte(fmt.Sprintf("pqtrust-sealed-key-v%d|%s", envelopeVersion, alg))
}

// Seal encrypts priv's seed under a key derived from passphrase.
func Seal(priv pqx509.PrivateKey, passphrase []byte) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, ErrEmptyPassphrase
	}
	if !priv.Algorithm.Valid() {
		return nil, fmt.Errorf("keystore: %w: %v", pqx509.ErrUnknownAlgorithm, priv.Algorithm)
	}
	if len(priv.Seed) != 32 {
		return nil, fmt.Errorf("keystore: %w: seed is %d bytes, want 32", pqx509.ErrInvalidKeySize, len(priv.Seed))
	}

	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("keystore: reading salt: %w", err)
	}
	key := argon2.IDKey(passphrase, salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	defer zero(key)

	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("keystore: reading nonce: %w", err)
	}
	algName := priv.Algorithm.String()
	ct := gcm.Seal(nil, nonce, priv.Seed, aad(algName))

	blob, err := json.Marshal(envelope{
		Version: envelopeVersion,
		Alg:     algName,
		KDF:     "argon2id",
		Time:    argonTime,
		Memory:  argonMemory,
		Threads: argonThreads,
		Salt:    salt,
		Nonce:   nonce,
		Cipher:  ct,
	})
	if err != nil {
		return nil, fmt.Errorf("keystore: marshaling envelope: %w", err)
	}
	return blob, nil
}

// Unseal decrypts a sealed key produced by Seal.
func Unseal(sealed, passphrase []byte) (pqx509.PrivateKey, error) {
	if len(passphrase) == 0 {
		return pqx509.PrivateKey{}, ErrEmptyPassphrase
	}
	var env envelope
	if err := json.Unmarshal(sealed, &env); err != nil {
		return pqx509.PrivateKey{}, fmt.Errorf("keystore: parsing sealed key: %w", err)
	}
	if env.Version != envelopeVersion {
		return pqx509.PrivateKey{}, fmt.Errorf("keystore: unsupported sealed key version %d", env.Version)
	}
	if env.KDF != "argon2id" {
		return pqx509.PrivateKey{}, fmt.Errorf("keystore: unsupported KDF %q", env.KDF)
	}
	alg, err := pqx509.ParseAlgorithm(env.Alg)
	if err != nil {
		return pqx509.PrivateKey{}, fmt.Errorf("keystore: %w", err)
	}
	if env.Threads == 0 || env.Time == 0 || env.Memory == 0 || len(env.Salt) == 0 || len(env.Nonce) == 0 {
		return pqx509.PrivateKey{}, fmt.Errorf("keystore: incomplete sealed key envelope")
	}

	key := argon2.IDKey(passphrase, env.Salt, env.Time, env.Memory, env.Threads, argonKeyLen)
	defer zero(key)

	gcm, err := newGCM(key)
	if err != nil {
		return pqx509.PrivateKey{}, err
	}
	if len(env.Nonce) != gcm.NonceSize() {
		return pqx509.PrivateKey{}, fmt.Errorf("keystore: nonce is %d bytes, want %d", len(env.Nonce), gcm.NonceSize())
	}
	seed, err := gcm.Open(nil, env.Nonce, env.Cipher, aad(env.Alg))
	if err != nil {
		return pqx509.PrivateKey{}, ErrWrongPassphrase
	}
	if len(seed) != 32 {
		zero(seed)
		return pqx509.PrivateKey{}, fmt.Errorf("keystore: %w: sealed seed is %d bytes", pqx509.ErrInvalidKeySize, len(seed))
	}
	return pqx509.PrivateKey{Algorithm: alg, Seed: seed}, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("keystore: creating AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("keystore: creating GCM: %w", err)
	}
	return gcm, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
```

- [ ] **Step 4: Implement `keystore.go`**

```go
package keystore

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"

	"github.com/fernando/pqtrust/internal/pqx509"
)

// Backend generates, stores and loads sealed private keys. A future HSM or
// PKCS#11 implementation satisfies the same interface, which is why Load
// returns a Signer rather than key material.
type Backend interface {
	Generate(alg pqx509.Algorithm, passphrase []byte) (keyID string, pub pqx509.PublicKey, priv pqx509.PrivateKey, err error)
	Load(keyID string, passphrase []byte) (pqx509.Signer, error)
	Store(keyID string, priv pqx509.PrivateKey, passphrase []byte) error
	Delete(keyID string) error
	Has(keyID string) (bool, error)
}

var keyIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// NewKeyID returns a random 32-character lowercase hex key identifier.
func NewKeyID() (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("keystore: generating key ID: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func validateKeyID(keyID string) error {
	if !keyIDPattern.MatchString(keyID) {
		return fmt.Errorf("keystore: invalid key ID %q (want 32 lowercase hex characters)", keyID)
	}
	return nil
}
```

- [ ] **Step 5: Implement `filebackend.go`**

```go
package keystore

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/fernando/pqtrust/internal/pqx509"
)

// FileBackend stores sealed keys as 0600 files in a 0700 directory.
type FileBackend struct {
	dir string
}

// NewFileBackend creates dir if needed and returns a filesystem-backed keystore.
func NewFileBackend(dir string) (*FileBackend, error) {
	if dir == "" {
		return nil, fmt.Errorf("keystore: key directory must not be empty")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("keystore: creating key directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("keystore: tightening key directory permissions: %w", err)
	}
	return &FileBackend{dir: dir}, nil
}

func (b *FileBackend) path(keyID string) string {
	return filepath.Join(b.dir, keyID+".key")
}

// Generate creates a key pair, seals the private key and returns both halves.
// The caller is responsible for discarding priv once it is no longer needed.
func (b *FileBackend) Generate(alg pqx509.Algorithm, passphrase []byte) (string, pqx509.PublicKey, pqx509.PrivateKey, error) {
	pub, priv, err := pqx509.GenerateKey(rand.Reader, alg)
	if err != nil {
		return "", pqx509.PublicKey{}, pqx509.PrivateKey{}, err
	}
	keyID, err := NewKeyID()
	if err != nil {
		return "", pqx509.PublicKey{}, pqx509.PrivateKey{}, err
	}
	if err := b.Store(keyID, priv, passphrase); err != nil {
		return "", pqx509.PublicKey{}, pqx509.PrivateKey{}, err
	}
	return keyID, pub, priv, nil
}

// Store seals priv and writes it under keyID. It never overwrites.
func (b *FileBackend) Store(keyID string, priv pqx509.PrivateKey, passphrase []byte) error {
	if err := validateKeyID(keyID); err != nil {
		return err
	}
	sealed, err := Seal(priv, passphrase)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(b.path(keyID), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%w: %s", ErrKeyExists, keyID)
		}
		return fmt.Errorf("keystore: creating key file: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(sealed); err != nil {
		return fmt.Errorf("keystore: writing key file: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("keystore: syncing key file: %w", err)
	}
	return nil
}

// Load unseals the key and returns a Signer. Key material is discarded as soon
// as the signer has been derived.
func (b *FileBackend) Load(keyID string, passphrase []byte) (pqx509.Signer, error) {
	if err := validateKeyID(keyID); err != nil {
		return nil, err
	}
	sealed, err := os.ReadFile(b.path(keyID))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, keyID)
		}
		return nil, fmt.Errorf("keystore: reading key file: %w", err)
	}
	priv, err := Unseal(sealed, passphrase)
	if err != nil {
		return nil, err
	}
	defer zero(priv.Seed)
	return priv.Signer()
}

// Delete removes a sealed key.
func (b *FileBackend) Delete(keyID string) error {
	if err := validateKeyID(keyID); err != nil {
		return err
	}
	if err := os.Remove(b.path(keyID)); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%w: %s", ErrKeyNotFound, keyID)
		}
		return fmt.Errorf("keystore: deleting key file: %w", err)
	}
	return nil
}

// Has reports whether a sealed key exists.
func (b *FileBackend) Has(keyID string) (bool, error) {
	if err := validateKeyID(keyID); err != nil {
		return false, err
	}
	_, err := os.Stat(b.path(keyID))
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	default:
		return false, fmt.Errorf("keystore: stat key file: %w", err)
	}
}

var _ Backend = (*FileBackend)(nil)
```

- [ ] **Step 6: Run the tests and confirm they pass**

Run: `CGO_ENABLED=0 go test ./internal/keystore/ -v`
Expected: PASS. Argon2id at 64 MiB makes each seal/unseal take tens of milliseconds; the suite should still finish in a few seconds.

- [ ] **Step 7: Commit**

```bash
git add internal/keystore go.mod go.sum
git commit -m "feat(keystore): Argon2id + AES-256-GCM sealed key storage behind a Backend interface"
```

---

### Task 9: store — SQLite persistence

**Files:**
- Create: `internal/store/store.go`, `internal/store/migrate.go`, `internal/store/migrations/0001_init.sql`, `internal/store/cas.go`, `internal/store/certificates.go`, `internal/store/tokens.go`
- Test: `internal/store/store_test.go`

**Interfaces:**
- Consumes: nothing from other internal packages (keep `store` free of `pqx509` types so the schema stays independent).
- Produces:
  - `func Open(path string) (*Store, error)`, `func (s *Store) Close() error`
  - ```go
    type CA struct {
        ID        string
        Name      string
        ParentID  string // empty for a root
        Algorithm string
        CertPEM   string
        KeyID     string
        Status    string // "active" | "revoked"
        CreatedAt time.Time
    }
    type Certificate struct {
        Serial           string // lowercase hex, no 0x
        CAID             string
        SubjectDN        string
        SANs             string // comma-separated, as issued
        Algorithm        string
        CertPEM          string
        KeyID            string // empty when the key was not stored
        Status           string // "valid" | "revoked"
        NotBefore        time.Time
        NotAfter         time.Time
        RevokedAt        *time.Time
        RevocationReason *int
    }
    type Token struct {
        ID        string
        Name      string
        TokenHash string // hex SHA-256
        CreatedAt time.Time
    }
    ```
  - `func (s *Store) CreateCA(ctx context.Context, ca CA) error`
  - `func (s *Store) GetCA(ctx context.Context, id string) (CA, error)`
  - `func (s *Store) ListCAs(ctx context.Context) ([]CA, error)`
  - `func (s *Store) InsertCertificate(ctx context.Context, c Certificate) error`
  - `func (s *Store) GetCertificate(ctx context.Context, serial string) (Certificate, error)`
  - `func (s *Store) ListCertificatesByCA(ctx context.Context, caID string) ([]Certificate, error)`
  - `func (s *Store) RevokeCertificate(ctx context.Context, serial string, at time.Time, reason int) error`
  - `func (s *Store) ListRevoked(ctx context.Context, caID string) ([]Certificate, error)`
  - `func (s *Store) CreateToken(ctx context.Context, t Token) error`
  - `func (s *Store) TokenByHash(ctx context.Context, hash string) (Token, error)`
  - Sentinels: `ErrNotFound`, `ErrConflict` (already exists / already revoked)

- [ ] **Step 1: Write the failing tests**

`internal/store/store_test.go`:

```go
package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return s
}

func TestOpenAppliesMigrationsIdempotently(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopening an existing database must succeed: %v", err)
	}
	if err := s2.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCALifecycle(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	root := CA{ID: "ca-root", Name: "Root", Algorithm: "ML-DSA-87", CertPEM: "PEM-ROOT", KeyID: "k1", Status: "active", CreatedAt: now}
	if err := s.CreateCA(ctx, root); err != nil {
		t.Fatal(err)
	}
	inter := CA{ID: "ca-int", Name: "Intermediate", ParentID: "ca-root", Algorithm: "ML-DSA-65", CertPEM: "PEM-INT", KeyID: "k2", Status: "active", CreatedAt: now}
	if err := s.CreateCA(ctx, inter); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetCA(ctx, "ca-int")
	if err != nil {
		t.Fatal(err)
	}
	if got.ParentID != "ca-root" || got.Algorithm != "ML-DSA-65" || got.CertPEM != "PEM-INT" {
		t.Errorf("GetCA = %+v", got)
	}
	if !got.CreatedAt.Equal(now) {
		t.Errorf("CreatedAt = %v, want %v", got.CreatedAt, now)
	}

	list, err := s.ListCAs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Errorf("ListCAs returned %d CAs, want 2", len(list))
	}
}

func TestCreateCADuplicateAndMissingParent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	ca := CA{ID: "dup", Name: "A", Algorithm: "ML-DSA-87", CertPEM: "P", KeyID: "k", Status: "active", CreatedAt: now}
	if err := s.CreateCA(ctx, ca); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateCA(ctx, ca); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate CA: want ErrConflict, got %v", err)
	}
	orphan := CA{ID: "orphan", Name: "B", ParentID: "nope", Algorithm: "ML-DSA-65", CertPEM: "P", KeyID: "k", Status: "active", CreatedAt: now}
	if err := s.CreateCA(ctx, orphan); err == nil {
		t.Error("a CA with an unknown parent must be rejected by the foreign key")
	}
}

func TestGetCANotFound(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.GetCA(context.Background(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}
}

func TestCertificateLifecycle(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	if err := s.CreateCA(ctx, CA{ID: "ca1", Name: "CA", Algorithm: "ML-DSA-65", CertPEM: "P", KeyID: "k", Status: "active", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	cert := Certificate{
		Serial:    "0a1b2c",
		CAID:      "ca1",
		SubjectDN: "CN=api.example.com",
		SANs:      "api.example.com,192.0.2.10",
		Algorithm: "ML-DSA-44",
		CertPEM:   "PEM-LEAF",
		Status:    "valid",
		NotBefore: now,
		NotAfter:  now.Add(397 * 24 * time.Hour),
	}
	if err := s.InsertCertificate(ctx, cert); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertCertificate(ctx, cert); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate serial: want ErrConflict, got %v", err)
	}

	got, err := s.GetCertificate(ctx, "0a1b2c")
	if err != nil {
		t.Fatal(err)
	}
	if got.SubjectDN != cert.SubjectDN || got.SANs != cert.SANs || got.Status != "valid" {
		t.Errorf("GetCertificate = %+v", got)
	}
	if got.RevokedAt != nil || got.RevocationReason != nil {
		t.Error("a fresh certificate must have no revocation fields")
	}
	if !got.NotAfter.Equal(cert.NotAfter) {
		t.Errorf("NotAfter = %v, want %v", got.NotAfter, cert.NotAfter)
	}

	list, err := s.ListCertificatesByCA(ctx, "ca1")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("ListCertificatesByCA returned %d, want 1", len(list))
	}
}

func TestRevokeCertificate(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	if err := s.CreateCA(ctx, CA{ID: "ca1", Name: "CA", Algorithm: "ML-DSA-65", CertPEM: "P", KeyID: "k", Status: "active", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertCertificate(ctx, Certificate{
		Serial: "ff", CAID: "ca1", SubjectDN: "CN=x", Algorithm: "ML-DSA-44", CertPEM: "P",
		Status: "valid", NotBefore: now, NotAfter: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	if err := s.RevokeCertificate(ctx, "ff", now, 1); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetCertificate(ctx, "ff")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "revoked" {
		t.Errorf("status = %q, want revoked", got.Status)
	}
	if got.RevokedAt == nil || !got.RevokedAt.Equal(now) {
		t.Errorf("RevokedAt = %v, want %v", got.RevokedAt, now)
	}
	if got.RevocationReason == nil || *got.RevocationReason != 1 {
		t.Errorf("RevocationReason = %v, want 1", got.RevocationReason)
	}

	// Revoking twice is a conflict, not a silent success.
	if err := s.RevokeCertificate(ctx, "ff", now, 1); !errors.Is(err, ErrConflict) {
		t.Errorf("second revoke: want ErrConflict, got %v", err)
	}
	if err := s.RevokeCertificate(ctx, "nope", now, 1); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoking a missing serial: want ErrNotFound, got %v", err)
	}

	revoked, err := s.ListRevoked(ctx, "ca1")
	if err != nil {
		t.Fatal(err)
	}
	if len(revoked) != 1 || revoked[0].Serial != "ff" {
		t.Errorf("ListRevoked = %+v", revoked)
	}
}

func TestTokens(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	tok := Token{ID: "t1", Name: "ci", TokenHash: "abc123", CreatedAt: now}
	if err := s.CreateToken(ctx, tok); err != nil {
		t.Fatal(err)
	}
	got, err := s.TokenByHash(ctx, "abc123")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "t1" || got.Name != "ci" {
		t.Errorf("TokenByHash = %+v", got)
	}
	if _, err := s.TokenByHash(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}
	if err := s.CreateToken(ctx, tok); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate token: want ErrConflict, got %v", err)
	}
}

func TestListCertificatesByCAIsScoped(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	for _, id := range []string{"ca1", "ca2"} {
		if err := s.CreateCA(ctx, CA{ID: id, Name: id, Algorithm: "ML-DSA-65", CertPEM: "P", KeyID: "k-" + id, Status: "active", CreatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.InsertCertificate(ctx, Certificate{Serial: "01", CAID: "ca1", SubjectDN: "CN=a", Algorithm: "ML-DSA-44", CertPEM: "P", Status: "valid", NotBefore: now, NotAfter: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertCertificate(ctx, Certificate{Serial: "02", CAID: "ca2", SubjectDN: "CN=b", Algorithm: "ML-DSA-44", CertPEM: "P", Status: "valid", NotBefore: now, NotAfter: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListCertificatesByCA(ctx, "ca1")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Serial != "01" {
		t.Errorf("ListCertificatesByCA(ca1) = %+v", list)
	}
}
```

- [ ] **Step 2: Add the driver and run to confirm failure**

```bash
go get modernc.org/sqlite@latest
CGO_ENABLED=0 go test ./internal/store/ -v
```

Expected: compile failure.

- [ ] **Step 3: Write the migration**

`internal/store/migrations/0001_init.sql`:

```sql
CREATE TABLE cas (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    parent_id  TEXT NULL REFERENCES cas(id),
    algorithm  TEXT NOT NULL,
    cert_pem   TEXT NOT NULL,
    key_id     TEXT NOT NULL,
    status     TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL
);

CREATE TABLE certificates (
    serial            TEXT PRIMARY KEY,
    ca_id             TEXT NOT NULL REFERENCES cas(id),
    subject_dn        TEXT NOT NULL,
    sans              TEXT NOT NULL DEFAULT '',
    algorithm         TEXT NOT NULL,
    cert_pem          TEXT NOT NULL,
    key_id            TEXT NULL,
    status            TEXT NOT NULL,
    not_before        TIMESTAMP NOT NULL,
    not_after         TIMESTAMP NOT NULL,
    revoked_at        TIMESTAMP NULL,
    revocation_reason INTEGER NULL
);

CREATE INDEX certificates_ca_id_idx ON certificates(ca_id);
CREATE INDEX certificates_status_idx ON certificates(ca_id, status);

CREATE TABLE tokens (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMP NOT NULL
);
```

- [ ] **Step 4: Implement `store.go` and `migrate.go`**

`internal/store/store.go`:

```go
// Package store persists pqtrust state in SQLite. It holds no domain logic and
// no pqx509 types, so a future multi-tenant schema can be introduced here alone.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var (
	// ErrNotFound reports a missing row.
	ErrNotFound = errors.New("store: not found")
	// ErrConflict reports a uniqueness or state conflict.
	ErrConflict = errors.New("store: conflict")
)

// Store is a SQLite-backed pqtrust datastore.
type Store struct {
	db *sql.DB
}

// CA is a certificate authority record.
type CA struct {
	ID        string
	Name      string
	ParentID  string
	Algorithm string
	CertPEM   string
	KeyID     string
	Status    string
	CreatedAt time.Time
}

// Certificate is an issued end-entity certificate record.
type Certificate struct {
	Serial           string
	CAID             string
	SubjectDN        string
	SANs             string
	Algorithm        string
	CertPEM          string
	KeyID            string
	Status           string
	NotBefore        time.Time
	NotAfter         time.Time
	RevokedAt        *time.Time
	RevocationReason *int
}

// Token is an API bearer token record; only its SHA-256 hash is stored.
type Token struct {
	ID        string
	Name      string
	TokenHash string
	CreatedAt time.Time
}

// Certificate and CA status values.
const (
	StatusValid   = "valid"
	StatusRevoked = "revoked"
	StatusActive  = "active"
)

// Open opens (creating if needed) the SQLite database at path and applies migrations.
func Open(path string) (*Store, error) {
	if path == "" {
		return nil, fmt.Errorf("store: database path must not be empty")
	}
	dsn := path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: opening database: %w", err)
	}
	// modernc.org/sqlite serializes writes; a single connection avoids
	// "database is locked" surprises and keeps transactions predictable.
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: pinging database: %w", err)
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the database handle.
func (s *Store) Close() error {
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("store: closing database: %w", err)
	}
	return nil
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") ||
		strings.Contains(msg, "PRIMARY KEY must be unique")
}
```

`internal/store/migrate.go`:

```go
package store

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// migrate applies every embedded migration that has not been applied yet.
func (s *Store) migrate() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		name TEXT PRIMARY KEY,
		applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		return fmt.Errorf("store: creating migration table: %w", err)
	}

	entries, err := fs.Glob(migrationFS, "migrations/*.sql")
	if err != nil {
		return fmt.Errorf("store: listing migrations: %w", err)
	}
	sort.Strings(entries)

	for _, name := range entries {
		var count int
		if err := s.db.QueryRow(`SELECT COUNT(1) FROM schema_migrations WHERE name = ?`, name).Scan(&count); err != nil {
			return fmt.Errorf("store: checking migration %s: %w", name, err)
		}
		if count > 0 {
			continue
		}
		sqlBytes, err := migrationFS.ReadFile(name)
		if err != nil {
			return fmt.Errorf("store: reading migration %s: %w", name, err)
		}
		tx, err := s.db.Begin()
		if err != nil {
			return fmt.Errorf("store: beginning migration %s: %w", name, err)
		}
		if _, err := tx.Exec(string(sqlBytes)); err != nil {
			tx.Rollback()
			return fmt.Errorf("store: applying migration %s: %w", name, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations(name) VALUES (?)`, name); err != nil {
			tx.Rollback()
			return fmt.Errorf("store: recording migration %s: %w", name, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("store: committing migration %s: %w", name, err)
		}
	}
	return nil
}
```

- [ ] **Step 5: Implement `cas.go`**

```go
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// CreateCA inserts a CA record.
func (s *Store) CreateCA(ctx context.Context, ca CA) error {
	var parent any
	if ca.ParentID != "" {
		parent = ca.ParentID
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO cas (id, name, parent_id, algorithm, cert_pem, key_id, status, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		ca.ID, ca.Name, parent, ca.Algorithm, ca.CertPEM, ca.KeyID, ca.Status, ca.CreatedAt.UTC())
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: CA %q already exists", ErrConflict, ca.ID)
		}
		return fmt.Errorf("store: inserting CA: %w", err)
	}
	return nil
}

func scanCA(row interface{ Scan(...any) error }) (CA, error) {
	var ca CA
	var parent sql.NullString
	var createdAt time.Time
	if err := row.Scan(&ca.ID, &ca.Name, &parent, &ca.Algorithm, &ca.CertPEM, &ca.KeyID, &ca.Status, &createdAt); err != nil {
		return CA{}, err
	}
	ca.ParentID = parent.String
	ca.CreatedAt = createdAt.UTC()
	return ca, nil
}

const caColumns = `id, name, parent_id, algorithm, cert_pem, key_id, status, created_at`

// GetCA fetches one CA by ID.
func (s *Store) GetCA(ctx context.Context, id string) (CA, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+caColumns+` FROM cas WHERE id = ?`, id)
	ca, err := scanCA(row)
	if errors.Is(err, sql.ErrNoRows) {
		return CA{}, fmt.Errorf("%w: CA %q", ErrNotFound, id)
	}
	if err != nil {
		return CA{}, fmt.Errorf("store: querying CA: %w", err)
	}
	return ca, nil
}

// ListCAs returns all CAs, oldest first.
func (s *Store) ListCAs(ctx context.Context) ([]CA, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+caColumns+` FROM cas ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("store: listing CAs: %w", err)
	}
	defer rows.Close()
	var out []CA
	for rows.Next() {
		ca, err := scanCA(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scanning CA: %w", err)
		}
		out = append(out, ca)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterating CAs: %w", err)
	}
	return out, nil
}
```

- [ ] **Step 6: Implement `certificates.go`**

```go
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

const certColumns = `serial, ca_id, subject_dn, sans, algorithm, cert_pem, key_id, status,
	not_before, not_after, revoked_at, revocation_reason`

// InsertCertificate stores a newly issued certificate.
func (s *Store) InsertCertificate(ctx context.Context, c Certificate) error {
	var keyID any
	if c.KeyID != "" {
		keyID = c.KeyID
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO certificates (serial, ca_id, subject_dn, sans, algorithm, cert_pem, key_id, status, not_before, not_after)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.Serial, c.CAID, c.SubjectDN, c.SANs, c.Algorithm, c.CertPEM, keyID, c.Status, c.NotBefore.UTC(), c.NotAfter.UTC())
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: certificate %q already exists", ErrConflict, c.Serial)
		}
		return fmt.Errorf("store: inserting certificate: %w", err)
	}
	return nil
}

func scanCertificate(row interface{ Scan(...any) error }) (Certificate, error) {
	var c Certificate
	var keyID sql.NullString
	var revokedAt sql.NullTime
	var reason sql.NullInt64
	var notBefore, notAfter time.Time
	if err := row.Scan(&c.Serial, &c.CAID, &c.SubjectDN, &c.SANs, &c.Algorithm, &c.CertPEM,
		&keyID, &c.Status, &notBefore, &notAfter, &revokedAt, &reason); err != nil {
		return Certificate{}, err
	}
	c.KeyID = keyID.String
	c.NotBefore, c.NotAfter = notBefore.UTC(), notAfter.UTC()
	if revokedAt.Valid {
		t := revokedAt.Time.UTC()
		c.RevokedAt = &t
	}
	if reason.Valid {
		r := int(reason.Int64)
		c.RevocationReason = &r
	}
	return c, nil
}

// GetCertificate fetches one certificate by serial.
func (s *Store) GetCertificate(ctx context.Context, serial string) (Certificate, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+certColumns+` FROM certificates WHERE serial = ?`, serial)
	c, err := scanCertificate(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Certificate{}, fmt.Errorf("%w: certificate %q", ErrNotFound, serial)
	}
	if err != nil {
		return Certificate{}, fmt.Errorf("store: querying certificate: %w", err)
	}
	return c, nil
}

func (s *Store) listCertificates(ctx context.Context, query string, args ...any) ([]Certificate, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: listing certificates: %w", err)
	}
	defer rows.Close()
	var out []Certificate
	for rows.Next() {
		c, err := scanCertificate(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scanning certificate: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterating certificates: %w", err)
	}
	return out, nil
}

// ListCertificatesByCA returns every certificate issued by caID.
func (s *Store) ListCertificatesByCA(ctx context.Context, caID string) ([]Certificate, error) {
	return s.listCertificates(ctx,
		`SELECT `+certColumns+` FROM certificates WHERE ca_id = ? ORDER BY not_before, serial`, caID)
}

// ListRevoked returns every revoked certificate issued by caID.
func (s *Store) ListRevoked(ctx context.Context, caID string) ([]Certificate, error) {
	return s.listCertificates(ctx,
		`SELECT `+certColumns+` FROM certificates WHERE ca_id = ? AND status = ? ORDER BY revoked_at, serial`,
		caID, StatusRevoked)
}

// RevokeCertificate marks a certificate revoked in a single transaction.
// Revoking an already-revoked certificate is a conflict.
func (s *Store) RevokeCertificate(ctx context.Context, serial string, at time.Time, reason int) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: beginning revocation: %w", err)
	}
	defer tx.Rollback()

	var status string
	err = tx.QueryRowContext(ctx, `SELECT status FROM certificates WHERE serial = ?`, serial).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: certificate %q", ErrNotFound, serial)
	}
	if err != nil {
		return fmt.Errorf("store: reading certificate status: %w", err)
	}
	if status == StatusRevoked {
		return fmt.Errorf("%w: certificate %q is already revoked", ErrConflict, serial)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE certificates SET status = ?, revoked_at = ?, revocation_reason = ? WHERE serial = ?`,
		StatusRevoked, at.UTC(), reason, serial); err != nil {
		return fmt.Errorf("store: updating certificate: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: committing revocation: %w", err)
	}
	return nil
}
```

- [ ] **Step 7: Implement `tokens.go`**

```go
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// CreateToken stores an API token's hash.
func (s *Store) CreateToken(ctx context.Context, t Token) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO tokens (id, name, token_hash, created_at) VALUES (?, ?, ?, ?)`,
		t.ID, t.Name, t.TokenHash, t.CreatedAt.UTC())
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: token already exists", ErrConflict)
		}
		return fmt.Errorf("store: inserting token: %w", err)
	}
	return nil
}

// TokenByHash looks a token up by its hex SHA-256 hash.
func (s *Store) TokenByHash(ctx context.Context, hash string) (Token, error) {
	var t Token
	var createdAt time.Time
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, token_hash, created_at FROM tokens WHERE token_hash = ?`, hash).
		Scan(&t.ID, &t.Name, &t.TokenHash, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Token{}, fmt.Errorf("%w: token", ErrNotFound)
	}
	if err != nil {
		return Token{}, fmt.Errorf("store: querying token: %w", err)
	}
	t.CreatedAt = createdAt.UTC()
	return t, nil
}
```

- [ ] **Step 8: Run the tests and confirm they pass**

Run: `CGO_ENABLED=0 go test ./internal/store/ -v`
Expected: PASS.

Likely snag: `modernc.org/sqlite` returns `TIMESTAMP` columns as `time.Time` only when the driver recognizes the declared type. If a scan fails with `converting driver.Value type string`, store times as `INTEGER` Unix seconds instead: change the migration columns to `INTEGER NOT NULL`, write `t.UTC().Unix()`, and scan into `int64` before converting with `time.Unix(v, 0).UTC()`. Adjust every time column consistently and keep the tests unchanged.

- [ ] **Step 9: Commit**

```bash
git add internal/store go.mod go.sum
git commit -m "feat(store): SQLite persistence with embedded migrations for CAs, certificates and tokens"
```

---

### Task 10: config — YAML plus environment

**Files:**
- Create: `internal/config/config.go`
- Test: `internal/config/config_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - ```go
    type Config struct {
        Server struct {
            Listen   string `yaml:"listen"`
            TLS struct {
                CertFile       string `yaml:"cert_file"`
                KeyFile        string `yaml:"key_file"`
                AutoSelfSigned bool   `yaml:"auto_self_signed"`
                Hostname       string `yaml:"hostname"`
            } `yaml:"tls"`
        } `yaml:"server"`
        Database struct{ Path string `yaml:"path"` } `yaml:"database"`
        Keystore struct{ Dir string `yaml:"dir"` } `yaml:"keystore"`
        Issuance struct {
            MaxValidityDays int    `yaml:"max_validity_days"`
            CRLValidityHours int   `yaml:"crl_validity_hours"`
        } `yaml:"issuance"`
    }
    ```
  - `func Default() Config`
  - `func Load(path string) (Config, error)` — empty path means defaults only; missing file at an explicitly given path is an error
  - `func (c *Config) applyEnv() error` and `func (c Config) Validate() error`
  - Environment overrides: `PQTRUST_LISTEN`, `PQTRUST_TLS_CERT_FILE`, `PQTRUST_TLS_KEY_FILE`, `PQTRUST_TLS_AUTO_SELF_SIGNED` (`true`/`false`), `PQTRUST_TLS_HOSTNAME`, `PQTRUST_DB_PATH`, `PQTRUST_KEYSTORE_DIR`, `PQTRUST_MAX_VALIDITY_DAYS`, `PQTRUST_CRL_VALIDITY_HOURS`
  - Defaults: listen `:8443`, db `/var/lib/pqtrust/pqtrust.db`, keystore dir `/var/lib/pqtrust/keys`, auto self-signed `true`, hostname `localhost`, max validity 397 days, CRL validity 168 hours.

- [ ] **Step 1: Write the failing tests**

`internal/config/config_test.go`:

```go
package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaults(t *testing.T) {
	c := Default()
	if c.Server.Listen != ":8443" {
		t.Errorf("listen = %q", c.Server.Listen)
	}
	if !c.Server.TLS.AutoSelfSigned {
		t.Error("auto_self_signed must default to true")
	}
	if c.Issuance.MaxValidityDays != 397 {
		t.Errorf("max validity = %d, want 397", c.Issuance.MaxValidityDays)
	}
	if c.Issuance.CRLValidityHours != 168 {
		t.Errorf("CRL validity = %d, want 168", c.Issuance.CRLValidityHours)
	}
	if err := c.Validate(); err != nil {
		t.Errorf("defaults must validate: %v", err)
	}
}

func TestLoadYAMLOverridesDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := `
server:
  listen: "127.0.0.1:9443"
  tls:
    auto_self_signed: false
    cert_file: /tmp/cert.pem
    key_file: /tmp/key.pem
database:
  path: /tmp/pqtrust.db
keystore:
  dir: /tmp/keys
issuance:
  max_validity_days: 90
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.Listen != "127.0.0.1:9443" {
		t.Errorf("listen = %q", c.Server.Listen)
	}
	if c.Server.TLS.AutoSelfSigned {
		t.Error("auto_self_signed must be false")
	}
	if c.Database.Path != "/tmp/pqtrust.db" || c.Keystore.Dir != "/tmp/keys" {
		t.Errorf("paths = %q / %q", c.Database.Path, c.Keystore.Dir)
	}
	if c.Issuance.MaxValidityDays != 90 {
		t.Errorf("max validity = %d", c.Issuance.MaxValidityDays)
	}
	// Unset keys keep their defaults.
	if c.Issuance.CRLValidityHours != 168 {
		t.Errorf("CRL validity = %d, want the default 168", c.Issuance.CRLValidityHours)
	}
}

func TestEnvOverridesYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("server:\n  listen: \":1111\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PQTRUST_LISTEN", ":2222")
	t.Setenv("PQTRUST_DB_PATH", "/env/db.sqlite")
	t.Setenv("PQTRUST_MAX_VALIDITY_DAYS", "30")
	t.Setenv("PQTRUST_TLS_AUTO_SELF_SIGNED", "false")

	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.Listen != ":2222" {
		t.Errorf("listen = %q, want :2222", c.Server.Listen)
	}
	if c.Database.Path != "/env/db.sqlite" {
		t.Errorf("db path = %q", c.Database.Path)
	}
	if c.Issuance.MaxValidityDays != 30 {
		t.Errorf("max validity = %d", c.Issuance.MaxValidityDays)
	}
	if c.Server.TLS.AutoSelfSigned {
		t.Error("auto_self_signed must be false from the environment")
	}
}

func TestLoadMissingFileIsAnError(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Error("an explicitly requested missing config file must be an error")
	}
}

func TestLoadEmptyPathUsesDefaults(t *testing.T) {
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.Listen != ":8443" {
		t.Errorf("listen = %q", c.Server.Listen)
	}
}

func TestValidate(t *testing.T) {
	t.Run("bad max validity", func(t *testing.T) {
		c := Default()
		c.Issuance.MaxValidityDays = 0
		if err := c.Validate(); err == nil {
			t.Error("max_validity_days must be positive")
		}
	})
	t.Run("tls files required when not self-signing", func(t *testing.T) {
		c := Default()
		c.Server.TLS.AutoSelfSigned = false
		if err := c.Validate(); err == nil {
			t.Error("cert_file and key_file are required when auto_self_signed is false")
		}
	})
	t.Run("empty listen", func(t *testing.T) {
		c := Default()
		c.Server.Listen = ""
		if err := c.Validate(); err == nil {
			t.Error("listen must not be empty")
		}
	})
	t.Run("bad env integer", func(t *testing.T) {
		t.Setenv("PQTRUST_MAX_VALIDITY_DAYS", "not-a-number")
		if _, err := Load(""); err == nil {
			t.Error("a non-numeric integer override must be an error")
		}
	})
}

func TestLoadRejectsUnknownYAMLKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("server:\n  lissten: \":1\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("a typo'd config key must be rejected, not silently ignored")
	}
}
```

- [ ] **Step 2: Add the YAML dependency and run to confirm failure**

```bash
go get gopkg.in/yaml.v3@latest
CGO_ENABLED=0 go test ./internal/config/ -v
```

Expected: compile failure.

- [ ] **Step 3: Implement `config.go`**

```go
// Package config loads pqtrust configuration from YAML with environment overrides.
package config

import (
	"bytes"
	"fmt"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

// TLSConfig configures the API server's transport certificate.
type TLSConfig struct {
	CertFile       string `yaml:"cert_file"`
	KeyFile        string `yaml:"key_file"`
	AutoSelfSigned bool   `yaml:"auto_self_signed"`
	Hostname       string `yaml:"hostname"`
}

// ServerConfig configures the HTTP listener.
type ServerConfig struct {
	Listen string    `yaml:"listen"`
	TLS    TLSConfig `yaml:"tls"`
}

// DatabaseConfig configures SQLite storage.
type DatabaseConfig struct {
	Path string `yaml:"path"`
}

// KeystoreConfig configures sealed key storage.
type KeystoreConfig struct {
	Dir string `yaml:"dir"`
}

// IssuanceConfig configures issuance and CRL policy.
type IssuanceConfig struct {
	MaxValidityDays  int `yaml:"max_validity_days"`
	CRLValidityHours int `yaml:"crl_validity_hours"`
}

// Config is the complete pqtrust configuration.
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Database DatabaseConfig `yaml:"database"`
	Keystore KeystoreConfig `yaml:"keystore"`
	Issuance IssuanceConfig `yaml:"issuance"`
}

// Default returns the built-in configuration.
func Default() Config {
	var c Config
	c.Server.Listen = ":8443"
	c.Server.TLS.AutoSelfSigned = true
	c.Server.TLS.Hostname = "localhost"
	c.Database.Path = "/var/lib/pqtrust/pqtrust.db"
	c.Keystore.Dir = "/var/lib/pqtrust/keys"
	c.Issuance.MaxValidityDays = 397
	c.Issuance.CRLValidityHours = 168
	return c
}

// Load reads path (when non-empty) over the defaults, applies environment
// overrides and validates the result.
func Load(path string) (Config, error) {
	c := Default()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return Config{}, fmt.Errorf("config: reading %s: %w", path, err)
		}
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		if err := dec.Decode(&c); err != nil {
			return Config{}, fmt.Errorf("config: parsing %s: %w", path, err)
		}
	}
	if err := c.applyEnv(); err != nil {
		return Config{}, err
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

func (c *Config) applyEnv() error {
	str := func(env string, dst *string) {
		if v, ok := os.LookupEnv(env); ok {
			*dst = v
		}
	}
	str("PQTRUST_LISTEN", &c.Server.Listen)
	str("PQTRUST_TLS_CERT_FILE", &c.Server.TLS.CertFile)
	str("PQTRUST_TLS_KEY_FILE", &c.Server.TLS.KeyFile)
	str("PQTRUST_TLS_HOSTNAME", &c.Server.TLS.Hostname)
	str("PQTRUST_DB_PATH", &c.Database.Path)
	str("PQTRUST_KEYSTORE_DIR", &c.Keystore.Dir)

	if v, ok := os.LookupEnv("PQTRUST_TLS_AUTO_SELF_SIGNED"); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("config: PQTRUST_TLS_AUTO_SELF_SIGNED=%q is not a boolean: %w", v, err)
		}
		c.Server.TLS.AutoSelfSigned = b
	}
	for _, e := range []struct {
		env string
		dst *int
	}{
		{"PQTRUST_MAX_VALIDITY_DAYS", &c.Issuance.MaxValidityDays},
		{"PQTRUST_CRL_VALIDITY_HOURS", &c.Issuance.CRLValidityHours},
	} {
		if v, ok := os.LookupEnv(e.env); ok {
			n, err := strconv.Atoi(v)
			if err != nil {
				return fmt.Errorf("config: %s=%q is not an integer: %w", e.env, v, err)
			}
			*e.dst = n
		}
	}
	return nil
}

// Validate reports configuration that cannot produce a working server.
func (c Config) Validate() error {
	if c.Server.Listen == "" {
		return fmt.Errorf("config: server.listen must not be empty")
	}
	if !c.Server.TLS.AutoSelfSigned && (c.Server.TLS.CertFile == "" || c.Server.TLS.KeyFile == "") {
		return fmt.Errorf("config: server.tls.cert_file and key_file are required when auto_self_signed is false")
	}
	if c.Database.Path == "" {
		return fmt.Errorf("config: database.path must not be empty")
	}
	if c.Keystore.Dir == "" {
		return fmt.Errorf("config: keystore.dir must not be empty")
	}
	if c.Issuance.MaxValidityDays <= 0 {
		return fmt.Errorf("config: issuance.max_validity_days must be positive, got %d", c.Issuance.MaxValidityDays)
	}
	if c.Issuance.CRLValidityHours <= 0 {
		return fmt.Errorf("config: issuance.crl_validity_hours must be positive, got %d", c.Issuance.CRLValidityHours)
	}
	return nil
}
```

Note: `yaml.NewDecoder` is used instead of `yaml.Unmarshal` because only the decoder supports `KnownFields(true)`, which is what makes a typo'd key an error.

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `CGO_ENABLED=0 go test ./internal/config/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/config go.mod go.sum
git commit -m "feat(config): YAML configuration with environment overrides and validation"
```

---

### Task 11: ca — issuance profiles, hierarchy and CRL

**Files:**
- Create: `internal/ca/profiles.go`, `internal/ca/engine.go`, `internal/ca/crl.go`
- Test: `internal/ca/engine_test.go`, `internal/ca/crl_test.go`

**Interfaces:**
- Consumes: `pqx509` (all of Tasks 1–6), `keystore.Backend`, `store.Store`.
- Produces:
  - ```go
    type Engine struct { /* unexported fields */ }
    type Options struct {
        MaxValidity   time.Duration // end-entity ceiling; 397 days by default
        CRLValidity   time.Duration
        Now           func() time.Time // injectable clock; nil means time.Now
    }
    func New(st *store.Store, ks keystore.Backend, opts Options) (*Engine, error)

    type CreateCARequest struct {
        Name          string
        ParentID      string // empty creates a root
        Algorithm     pqx509.Algorithm
        Subject       pqx509.Name
        ValidityDays  int    // 0 uses the profile default (root 3650, intermediate 1825)
        Passphrase    []byte // seals the new CA key
        ParentPassphrase []byte // required when ParentID is set
    }
    type CAResult struct {
        ID       string
        Name     string
        ParentID string
        Algorithm pqx509.Algorithm
        CertPEM  string
        ChainPEM string
        Certificate *pqx509.Certificate
        CreatedAt time.Time
    }
    func (e *Engine) CreateCA(ctx context.Context, req CreateCARequest) (CAResult, error)
    func (e *Engine) GetCA(ctx context.Context, id string) (CAResult, error)
    func (e *Engine) ListCAs(ctx context.Context) ([]CAResult, error)

    type IssueRequest struct {
        CAID         string
        CAPassphrase []byte
        Subject      pqx509.Name
        SANs         pqx509.SANs
        Algorithm    pqx509.Algorithm // 0 means ML-DSA-44
        ValidityDays int              // 0 means the profile default (90)
        ExtKeyUsage  []pqx509.ExtKeyUsage // empty means serverAuth
        StoreKey     bool
    }
    type IssueResult struct {
        Serial        string // lowercase hex
        CertPEM       string
        ChainPEM      string
        PrivateKeyPEM string // empty when StoreKey is true
        Certificate   *pqx509.Certificate
    }
    func (e *Engine) IssueCertificate(ctx context.Context, req IssueRequest) (IssueResult, error)
    func (e *Engine) GetCertificate(ctx context.Context, serial string) (store.Certificate, error)
    func (e *Engine) Revoke(ctx context.Context, serial string, reason int) error
    func (e *Engine) CRL(ctx context.Context, caID string, passphrase []byte) ([]byte, error)
    ```
  - Sentinels: `ErrConstraintViolation`, `ErrNotFound` (wrapping `store.ErrNotFound`), `ErrAlreadyRevoked`
  - `func EncodePrivateKeyPEM(priv pqx509.PrivateKey) []byte` and `func SerialHex(*big.Int) string` (lowercase, no leading zeroes stripped beyond `big.Int` semantics)

Profile rules (`profiles.go`), enforced with `ErrConstraintViolation`:
- Root: algorithm must be ML-DSA-87; `cA=TRUE, pathlen=1`; KU `keyCertSign|cRLSign`; default validity 3650 days; max 3650.
- Intermediate: algorithm must be ML-DSA-65; parent must be a root (a CA whose `ParentID` is empty); `cA=TRUE, pathlen=0`; KU `keyCertSign|cRLSign`; default validity 1825 days; max 1825; must not exceed the parent's `NotAfter`.
- End-entity: algorithm must be ML-DSA-44 or ML-DSA-65; issuing CA must be an intermediate (`ParentID != ""`); `cA=FALSE`; KU `digitalSignature`; EKU subset of {serverAuth, clientAuth}; validity ≤ `Options.MaxValidity` (default 397 days) and must not exceed the CA's `NotAfter`; at least one of Subject.CommonName or SANs must be present.
- Revoked or non-active CAs cannot issue.

Private key PEM: `-----BEGIN PQTRUST ML-DSA PRIVATE KEY-----` wrapping the 32-byte seed, with headers `Algorithm: ML-DSA-44`. This is deliberately a pqtrust-specific format; PKCS#8 for ML-DSA arrives with the Phase 2 CSR work. Document it in LIMITATIONS.md (Task 15).

CRL behaviour (`crl.go`): `CRL` regenerates lazily. The engine caches, per CA ID, the DER plus the revocation count and `nextUpdate` used to build it. A cached CRL is returned when the revoked-certificate count is unchanged and `now` is before `nextUpdate`; otherwise it is rebuilt with `number = revocationCount + 1`.

- [ ] **Step 1: Write the failing engine tests**

`internal/ca/engine_test.go`:

```go
package ca

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fernando/pqtrust/internal/keystore"
	"github.com/fernando/pqtrust/internal/pqx509"
	"github.com/fernando/pqtrust/internal/store"
)

func newEngine(t *testing.T) *Engine {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "pqtrust.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ks, err := keystore.NewFileBackend(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	e, err := New(st, ks, Options{})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

var pass = []byte("test-passphrase")

func createRoot(t *testing.T, e *Engine) CAResult {
	t.Helper()
	root, err := e.CreateCA(context.Background(), CreateCARequest{
		Name:       "pqtrust Root",
		Algorithm:  pqx509.MLDSA87,
		Subject:    pqx509.Name{CommonName: "pqtrust Root CA", Organization: []string{"pqtrust"}},
		Passphrase: pass,
	})
	if err != nil {
		t.Fatalf("CreateCA(root): %v", err)
	}
	return root
}

func createIntermediate(t *testing.T, e *Engine, rootID string) CAResult {
	t.Helper()
	inter, err := e.CreateCA(context.Background(), CreateCARequest{
		Name:             "pqtrust Issuing",
		ParentID:         rootID,
		Algorithm:        pqx509.MLDSA65,
		Subject:          pqx509.Name{CommonName: "pqtrust Issuing CA", Organization: []string{"pqtrust"}},
		Passphrase:       pass,
		ParentPassphrase: pass,
	})
	if err != nil {
		t.Fatalf("CreateCA(intermediate): %v", err)
	}
	return inter
}

func TestCreateRootCA(t *testing.T) {
	e := newEngine(t)
	root := createRoot(t, e)

	if root.ID == "" {
		t.Error("root CA must get an ID")
	}
	cert := root.Certificate
	if !cert.IsSelfSigned() {
		t.Error("root must be self-signed")
	}
	if cert.SignatureAlgorithm != pqx509.MLDSA87 {
		t.Errorf("algorithm = %v, want ML-DSA-87", cert.SignatureAlgorithm)
	}
	if !cert.BasicConstraints.IsCA || cert.BasicConstraints.MaxPathLen != 1 {
		t.Errorf("basic constraints = %+v, want cA=TRUE pathlen=1", cert.BasicConstraints)
	}
	if cert.KeyUsage != pqx509.KeyUsageKeyCertSign|pqx509.KeyUsageCRLSign {
		t.Errorf("key usage = %b", cert.KeyUsage)
	}
	years := cert.NotAfter.Sub(cert.NotBefore).Hours() / 24 / 365
	if years < 9.9 || years > 10.1 {
		t.Errorf("root validity = %.2f years, want ~10", years)
	}
	if !strings.Contains(root.CertPEM, "BEGIN CERTIFICATE") {
		t.Error("CertPEM must be PEM")
	}
	if root.ChainPEM != root.CertPEM {
		t.Error("a root's chain is just itself")
	}
}

func TestCreateIntermediateCA(t *testing.T) {
	e := newEngine(t)
	root := createRoot(t, e)
	inter := createIntermediate(t, e, root.ID)

	cert := inter.Certificate
	if cert.IsSelfSigned() {
		t.Error("intermediate must not be self-signed")
	}
	if cert.SignatureAlgorithm != pqx509.MLDSA87 {
		t.Errorf("intermediate must be signed by the root's ML-DSA-87 key, got %v", cert.SignatureAlgorithm)
	}
	if cert.PublicKey.Algorithm != pqx509.MLDSA65 {
		t.Errorf("intermediate key algorithm = %v, want ML-DSA-65", cert.PublicKey.Algorithm)
	}
	if !cert.BasicConstraints.IsCA || cert.BasicConstraints.MaxPathLen != 0 {
		t.Errorf("basic constraints = %+v, want cA=TRUE pathlen=0", cert.BasicConstraints)
	}
	if err := cert.VerifySignatureFrom(root.Certificate); err != nil {
		t.Errorf("intermediate must verify under the root: %v", err)
	}
	// Chain is intermediate then root.
	if strings.Count(inter.ChainPEM, "BEGIN CERTIFICATE") != 2 {
		t.Errorf("chain must contain 2 certificates:\n%s", inter.ChainPEM)
	}
}

func TestCreateCAConstraints(t *testing.T) {
	e := newEngine(t)
	ctx := context.Background()
	root := createRoot(t, e)

	t.Run("root with wrong algorithm", func(t *testing.T) {
		_, err := e.CreateCA(ctx, CreateCARequest{Name: "bad", Algorithm: pqx509.MLDSA44, Subject: pqx509.Name{CommonName: "bad"}, Passphrase: pass})
		if !errors.Is(err, ErrConstraintViolation) {
			t.Errorf("want ErrConstraintViolation, got %v", err)
		}
	})
	t.Run("intermediate with wrong algorithm", func(t *testing.T) {
		_, err := e.CreateCA(ctx, CreateCARequest{Name: "bad", ParentID: root.ID, Algorithm: pqx509.MLDSA87,
			Subject: pqx509.Name{CommonName: "bad"}, Passphrase: pass, ParentPassphrase: pass})
		if !errors.Is(err, ErrConstraintViolation) {
			t.Errorf("want ErrConstraintViolation, got %v", err)
		}
	})
	t.Run("three levels rejected", func(t *testing.T) {
		inter := createIntermediate(t, e, root.ID)
		_, err := e.CreateCA(ctx, CreateCARequest{Name: "third", ParentID: inter.ID, Algorithm: pqx509.MLDSA65,
			Subject: pqx509.Name{CommonName: "third"}, Passphrase: pass, ParentPassphrase: pass})
		if !errors.Is(err, ErrConstraintViolation) {
			t.Errorf("a third hierarchy level must be rejected, got %v", err)
		}
	})
	t.Run("unknown parent", func(t *testing.T) {
		_, err := e.CreateCA(ctx, CreateCARequest{Name: "orphan", ParentID: "nope", Algorithm: pqx509.MLDSA65,
			Subject: pqx509.Name{CommonName: "orphan"}, Passphrase: pass, ParentPassphrase: pass})
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("want ErrNotFound, got %v", err)
		}
	})
	t.Run("wrong parent passphrase", func(t *testing.T) {
		_, err := e.CreateCA(ctx, CreateCARequest{Name: "x", ParentID: root.ID, Algorithm: pqx509.MLDSA65,
			Subject: pqx509.Name{CommonName: "x"}, Passphrase: pass, ParentPassphrase: []byte("wrong")})
		if !errors.Is(err, keystore.ErrWrongPassphrase) {
			t.Errorf("want keystore.ErrWrongPassphrase, got %v", err)
		}
	})
	t.Run("validity beyond the maximum", func(t *testing.T) {
		_, err := e.CreateCA(ctx, CreateCARequest{Name: "long", Algorithm: pqx509.MLDSA87,
			Subject: pqx509.Name{CommonName: "long"}, ValidityDays: 20000, Passphrase: pass})
		if !errors.Is(err, ErrConstraintViolation) {
			t.Errorf("want ErrConstraintViolation, got %v", err)
		}
	})
}

func TestIssueCertificate(t *testing.T) {
	e := newEngine(t)
	ctx := context.Background()
	root := createRoot(t, e)
	inter := createIntermediate(t, e, root.ID)

	res, err := e.IssueCertificate(ctx, IssueRequest{
		CAID:         inter.ID,
		CAPassphrase: pass,
		Subject:      pqx509.Name{CommonName: "api.example.com"},
		SANs:         pqx509.SANs{DNSNames: []string{"api.example.com"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Serial == "" {
		t.Error("serial must be set")
	}
	if res.PrivateKeyPEM == "" {
		t.Error("the private key must be returned when StoreKey is false")
	}
	if !strings.Contains(res.PrivateKeyPEM, "PQTRUST ML-DSA PRIVATE KEY") {
		t.Errorf("unexpected private key PEM: %q", res.PrivateKeyPEM[:40])
	}
	leaf := res.Certificate
	if leaf.PublicKey.Algorithm != pqx509.MLDSA44 {
		t.Errorf("default end-entity algorithm = %v, want ML-DSA-44", leaf.PublicKey.Algorithm)
	}
	if leaf.KeyUsage != pqx509.KeyUsageDigitalSignature {
		t.Errorf("key usage = %b", leaf.KeyUsage)
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != pqx509.ExtKeyUsageServerAuth {
		t.Errorf("default EKU = %v, want [serverAuth]", leaf.ExtKeyUsage)
	}
	if leaf.BasicConstraints.IsCA {
		t.Error("end-entity must not be a CA")
	}
	days := leaf.NotAfter.Sub(leaf.NotBefore).Hours() / 24
	if days < 89 || days > 91 {
		t.Errorf("default validity = %.1f days, want ~90", days)
	}
	// The full chain must validate.
	chains, err := leaf.Verify(pqx509.VerifyOptions{
		Roots:         []*pqx509.Certificate{root.Certificate},
		Intermediates: []*pqx509.Certificate{inter.Certificate},
	})
	if err != nil {
		t.Fatalf("issued certificate must chain to the root: %v", err)
	}
	if len(chains[0]) != 3 {
		t.Errorf("chain length = %d, want 3", len(chains[0]))
	}
	if strings.Count(res.ChainPEM, "BEGIN CERTIFICATE") != 3 {
		t.Errorf("ChainPEM must hold leaf + intermediate + root:\n%s", res.ChainPEM)
	}

	// Persisted record must match.
	rec, err := e.GetCertificate(ctx, res.Serial)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != store.StatusValid || rec.CAID != inter.ID {
		t.Errorf("record = %+v", rec)
	}
	if rec.KeyID != "" {
		t.Error("the key must not be stored when StoreKey is false")
	}
	if rec.SANs != "api.example.com" {
		t.Errorf("stored SANs = %q", rec.SANs)
	}
}

func TestIssueCertificateStoreKey(t *testing.T) {
	e := newEngine(t)
	ctx := context.Background()
	root := createRoot(t, e)
	inter := createIntermediate(t, e, root.ID)

	res, err := e.IssueCertificate(ctx, IssueRequest{
		CAID: inter.ID, CAPassphrase: pass,
		Subject:  pqx509.Name{CommonName: "stored.example.com"},
		SANs:     pqx509.SANs{DNSNames: []string{"stored.example.com"}},
		StoreKey: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.PrivateKeyPEM != "" {
		t.Error("the private key must not be returned when StoreKey is true")
	}
	rec, err := e.GetCertificate(ctx, res.Serial)
	if err != nil {
		t.Fatal(err)
	}
	if rec.KeyID == "" {
		t.Error("a stored key must be recorded")
	}
}

func TestIssueCertificateConstraints(t *testing.T) {
	e := newEngine(t)
	ctx := context.Background()
	root := createRoot(t, e)
	inter := createIntermediate(t, e, root.ID)

	t.Run("root may not issue end-entity certificates", func(t *testing.T) {
		_, err := e.IssueCertificate(ctx, IssueRequest{CAID: root.ID, CAPassphrase: pass,
			Subject: pqx509.Name{CommonName: "x"}, SANs: pqx509.SANs{DNSNames: []string{"x"}}})
		if !errors.Is(err, ErrConstraintViolation) {
			t.Errorf("want ErrConstraintViolation, got %v", err)
		}
	})
	t.Run("validity beyond the maximum", func(t *testing.T) {
		_, err := e.IssueCertificate(ctx, IssueRequest{CAID: inter.ID, CAPassphrase: pass,
			Subject: pqx509.Name{CommonName: "x"}, SANs: pqx509.SANs{DNSNames: []string{"x"}}, ValidityDays: 500})
		if !errors.Is(err, ErrConstraintViolation) {
			t.Errorf("want ErrConstraintViolation, got %v", err)
		}
	})
	t.Run("unsupported algorithm", func(t *testing.T) {
		_, err := e.IssueCertificate(ctx, IssueRequest{CAID: inter.ID, CAPassphrase: pass, Algorithm: pqx509.MLDSA87,
			Subject: pqx509.Name{CommonName: "x"}, SANs: pqx509.SANs{DNSNames: []string{"x"}}})
		if !errors.Is(err, ErrConstraintViolation) {
			t.Errorf("ML-DSA-87 end-entity certificates are not offered: %v", err)
		}
	})
	t.Run("no subject and no SANs", func(t *testing.T) {
		_, err := e.IssueCertificate(ctx, IssueRequest{CAID: inter.ID, CAPassphrase: pass})
		if !errors.Is(err, ErrConstraintViolation) {
			t.Errorf("want ErrConstraintViolation, got %v", err)
		}
	})
	t.Run("unknown CA", func(t *testing.T) {
		_, err := e.IssueCertificate(ctx, IssueRequest{CAID: "nope", CAPassphrase: pass,
			Subject: pqx509.Name{CommonName: "x"}, SANs: pqx509.SANs{DNSNames: []string{"x"}}})
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("want ErrNotFound, got %v", err)
		}
	})
	t.Run("wrong CA passphrase", func(t *testing.T) {
		_, err := e.IssueCertificate(ctx, IssueRequest{CAID: inter.ID, CAPassphrase: []byte("wrong"),
			Subject: pqx509.Name{CommonName: "x"}, SANs: pqx509.SANs{DNSNames: []string{"x"}}})
		if !errors.Is(err, keystore.ErrWrongPassphrase) {
			t.Errorf("want keystore.ErrWrongPassphrase, got %v", err)
		}
	})
}

func TestRevoke(t *testing.T) {
	e := newEngine(t)
	ctx := context.Background()
	root := createRoot(t, e)
	inter := createIntermediate(t, e, root.ID)
	res, err := e.IssueCertificate(ctx, IssueRequest{CAID: inter.ID, CAPassphrase: pass,
		Subject: pqx509.Name{CommonName: "revoke.example.com"}, SANs: pqx509.SANs{DNSNames: []string{"revoke.example.com"}}})
	if err != nil {
		t.Fatal(err)
	}

	if err := e.Revoke(ctx, res.Serial, 1); err != nil {
		t.Fatal(err)
	}
	rec, err := e.GetCertificate(ctx, res.Serial)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != store.StatusRevoked || rec.RevocationReason == nil || *rec.RevocationReason != 1 {
		t.Errorf("record after revoke = %+v", rec)
	}
	if err := e.Revoke(ctx, res.Serial, 1); !errors.Is(err, ErrAlreadyRevoked) {
		t.Errorf("second revoke: want ErrAlreadyRevoked, got %v", err)
	}
	if err := e.Revoke(ctx, "deadbeef", 1); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoking an unknown serial: want ErrNotFound, got %v", err)
	}
}

func TestInjectedClockGovernsValidity(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ks, err := keystore.NewFileBackend(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	fixed := time.Date(2030, 5, 4, 3, 2, 1, 0, time.UTC)
	e, err := New(st, ks, Options{Now: func() time.Time { return fixed }})
	if err != nil {
		t.Fatal(err)
	}
	root, err := e.CreateCA(context.Background(), CreateCARequest{Name: "R", Algorithm: pqx509.MLDSA87,
		Subject: pqx509.Name{CommonName: "R"}, Passphrase: pass})
	if err != nil {
		t.Fatal(err)
	}
	// NotBefore is backdated by a small skew allowance, never in the future.
	if root.Certificate.NotBefore.After(fixed) {
		t.Errorf("NotBefore %v must not be after the injected now %v", root.Certificate.NotBefore, fixed)
	}
	if root.Certificate.NotAfter.Year() != 2040 {
		t.Errorf("NotAfter year = %d, want 2040", root.Certificate.NotAfter.Year())
	}
}
```

- [ ] **Step 2: Write the failing CRL tests**

`internal/ca/crl_test.go`:

```go
package ca

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/fernando/pqtrust/internal/pqx509"
)

func TestCRLEmptyThenRevoked(t *testing.T) {
	e := newEngine(t)
	ctx := context.Background()
	root := createRoot(t, e)
	inter := createIntermediate(t, e, root.ID)

	der, err := e.CRL(ctx, inter.ID, pass)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := pqx509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(crl.Entries) != 0 {
		t.Errorf("fresh CRL has %d entries, want 0", len(crl.Entries))
	}
	if err := crl.VerifySignatureFrom(inter.Certificate); err != nil {
		t.Errorf("CRL must verify under the issuing CA: %v", err)
	}

	res, err := e.IssueCertificate(ctx, IssueRequest{CAID: inter.ID, CAPassphrase: pass,
		Subject: pqx509.Name{CommonName: "crl.example.com"}, SANs: pqx509.SANs{DNSNames: []string{"crl.example.com"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Revoke(ctx, res.Serial, 4); err != nil {
		t.Fatal(err)
	}

	der2, err := e.CRL(ctx, inter.ID, pass)
	if err != nil {
		t.Fatal(err)
	}
	crl2, err := pqx509.ParseRevocationList(der2)
	if err != nil {
		t.Fatal(err)
	}
	if len(crl2.Entries) != 1 {
		t.Fatalf("CRL has %d entries, want 1", len(crl2.Entries))
	}
	serial, ok := new(big.Int).SetString(res.Serial, 16)
	if !ok {
		t.Fatalf("serial %q is not hex", res.Serial)
	}
	entry, found := crl2.IsRevoked(serial)
	if !found {
		t.Fatal("the revoked serial must appear on the CRL")
	}
	if entry.ReasonCode != 4 {
		t.Errorf("reason = %d, want 4", entry.ReasonCode)
	}
	if crl2.Number.Cmp(crl.Number) <= 0 {
		t.Errorf("CRL number must increase: %v then %v", crl.Number, crl2.Number)
	}
}

func TestCRLIsCachedUntilRevocationChanges(t *testing.T) {
	e := newEngine(t)
	ctx := context.Background()
	root := createRoot(t, e)
	inter := createIntermediate(t, e, root.ID)

	a, err := e.CRL(ctx, inter.ID, pass)
	if err != nil {
		t.Fatal(err)
	}
	// A second call with no revocation change must return the identical bytes,
	// which also proves the CA key was not unsealed again.
	b, err := e.CRL(ctx, inter.ID, nil)
	if err != nil {
		t.Fatalf("a cached CRL must not require the passphrase: %v", err)
	}
	if string(a) != string(b) {
		t.Error("an unchanged CRL must be served from cache")
	}

	res, err := e.IssueCertificate(ctx, IssueRequest{CAID: inter.ID, CAPassphrase: pass,
		Subject: pqx509.Name{CommonName: "x.example.com"}, SANs: pqx509.SANs{DNSNames: []string{"x.example.com"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Revoke(ctx, res.Serial, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := e.CRL(ctx, inter.ID, nil); err == nil {
		t.Error("rebuilding the CRL after a revocation requires the passphrase")
	}
	c, err := e.CRL(ctx, inter.ID, pass)
	if err != nil {
		t.Fatal(err)
	}
	if string(c) == string(a) {
		t.Error("the CRL must change after a revocation")
	}
}

func TestCRLUnknownCA(t *testing.T) {
	e := newEngine(t)
	if _, err := e.CRL(context.Background(), "nope", pass); !errors.Is(err, ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}
}
```

- [ ] **Step 3: Run and confirm failure**

Run: `CGO_ENABLED=0 go test ./internal/ca/ -v`
Expected: compile failure.

- [ ] **Step 4: Implement `profiles.go`**

```go
// Package ca holds pqtrust's domain logic: what may be issued, by whom, and for
// how long. It builds certificates with pqx509, keeps keys in a keystore.Backend
// and records state through store.
package ca

import (
	"errors"
	"fmt"
	"time"

	"github.com/fernando/pqtrust/internal/pqx509"
)

var (
	// ErrConstraintViolation reports a request that policy forbids.
	ErrConstraintViolation = errors.New("ca: constraint violation")
	// ErrNotFound reports an unknown CA or certificate.
	ErrNotFound = errors.New("ca: not found")
	// ErrAlreadyRevoked reports a second revocation of the same certificate.
	ErrAlreadyRevoked = errors.New("ca: certificate is already revoked")
)

// Profile defaults, in days.
const (
	rootValidityDays         = 3650
	intermediateValidityDays = 1825
	endEntityValidityDays    = 90
	maxEndEntityValidityDays = 397
)

// clockSkew backdates NotBefore so that a freshly issued certificate is usable
// on a verifier whose clock is slightly behind.
const clockSkew = 5 * time.Minute

type caProfile struct {
	algorithm    pqx509.Algorithm
	pathLen      int
	keyUsage     pqx509.KeyUsage
	defaultDays  int
	maxDays      int
}

var (
	rootProfile = caProfile{
		algorithm:   pqx509.MLDSA87,
		pathLen:     1,
		keyUsage:    pqx509.KeyUsageKeyCertSign | pqx509.KeyUsageCRLSign,
		defaultDays: rootValidityDays,
		maxDays:     rootValidityDays,
	}
	intermediateProfile = caProfile{
		algorithm:   pqx509.MLDSA65,
		pathLen:     0,
		keyUsage:    pqx509.KeyUsageKeyCertSign | pqx509.KeyUsageCRLSign,
		defaultDays: intermediateValidityDays,
		maxDays:     intermediateValidityDays,
	}
)

func (p caProfile) checkAlgorithm(alg pqx509.Algorithm) error {
	if alg != p.algorithm {
		return fmt.Errorf("%w: this CA level requires %v, got %v", ErrConstraintViolation, p.algorithm, alg)
	}
	return nil
}

func (p caProfile) resolveDays(requested int) (int, error) {
	if requested == 0 {
		return p.defaultDays, nil
	}
	if requested < 0 {
		return 0, fmt.Errorf("%w: validity must be positive, got %d days", ErrConstraintViolation, requested)
	}
	if requested > p.maxDays {
		return 0, fmt.Errorf("%w: validity %d days exceeds the %d day maximum for this CA level",
			ErrConstraintViolation, requested, p.maxDays)
	}
	return requested, nil
}

// endEntityAlgorithms are the algorithms pqtrust issues to end entities.
func checkEndEntityAlgorithm(alg pqx509.Algorithm) error {
	switch alg {
	case pqx509.MLDSA44, pqx509.MLDSA65:
		return nil
	default:
		return fmt.Errorf("%w: end-entity certificates support ML-DSA-44 and ML-DSA-65, got %v", ErrConstraintViolation, alg)
	}
}

func checkExtKeyUsage(ekus []pqx509.ExtKeyUsage) error {
	for _, e := range ekus {
		switch e {
		case pqx509.ExtKeyUsageServerAuth, pqx509.ExtKeyUsageClientAuth:
		default:
			return fmt.Errorf("%w: unsupported extended key usage %v", ErrConstraintViolation, e)
		}
	}
	return nil
}
```

- [ ] **Step 5: Implement `engine.go`**

```go
package ca

import (
	"context"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/fernando/pqtrust/internal/keystore"
	"github.com/fernando/pqtrust/internal/pqx509"
	"github.com/fernando/pqtrust/internal/store"
)

// Options configures an Engine.
type Options struct {
	// MaxValidity caps end-entity validity; zero means 397 days.
	MaxValidity time.Duration
	// CRLValidity is the nextUpdate offset; zero means 168 hours.
	CRLValidity time.Duration
	// Now is an injectable clock for tests; nil means time.Now.
	Now func() time.Time
}

// Engine is pqtrust's certificate authority.
type Engine struct {
	st  *store.Store
	ks  keystore.Backend
	now func() time.Time

	maxValidity time.Duration
	crlValidity time.Duration

	mu       sync.Mutex
	crlCache map[string]crlCacheEntry
}

// New builds an Engine over st and ks.
func New(st *store.Store, ks keystore.Backend, opts Options) (*Engine, error) {
	if st == nil || ks == nil {
		return nil, fmt.Errorf("ca: store and keystore are required")
	}
	e := &Engine{
		st:          st,
		ks:          ks,
		now:         opts.Now,
		maxValidity: opts.MaxValidity,
		crlValidity: opts.CRLValidity,
		crlCache:    map[string]crlCacheEntry{},
	}
	if e.now == nil {
		e.now = time.Now
	}
	if e.maxValidity == 0 {
		e.maxValidity = maxEndEntityValidityDays * 24 * time.Hour
	}
	if e.crlValidity == 0 {
		e.crlValidity = 168 * time.Hour
	}
	return e, nil
}

// CreateCARequest describes a root or intermediate CA to create.
type CreateCARequest struct {
	Name             string
	ParentID         string
	Algorithm        pqx509.Algorithm
	Subject          pqx509.Name
	ValidityDays     int
	Passphrase       []byte
	ParentPassphrase []byte
}

// CAResult is a CA and its chain.
type CAResult struct {
	ID          string
	Name        string
	ParentID    string
	Algorithm   pqx509.Algorithm
	CertPEM     string
	ChainPEM    string
	Certificate *pqx509.Certificate
	CreatedAt   time.Time
}

// CreateCA generates a key, issues the CA certificate and records it.
func (e *Engine) CreateCA(ctx context.Context, req CreateCARequest) (CAResult, error) {
	if strings.TrimSpace(req.Name) == "" {
		return CAResult{}, fmt.Errorf("%w: CA name must not be empty", ErrConstraintViolation)
	}
	if req.Subject.CommonName == "" {
		return CAResult{}, fmt.Errorf("%w: a CA subject must include a common name", ErrConstraintViolation)
	}
	if len(req.Passphrase) == 0 {
		return CAResult{}, fmt.Errorf("%w: a passphrase is required to seal the CA key", ErrConstraintViolation)
	}

	profile := rootProfile
	var parentRec store.CA
	var parentCert *pqx509.Certificate
	if req.ParentID != "" {
		profile = intermediateProfile
		var err error
		parentRec, err = e.st.GetCA(ctx, req.ParentID)
		if err != nil {
			return CAResult{}, wrapStoreErr(err)
		}
		if parentRec.ParentID != "" {
			return CAResult{}, fmt.Errorf("%w: only a root CA may issue an intermediate; %q is itself an intermediate",
				ErrConstraintViolation, req.ParentID)
		}
		if parentRec.Status != store.StatusActive {
			return CAResult{}, fmt.Errorf("%w: parent CA %q is %s", ErrConstraintViolation, req.ParentID, parentRec.Status)
		}
		if parentCert, err = parseCertPEM(parentRec.CertPEM); err != nil {
			return CAResult{}, err
		}
	}
	if err := profile.checkAlgorithm(req.Algorithm); err != nil {
		return CAResult{}, err
	}
	days, err := profile.resolveDays(req.ValidityDays)
	if err != nil {
		return CAResult{}, err
	}

	now := e.now().UTC().Truncate(time.Second)
	notBefore := now.Add(-clockSkew)
	notAfter := now.AddDate(0, 0, days)
	if parentCert != nil && notAfter.After(parentCert.NotAfter) {
		return CAResult{}, fmt.Errorf("%w: intermediate validity would outlast the root (%v)", ErrConstraintViolation, parentCert.NotAfter)
	}

	keyID, pub, priv, err := e.ks.Generate(req.Algorithm, req.Passphrase)
	if err != nil {
		return CAResult{}, fmt.Errorf("ca: generating CA key: %w", err)
	}
	defer zeroSeed(priv)

	serial, err := pqx509.GenerateSerialNumber(rand.Reader)
	if err != nil {
		return CAResult{}, err
	}

	var signer pqx509.Signer
	signatureAlg := req.Algorithm
	if req.ParentID == "" {
		if signer, err = priv.Signer(); err != nil {
			return CAResult{}, err
		}
	} else {
		signatureAlg = parentCert.PublicKey.Algorithm
		if signer, err = e.ks.Load(parentRec.KeyID, req.ParentPassphrase); err != nil {
			_ = e.ks.Delete(keyID)
			return CAResult{}, err
		}
	}

	tmpl := &pqx509.Certificate{
		SerialNumber:          serial,
		SignatureAlgorithm:    signatureAlg,
		Subject:               req.Subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraints:      pqx509.BasicConstraints{IsCA: true, MaxPathLen: profile.pathLen, MaxPathLenSet: true},
		BasicConstraintsValid: true,
		KeyUsage:              profile.keyUsage,
	}
	parentTmpl := tmpl
	if parentCert != nil {
		parentTmpl = parentCert
	}
	der, err := pqx509.CreateCertificate(rand.Reader, tmpl, parentTmpl, pub, signer)
	if err != nil {
		_ = e.ks.Delete(keyID)
		return CAResult{}, fmt.Errorf("ca: creating CA certificate: %w", err)
	}
	cert, err := pqx509.ParseCertificate(der)
	if err != nil {
		_ = e.ks.Delete(keyID)
		return CAResult{}, fmt.Errorf("ca: re-parsing the new CA certificate: %w", err)
	}

	caID, err := keystore.NewKeyID()
	if err != nil {
		_ = e.ks.Delete(keyID)
		return CAResult{}, err
	}
	certPEM := string(pqx509.EncodeCertificatePEM(der))
	rec := store.CA{
		ID:        caID,
		Name:      req.Name,
		ParentID:  req.ParentID,
		Algorithm: req.Algorithm.String(),
		CertPEM:   certPEM,
		KeyID:     keyID,
		Status:    store.StatusActive,
		CreatedAt: now,
	}
	if err := e.st.CreateCA(ctx, rec); err != nil {
		_ = e.ks.Delete(keyID)
		return CAResult{}, wrapStoreErr(err)
	}

	chainPEM := certPEM
	if parentRec.CertPEM != "" {
		chainPEM = certPEM + parentRec.CertPEM
	}
	return CAResult{
		ID: caID, Name: req.Name, ParentID: req.ParentID, Algorithm: req.Algorithm,
		CertPEM: certPEM, ChainPEM: chainPEM, Certificate: cert, CreatedAt: now,
	}, nil
}

// GetCA loads a CA and assembles its chain.
func (e *Engine) GetCA(ctx context.Context, id string) (CAResult, error) {
	rec, err := e.st.GetCA(ctx, id)
	if err != nil {
		return CAResult{}, wrapStoreErr(err)
	}
	return e.caResult(ctx, rec)
}

// ListCAs returns every CA with its chain.
func (e *Engine) ListCAs(ctx context.Context) ([]CAResult, error) {
	recs, err := e.st.ListCAs(ctx)
	if err != nil {
		return nil, wrapStoreErr(err)
	}
	out := make([]CAResult, 0, len(recs))
	for _, rec := range recs {
		res, err := e.caResult(ctx, rec)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (e *Engine) caResult(ctx context.Context, rec store.CA) (CAResult, error) {
	cert, err := parseCertPEM(rec.CertPEM)
	if err != nil {
		return CAResult{}, err
	}
	alg, err := pqx509.ParseAlgorithm(rec.Algorithm)
	if err != nil {
		return CAResult{}, fmt.Errorf("ca: stored CA %q: %w", rec.ID, err)
	}
	chain := rec.CertPEM
	if rec.ParentID != "" {
		parent, err := e.st.GetCA(ctx, rec.ParentID)
		if err != nil {
			return CAResult{}, wrapStoreErr(err)
		}
		chain += parent.CertPEM
	}
	return CAResult{
		ID: rec.ID, Name: rec.Name, ParentID: rec.ParentID, Algorithm: alg,
		CertPEM: rec.CertPEM, ChainPEM: chain, Certificate: cert, CreatedAt: rec.CreatedAt,
	}, nil
}

// IssueRequest describes an end-entity certificate to issue.
type IssueRequest struct {
	CAID         string
	CAPassphrase []byte
	Subject      pqx509.Name
	SANs         pqx509.SANs
	Algorithm    pqx509.Algorithm
	ValidityDays int
	ExtKeyUsage  []pqx509.ExtKeyUsage
	StoreKey     bool
}

// IssueResult is a newly issued certificate.
type IssueResult struct {
	Serial        string
	CertPEM       string
	ChainPEM      string
	PrivateKeyPEM string
	Certificate   *pqx509.Certificate
}

// IssueCertificate generates a key pair, issues a certificate and records it.
func (e *Engine) IssueCertificate(ctx context.Context, req IssueRequest) (IssueResult, error) {
	caRec, err := e.st.GetCA(ctx, req.CAID)
	if err != nil {
		return IssueResult{}, wrapStoreErr(err)
	}
	if caRec.Status != store.StatusActive {
		return IssueResult{}, fmt.Errorf("%w: CA %q is %s", ErrConstraintViolation, req.CAID, caRec.Status)
	}
	if caRec.ParentID == "" {
		return IssueResult{}, fmt.Errorf("%w: the root CA issues intermediates only; use an intermediate CA to issue end-entity certificates", ErrConstraintViolation)
	}
	caCert, err := parseCertPEM(caRec.CertPEM)
	if err != nil {
		return IssueResult{}, err
	}

	alg := req.Algorithm
	if alg == 0 {
		alg = pqx509.MLDSA44
	}
	if err := checkEndEntityAlgorithm(alg); err != nil {
		return IssueResult{}, err
	}
	ekus := req.ExtKeyUsage
	if len(ekus) == 0 {
		ekus = []pqx509.ExtKeyUsage{pqx509.ExtKeyUsageServerAuth}
	}
	if err := checkExtKeyUsage(ekus); err != nil {
		return IssueResult{}, err
	}
	if req.Subject.CommonName == "" && req.SANs.Empty() {
		return IssueResult{}, fmt.Errorf("%w: a certificate needs a common name or at least one subject alternative name", ErrConstraintViolation)
	}

	days := req.ValidityDays
	if days == 0 {
		days = endEntityValidityDays
	}
	if days < 0 {
		return IssueResult{}, fmt.Errorf("%w: validity must be positive, got %d days", ErrConstraintViolation, days)
	}
	if requested := time.Duration(days) * 24 * time.Hour; requested > e.maxValidity {
		return IssueResult{}, fmt.Errorf("%w: validity %d days exceeds the %.0f day maximum",
			ErrConstraintViolation, days, e.maxValidity.Hours()/24)
	}

	now := e.now().UTC().Truncate(time.Second)
	notBefore := now.Add(-clockSkew)
	notAfter := now.AddDate(0, 0, days)
	if notAfter.After(caCert.NotAfter) {
		return IssueResult{}, fmt.Errorf("%w: requested validity outlasts the issuing CA (%v)", ErrConstraintViolation, caCert.NotAfter)
	}

	signer, err := e.ks.Load(caRec.KeyID, req.CAPassphrase)
	if err != nil {
		return IssueResult{}, err
	}

	pub, priv, err := pqx509.GenerateKey(rand.Reader, alg)
	if err != nil {
		return IssueResult{}, err
	}
	serial, err := pqx509.GenerateSerialNumber(rand.Reader)
	if err != nil {
		return IssueResult{}, err
	}

	tmpl := &pqx509.Certificate{
		SerialNumber:          serial,
		SignatureAlgorithm:    caCert.PublicKey.Algorithm,
		Subject:               req.Subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraints:      pqx509.BasicConstraints{IsCA: false},
		BasicConstraintsValid: true,
		KeyUsage:              pqx509.KeyUsageDigitalSignature,
		ExtKeyUsage:           ekus,
		SANs:                  req.SANs,
	}
	der, err := pqx509.CreateCertificate(rand.Reader, tmpl, caCert, pub, signer)
	if err != nil {
		return IssueResult{}, fmt.Errorf("ca: issuing certificate: %w", err)
	}
	cert, err := pqx509.ParseCertificate(der)
	if err != nil {
		return IssueResult{}, fmt.Errorf("ca: re-parsing the issued certificate: %w", err)
	}

	var storedKeyID string
	if req.StoreKey {
		id, err := keystore.NewKeyID()
		if err != nil {
			return IssueResult{}, err
		}
		if err := e.ks.Store(id, priv, req.CAPassphrase); err != nil {
			return IssueResult{}, fmt.Errorf("ca: storing the end-entity key: %w", err)
		}
		storedKeyID = id
	}

	certPEM := string(pqx509.EncodeCertificatePEM(der))
	serialHex := SerialHex(serial)
	rec := store.Certificate{
		Serial:    serialHex,
		CAID:      caRec.ID,
		SubjectDN: req.Subject.String(),
		SANs:      sansString(req.SANs),
		Algorithm: alg.String(),
		CertPEM:   certPEM,
		KeyID:     storedKeyID,
		Status:    store.StatusValid,
		NotBefore: notBefore,
		NotAfter:  notAfter,
	}
	if err := e.st.InsertCertificate(ctx, rec); err != nil {
		if storedKeyID != "" {
			_ = e.ks.Delete(storedKeyID)
		}
		return IssueResult{}, wrapStoreErr(err)
	}

	caResult, err := e.caResult(ctx, caRec)
	if err != nil {
		return IssueResult{}, err
	}
	out := IssueResult{
		Serial:      serialHex,
		CertPEM:     certPEM,
		ChainPEM:    certPEM + caResult.ChainPEM,
		Certificate: cert,
	}
	if !req.StoreKey {
		out.PrivateKeyPEM = string(EncodePrivateKeyPEM(priv))
	}
	zeroSeed(priv)
	return out, nil
}

// GetCertificate returns a stored certificate record.
func (e *Engine) GetCertificate(ctx context.Context, serial string) (store.Certificate, error) {
	rec, err := e.st.GetCertificate(ctx, strings.ToLower(serial))
	if err != nil {
		return store.Certificate{}, wrapStoreErr(err)
	}
	return rec, nil
}

// Revoke marks a certificate revoked with an RFC 5280 reason code.
func (e *Engine) Revoke(ctx context.Context, serial string, reason int) error {
	if reason < 0 || reason > 10 || reason == 7 {
		return fmt.Errorf("%w: %d is not an RFC 5280 CRLReason", ErrConstraintViolation, reason)
	}
	serial = strings.ToLower(serial)
	rec, err := e.st.GetCertificate(ctx, serial)
	if err != nil {
		return wrapStoreErr(err)
	}
	if err := e.st.RevokeCertificate(ctx, serial, e.now().UTC().Truncate(time.Second), reason); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return fmt.Errorf("%w: %s", ErrAlreadyRevoked, serial)
		}
		return wrapStoreErr(err)
	}
	e.invalidateCRL(rec.CAID)
	return nil
}

// EncodePrivateKeyPEM wraps a private key seed in a pqtrust-specific PEM block.
// PKCS#8 for ML-DSA arrives with the Phase 2 CSR work.
func EncodePrivateKeyPEM(priv pqx509.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:    "PQTRUST ML-DSA PRIVATE KEY",
		Headers: map[string]string{"Algorithm": priv.Algorithm.String()},
		Bytes:   priv.Seed,
	})
}

// SerialHex renders a serial number as lowercase hexadecimal.
func SerialHex(serial *big.Int) string {
	return strings.ToLower(serial.Text(16))
}

func sansString(s pqx509.SANs) string {
	var parts []string
	parts = append(parts, s.DNSNames...)
	for _, ip := range s.IPAddresses {
		parts = append(parts, ip.String())
	}
	parts = append(parts, s.EmailAddresses...)
	return strings.Join(parts, ",")
}

func parseCertPEM(certPEM string) (*pqx509.Certificate, error) {
	der, err := pqx509.DecodeCertificatePEM([]byte(certPEM))
	if err != nil {
		return nil, fmt.Errorf("ca: decoding stored certificate: %w", err)
	}
	cert, err := pqx509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("ca: parsing stored certificate: %w", err)
	}
	return cert, nil
}

func wrapStoreErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrNotFound):
		return fmt.Errorf("%w: %w", ErrNotFound, err)
	default:
		return err
	}
}

func zeroSeed(priv pqx509.PrivateKey) {
	for i := range priv.Seed {
		priv.Seed[i] = 0
	}
}
```

- [ ] **Step 6: Implement `crl.go`**

```go
package ca

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/fernando/pqtrust/internal/pqx509"
)

type crlCacheEntry struct {
	der         []byte
	entryCount  int
	nextUpdate  time.Time
	number      *big.Int
}

// CRL returns the current CRL for caID, rebuilding it only when the set of
// revoked certificates has changed or the cached one has expired. passphrase is
// needed only when a rebuild is required.
func (e *Engine) CRL(ctx context.Context, caID string, passphrase []byte) ([]byte, error) {
	caRec, err := e.st.GetCA(ctx, caID)
	if err != nil {
		return nil, wrapStoreErr(err)
	}
	revoked, err := e.st.ListRevoked(ctx, caID)
	if err != nil {
		return nil, wrapStoreErr(err)
	}
	now := e.now().UTC().Truncate(time.Second)

	e.mu.Lock()
	cached, ok := e.crlCache[caID]
	e.mu.Unlock()
	if ok && cached.entryCount == len(revoked) && now.Before(cached.nextUpdate) {
		return cached.der, nil
	}

	caCert, err := parseCertPEM(caRec.CertPEM)
	if err != nil {
		return nil, err
	}
	signer, err := e.ks.Load(caRec.KeyID, passphrase)
	if err != nil {
		return nil, err
	}

	entries := make([]pqx509.RevocationEntry, 0, len(revoked))
	for _, rec := range revoked {
		serial, ok := new(big.Int).SetString(rec.Serial, 16)
		if !ok {
			return nil, fmt.Errorf("ca: stored serial %q is not hexadecimal", rec.Serial)
		}
		entry := pqx509.RevocationEntry{SerialNumber: serial, RevocationTime: now}
		if rec.RevokedAt != nil {
			entry.RevocationTime = *rec.RevokedAt
		}
		if rec.RevocationReason != nil {
			entry.ReasonCode = *rec.RevocationReason
		}
		entries = append(entries, entry)
	}

	number := big.NewInt(int64(len(revoked)) + 1)
	nextUpdate := now.Add(e.crlValidity)
	der, err := pqx509.CreateRevocationList(rand.Reader, caCert, signer, number, entries, now, nextUpdate)
	if err != nil {
		return nil, fmt.Errorf("ca: creating CRL: %w", err)
	}

	e.mu.Lock()
	e.crlCache[caID] = crlCacheEntry{der: der, entryCount: len(revoked), nextUpdate: nextUpdate, number: number}
	e.mu.Unlock()
	return der, nil
}

func (e *Engine) invalidateCRL(caID string) {
	e.mu.Lock()
	delete(e.crlCache, caID)
	e.mu.Unlock()
}
```

- [ ] **Step 7: Run the tests and confirm they pass**

Run: `CGO_ENABLED=0 go test ./internal/ca/ -v`
Expected: PASS. Notes on the two subtle expectations:
- `TestCRLIsCachedUntilRevocationChanges` requires the cache check to happen *before* `ks.Load`, so a cached CRL never needs the passphrase.
- `TestIssueCertificateStoreKey` seals the end-entity key with the same passphrase used to unlock the CA. That is a deliberate Phase 1 simplification; record it in LIMITATIONS.md (Task 15).

- [ ] **Step 8: Commit**

```bash
git add internal/ca
git commit -m "feat(ca): issuance profiles, two-level hierarchy, revocation and lazy CRL generation"
```

---

### Task 12: api — REST handlers, auth and problem+json

**Files:**
- Create: `internal/api/problem.go`, `internal/api/auth.go`, `internal/api/server.go`, `internal/api/handlers_ca.go`, `internal/api/handlers_certs.go`, `internal/api/handlers_misc.go`
- Test: `internal/api/api_test.go`

**Interfaces:**
- Consumes: `ca.Engine`, `store.Store`, `pqx509`.
- Produces:
  - `func NewServer(engine *ca.Engine, st *store.Store) (*Server, error)`; `type Server struct{ ... }` implementing `http.Handler`
  - `func HashToken(token string) string` — hex SHA-256, used by both the middleware and `pqtrustd token create`
  - `func GenerateToken() (string, error)` — 32 random bytes, base64url without padding
  - Problem writer: `func writeProblem(w http.ResponseWriter, status int, typeURN, title, detail string)`
  - `func problemForError(err error) (status int, typeURN, title string)`

Routes, using Go 1.22 method patterns:

| Pattern | Handler |
|---|---|
| `GET /v1/health` | `handleHealth` (no auth) |
| `POST /v1/ca` | `handleCreateCA` |
| `GET /v1/ca` | `handleListCAs` |
| `GET /v1/ca/{id}` | `handleGetCA` |
| `GET /v1/ca/{id}/crl` | `handleGetCRL` |
| `POST /v1/certificates` | `handleIssueCertificate` |
| `GET /v1/certificates/{serial}` | `handleGetCertificate` |
| `POST /v1/certificates/{serial}/revoke` | `handleRevoke` |

Error mapping (`application/problem+json`, `type` URNs under `urn:pqtrust:error:`):

| Condition | Status | `type` |
|---|---|---|
| Malformed JSON / bad field | 400 | `urn:pqtrust:error:invalid-request` |
| Missing or bad bearer token | 401 | `urn:pqtrust:error:unauthorized` |
| `ca.ErrNotFound` | 404 | `urn:pqtrust:error:not-found` |
| `ca.ErrAlreadyRevoked` | 409 | `urn:pqtrust:error:conflict` |
| `keystore.ErrWrongPassphrase` | 403 | `urn:pqtrust:error:wrong-passphrase` |
| `ca.ErrConstraintViolation` | 422 | `urn:pqtrust:error:constraint-violation` |
| anything else | 500 | `urn:pqtrust:error:internal` |

Request/response JSON, exactly as the tests and README use them:

```jsonc
// POST /v1/ca
{"name":"Root","parent_id":null,"algorithm":"ML-DSA-87","subject":{"common_name":"pqtrust Root CA","organization":["pqtrust"],"country":["ES"]},"validity_days":3650,"passphrase":"...","parent_passphrase":null}
// 201 response
{"id":"...","name":"Root","parent_id":null,"algorithm":"ML-DSA-87","certificate_pem":"...","chain_pem":"...","not_before":"2026-...","not_after":"2036-...","created_at":"2026-..."}

// POST /v1/certificates
{"ca_id":"...","passphrase":"...","subject":{"common_name":"api.example.com"},"dns_names":["api.example.com"],"ip_addresses":["192.0.2.10"],"email_addresses":[],"algorithm":"ML-DSA-44","validity_days":90,"ext_key_usage":["serverAuth"],"store_key":false}
// 201 response
{"serial":"0a1b...","certificate_pem":"...","chain_pem":"...","private_key_pem":"...","not_before":"...","not_after":"..."}

// POST /v1/certificates/{serial}/revoke
{"reason":1}
// 200 response
{"serial":"0a1b...","status":"revoked","revoked_at":"...","reason":1}

// GET /v1/certificates/{serial}
{"serial":"...","ca_id":"...","subject_dn":"CN=api.example.com","sans":["api.example.com"],"algorithm":"ML-DSA-44","status":"valid","certificate_pem":"...","not_before":"...","not_after":"...","revoked_at":null,"revocation_reason":null}
```

`GET /v1/ca/{id}/crl` honours `Accept`: `application/pkix-crl` (default) returns DER, `application/x-pem-file` returns PEM. The CRL passphrase comes from the `X-PQTrust-Passphrase` header, which is only consulted when a rebuild is needed.

- [ ] **Step 1: Write the failing tests**

`internal/api/api_test.go`:

```go
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fernando/pqtrust/internal/ca"
	"github.com/fernando/pqtrust/internal/keystore"
	"github.com/fernando/pqtrust/internal/pqx509"
	"github.com/fernando/pqtrust/internal/store"
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
	t.Cleanup(func() { st.Close() })
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

	// List CAs.
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

	// Get the intermediate with its chain.
	rec = h.do(t, http.MethodGet, "/v1/ca/"+interID, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get CA = %d %s", rec.Code, rec.Body.String())
	}
	var caOut map[string]any
	decode(t, rec, &caOut)
	if strings.Count(caOut["chain_pem"].(string), "BEGIN CERTIFICATE") != 2 {
		t.Error("intermediate chain must contain two certificates")
	}

	// Issue.
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
		Serial        string `json:"serial"`
		CertificatePEM string `json:"certificate_pem"`
		ChainPEM      string `json:"chain_pem"`
		PrivateKeyPEM string `json:"private_key_pem"`
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

	// Fetch it back.
	rec = h.do(t, http.MethodGet, "/v1/certificates/"+issued.Serial, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get certificate = %d %s", rec.Code, rec.Body.String())
	}
	var fetched map[string]any
	decode(t, rec, &fetched)
	if fetched["status"] != "valid" || fetched["subject_dn"] != "CN=api.example.com" {
		t.Errorf("fetched = %v", fetched)
	}

	// CRL before revocation: empty but parseable.
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

	// Revoke.
	rec = h.do(t, http.MethodPost, "/v1/certificates/"+issued.Serial+"/revoke", map[string]any{"reason": 1}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke = %d %s", rec.Code, rec.Body.String())
	}
	var revoked map[string]any
	decode(t, rec, &revoked)
	if revoked["status"] != "revoked" || revoked["reason"] != float64(1) {
		t.Errorf("revoke response = %v", revoked)
	}

	// Revoking again is a 409.
	rec = h.do(t, http.MethodPost, "/v1/certificates/"+issued.Serial+"/revoke", map[string]any{"reason": 1}, nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("second revoke = %d %s", rec.Code, rec.Body.String())
	}
	var p map[string]any
	decode(t, rec, &p)
	if p["type"] != "urn:pqtrust:error:conflict" {
		t.Errorf("problem type = %v", p["type"])
	}

	// CRL now lists the serial, in PEM on request.
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
	if HashToken(a) != HashToken(a) {
		t.Error("HashToken must be deterministic")
	}
}
```

- [ ] **Step 2: Run and confirm failure**

Run: `CGO_ENABLED=0 go test ./internal/api/ -v`
Expected: compile failure.

- [ ] **Step 3: Implement `problem.go`**

```go
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
```

- [ ] **Step 4: Implement `auth.go`**

```go
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
```

- [ ] **Step 5: Implement `server.go`**

```go
package api

import (
	"fmt"
	"net/http"

	"github.com/fernando/pqtrust/internal/ca"
	"github.com/fernando/pqtrust/internal/store"
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
		"POST /v1/ca":                              s.handleCreateCA,
		"GET /v1/ca":                               s.handleListCAs,
		"GET /v1/ca/{id}":                          s.handleGetCA,
		"GET /v1/ca/{id}/crl":                      s.handleGetCRL,
		"POST /v1/certificates":                    s.handleIssueCertificate,
		"GET /v1/certificates/{serial}":            s.handleGetCertificate,
		"POST /v1/certificates/{serial}/revoke":    s.handleRevoke,
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
```

Note: `http.ServeMux` answers unmatched methods on a known path with 405 and unknown paths with 404 automatically, which is what the tests assert. Those two responses are plain text rather than problem+json; that is acceptable and worth one line in LIMITATIONS.md.

- [ ] **Step 6: Implement `handlers_misc.go`**

```go
package api

import (
	"net/http"

	"github.com/fernando/pqtrust/internal/version"
)

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"version": version.Version,
	})
}
```

- [ ] **Step 7: Implement `handlers_ca.go`**

```go
package api

import (
	"net/http"
	"time"

	"github.com/fernando/pqtrust/internal/ca"
	"github.com/fernando/pqtrust/internal/pqx509"
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
		_, _ = w.Write(pqx509.EncodeCRLPEM(der))
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(der)
}
```

- [ ] **Step 8: Implement `handlers_certs.go`**

```go
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
```

- [ ] **Step 9: Run the tests and confirm they pass**

Run: `CGO_ENABLED=0 go test ./internal/api/ -v`
Expected: PASS.

Watch for these:
- `decodeJSON` uses `DisallowUnknownFields`, so every field the tests send must exist in the request struct. If a test 400s unexpectedly, add the missing field rather than dropping the strictness.
- `handleGetCertificate` must lowercase the serial (the engine already does) so `GET /v1/certificates/0A1B` works.

- [ ] **Step 10: Commit**

```bash
git add internal/api
git commit -m "feat(api): REST handlers with bearer auth and RFC 7807 problem responses"
```

---

### Task 13: pqtrustd — daemon and token subcommand

**Files:**
- Create: `cmd/pqtrustd/main.go`, `cmd/pqtrustd/serve.go`, `cmd/pqtrustd/token.go`, `cmd/pqtrustd/selfsigned.go`
- Test: `cmd/pqtrustd/main_test.go`

**Interfaces:**
- Consumes: `config`, `store`, `keystore`, `ca`, `api`, `version`.
- Produces: the `pqtrustd` binary with two subcommands:
  - `pqtrustd serve [-config path]` — opens the store and keystore, builds the engine and API, serves TLS with Go's default (hybrid X25519MLKEM768) curve preferences, shuts down gracefully on SIGINT/SIGTERM.
  - `pqtrustd token create -name <name> [-config path]` — prints a new token once and stores its hash.
  - `pqtrustd version` — prints the version.
- `func selfSignedTLSCert(hostname string) (tls.Certificate, error)` — ECDSA P-256, 1-year validity, SAN for hostname plus `127.0.0.1` and `::1`.

- [ ] **Step 1: Write the failing test**

`cmd/pqtrustd/main_test.go`:

```go
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
```

- [ ] **Step 2: Run and confirm failure**

Run: `CGO_ENABLED=0 go test ./cmd/pqtrustd/ -v`
Expected: compile failure.

- [ ] **Step 3: Implement `selfsigned.go`**

```go
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"time"
)

// selfSignedTLSCert builds an ephemeral ECDSA P-256 certificate for the API
// listener. The transport certificate is classical because crypto/tls cannot
// yet parse ML-DSA certificates; the key exchange is still hybrid PQ.
func selfSignedTLSCert(hostname string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("pqtrustd: generating TLS key: %w", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 127)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("pqtrustd: generating TLS serial: %w", err)
	}
	if hostname == "" {
		hostname = "localhost"
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: hostname, Organization: []string{"pqtrust"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{hostname},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	if hostname != "localhost" {
		tmpl.DNSNames = append(tmpl.DNSNames, "localhost")
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("pqtrustd: creating TLS certificate: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
```

- [ ] **Step 4: Implement `serve.go`**

```go
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
```

- [ ] **Step 5: Implement `token.go` and `main.go`**

`cmd/pqtrustd/token.go`:

```go
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/fernando/pqtrust/internal/api"
	"github.com/fernando/pqtrust/internal/keystore"
	"github.com/fernando/pqtrust/internal/store"
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
```

`cmd/pqtrustd/main.go`:

```go
// Command pqtrustd is the pqtrust certificate authority daemon.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/fernando/pqtrust/internal/version"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "pqtrustd:", err)
		os.Exit(1)
	}
}

func usage() string {
	return `usage: pqtrustd <command> [flags]

commands:
  serve                 run the certificate authority API server
  token create -name X  mint an API token (printed once)
  version               print the pqtrust version

flags:
  -config path          configuration file (default: none, built-in defaults)
`
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Print(usage())
		return fmt.Errorf("a command is required")
	}
	switch args[0] {
	case "serve":
		fs := flag.NewFlagSet("serve", flag.ContinueOnError)
		configPath := fs.String("config", "", "path to config.yaml")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return serve(ctx, *configPath)

	case "token":
		if len(args) < 2 || args[1] != "create" {
			return fmt.Errorf("usage: pqtrustd token create -name <name>")
		}
		fs := flag.NewFlagSet("token create", flag.ContinueOnError)
		configPath := fs.String("config", "", "path to config.yaml")
		name := fs.String("name", "", "human-readable token name")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		return runTokenCreate(*configPath, *name, os.Stdout)

	case "version":
		fmt.Println(version.Version)
		return nil

	default:
		fmt.Print(usage())
		return fmt.Errorf("unknown command %q", args[0])
	}
}
```

- [ ] **Step 6: Run the tests and confirm they pass**

Run: `CGO_ENABLED=0 go test ./cmd/pqtrustd/ -v`
Expected: PASS, including the `X25519MLKEM768` assertion. If that assertion fails, check the Go version (`go version` must be ≥ 1.24) and make sure `tls.Config.CurvePreferences` is left unset.

- [ ] **Step 7: Build and smoke-test the binary by hand**

```bash
make build
mkdir -p /tmp/pqtrust-demo
cat > /tmp/pqtrust-demo/config.yaml <<'EOF'
server:
  listen: "127.0.0.1:8443"
  tls:
    auto_self_signed: true
    hostname: localhost
database:
  path: /tmp/pqtrust-demo/pqtrust.db
keystore:
  dir: /tmp/pqtrust-demo/keys
EOF
./bin/pqtrustd version
TOKEN=$(./bin/pqtrustd token create -config /tmp/pqtrust-demo/config.yaml -name demo)
./bin/pqtrustd serve -config /tmp/pqtrust-demo/config.yaml &
sleep 1
curl -sk https://127.0.0.1:8443/v1/health
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:8443/v1/ca
kill %1
```

Expected: `{"status":"ok","version":"0.1.0-dev"}` then `{"cas":[]}`.

- [ ] **Step 8: Commit**

```bash
git add cmd/pqtrustd
git commit -m "feat(pqtrustd): serve and token subcommands with hybrid post-quantum TLS"
```

---

### Task 14: CI and the OpenSSL 3.5 interop proof

**Files:**
- Create: `scripts/interop.sh`, `.github/workflows/ci.yml`, `.github/workflows/interop.yml`

**Interfaces:**
- Consumes: the `pqtrustd` binary and the API from Tasks 12–13.
- Produces: `scripts/interop.sh`, runnable locally and in CI, which starts pqtrustd, issues a chain, and has OpenSSL 3.5 verify it. This is the spec's headline success criterion (§13.1).

- [ ] **Step 1: Write the interop script**

`scripts/interop.sh`:

```bash
#!/usr/bin/env bash
# Proves third-party interoperability: OpenSSL 3.5+ must parse and verify a
# certificate chain issued by pqtrust. Run locally or from CI.
set -euo pipefail

work="$(mktemp -d)"
trap 'kill "${PID:-}" 2>/dev/null || true; rm -rf "$work"' EXIT

echo "== OpenSSL version =="
openssl version
if ! openssl version | grep -Eq 'OpenSSL 3\.(5|[6-9]|[1-9][0-9])'; then
	echo "FAIL: OpenSSL 3.5 or newer is required for ML-DSA support" >&2
	exit 1
fi

echo "== building pqtrustd =="
CGO_ENABLED=0 go build -o "$work/pqtrustd" ./cmd/pqtrustd

cat > "$work/config.yaml" <<EOF
server:
  listen: "127.0.0.1:18443"
  tls:
    auto_self_signed: true
    hostname: localhost
database:
  path: $work/pqtrust.db
keystore:
  dir: $work/keys
EOF

pass="interop-passphrase"
token="$("$work/pqtrustd" token create -config "$work/config.yaml" -name interop)"

"$work/pqtrustd" serve -config "$work/config.yaml" &
PID=$!

base="https://127.0.0.1:18443"
for _ in $(seq 1 100); do
	if curl -sk "$base/v1/health" >/dev/null 2>&1; then break; fi
	sleep 0.1
done
curl -fsk "$base/v1/health" >/dev/null

api() {
	curl -fsk -H "Authorization: Bearer $token" -H 'Content-Type: application/json' "$@"
}

echo "== creating the root CA =="
root_id="$(api -X POST "$base/v1/ca" -d "{
	\"name\":\"Interop Root\",
	\"algorithm\":\"ML-DSA-87\",
	\"subject\":{\"common_name\":\"pqtrust Interop Root CA\",\"organization\":[\"pqtrust\"]},
	\"passphrase\":\"$pass\"
}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"

echo "== creating the intermediate CA =="
inter_json="$(api -X POST "$base/v1/ca" -d "{
	\"name\":\"Interop Issuing\",
	\"parent_id\":\"$root_id\",
	\"algorithm\":\"ML-DSA-65\",
	\"subject\":{\"common_name\":\"pqtrust Interop Issuing CA\",\"organization\":[\"pqtrust\"]},
	\"passphrase\":\"$pass\",
	\"parent_passphrase\":\"$pass\"
}")"
inter_id="$(printf '%s' "$inter_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"

echo "== issuing an end-entity certificate =="
api -X POST "$base/v1/certificates" -d "{
	\"ca_id\":\"$inter_id\",
	\"passphrase\":\"$pass\",
	\"subject\":{\"common_name\":\"interop.example.com\"},
	\"dns_names\":[\"interop.example.com\"]
}" > "$work/issued.json"

# Split the returned chain into leaf, intermediate and root PEM files.
WORK="$work" python3 - <<'PY'
import json, os, re
work = os.environ["WORK"]
d = json.load(open(os.path.join(work, "issued.json")))
open(os.path.join(work, "serial.txt"), "w").write(d["serial"])
blocks = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----\n", d["chain_pem"], re.S)
assert len(blocks) == 3, f"expected 3 certificates in the chain, got {len(blocks)}"
for name, block in zip(["leaf.pem", "intermediate.pem", "root.pem"], blocks):
    open(os.path.join(work, name), "w").write(block)
PY

echo "== openssl x509 -text must parse our ML-DSA certificates =="
for f in leaf intermediate root; do
	echo "--- $f ---"
	openssl x509 -in "$work/$f.pem" -noout -text | head -20
	openssl x509 -in "$work/$f.pem" -noout -text | grep -q 'ML-DSA' \
		|| { echo "FAIL: openssl did not report an ML-DSA algorithm for $f" >&2; exit 1; }
done

echo "== openssl verify must accept the chain =="
openssl verify -CAfile "$work/root.pem" -untrusted "$work/intermediate.pem" "$work/leaf.pem"

echo "== revoke, then verify the CRL with openssl =="
serial="$(cat "$work/serial.txt")"
api -X POST "$base/v1/certificates/$serial/revoke" -d '{"reason":1}' >/dev/null
curl -fsk -H "Authorization: Bearer $token" -H "X-PQTrust-Passphrase: $pass" \
	-H 'Accept: application/x-pem-file' "$base/v1/ca/$inter_id/crl" -o "$work/crl.pem"
openssl crl -in "$work/crl.pem" -noout -text | head -20
openssl crl -in "$work/crl.pem" -noout -text | grep -qi "$serial" \
	|| { echo "FAIL: the revoked serial is not on the CRL according to openssl" >&2; exit 1; }
openssl crl -in "$work/crl.pem" -CAfile "$work/intermediate.pem" -noout -verify

echo "== our parser must read an OpenSSL-generated ML-DSA certificate =="
openssl req -x509 -newkey ml-dsa-65 -keyout "$work/ossl.key" -out "$work/ossl.pem" \
	-days 30 -nodes -subj "/CN=openssl-generated"
CGO_ENABLED=0 go run ./scripts/parsecert "$work/ossl.pem"

echo "ALL INTEROP CHECKS PASSED"
```

The script needs a tiny helper program to exercise our parser from the shell. Create `scripts/parsecert/main.go`:

```go
// Command parsecert parses a PEM certificate with pqtrust's own X.509 layer.
// It exists so that the interop script can prove we read third-party output.
package main

import (
	"fmt"
	"os"

	"github.com/fernando/pqtrust/internal/pqx509"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: parsecert <certificate.pem>")
		os.Exit(2)
	}
	pemBytes, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "parsecert:", err)
		os.Exit(1)
	}
	der, err := pqx509.DecodeCertificatePEM(pemBytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "parsecert:", err)
		os.Exit(1)
	}
	cert, err := pqx509.ParseCertificate(der)
	if err != nil {
		fmt.Fprintln(os.Stderr, "parsecert:", err)
		os.Exit(1)
	}
	fmt.Printf("parsed %s certificate: subject=%q issuer=%q serial=%s notAfter=%s\n",
		cert.SignatureAlgorithm, cert.Subject, cert.Issuer, cert.SerialNumber.Text(16), cert.NotAfter)
	if cert.IsSelfSigned() {
		if err := cert.VerifySignatureFrom(cert); err != nil {
			fmt.Fprintln(os.Stderr, "parsecert: self-signature does not verify:", err)
			os.Exit(1)
		}
		fmt.Println("self-signature verified")
	}
}
```

- [ ] **Step 2: Make the script executable**

```bash
chmod +x scripts/interop.sh
```

- [ ] **Step 3: Run the interop script locally if OpenSSL 3.5 is available**

```bash
openssl version
./scripts/interop.sh
```

Expected: `ALL INTEROP CHECKS PASSED`. If the local OpenSSL is older than 3.5, the script exits early with a clear message — that is fine; CI provides 3.5. Optionally run it in a container:

```bash
docker run --rm -v "$PWD:/src" -w /src golang:1.24-alpine sh -c \
	'apk add --no-cache openssl curl python3 bash && openssl version && ./scripts/interop.sh'
```

Check that the image's OpenSSL is ≥ 3.5 before trusting a pass; if it is older, use `alpine:edge` or build OpenSSL 3.5 from source in the container.

- [ ] **Step 4: Add the CI workflow**

`.github/workflows/ci.yml`:

```yaml
name: ci

on:
  push:
    branches: [main]
  pull_request:

env:
  CGO_ENABLED: "0"

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.24"
          check-latest: true
      - name: Fetch ACVP vectors
        run: ./scripts/fetch-acvp.sh
      - name: Test
        run: go test ./... -count=1
      - name: Test with the race detector
        env:
          CGO_ENABLED: "1"
        run: go test -race ./... -count=1
      - name: Coverage for pqx509
        run: |
          go test ./internal/pqx509/ -count=1 -coverprofile=coverage.out
          go tool cover -func=coverage.out | tail -n 1
          pct=$(go tool cover -func=coverage.out | tail -n 1 | awk '{print $3}' | tr -d '%')
          awk -v p="$pct" 'BEGIN { if (p+0 < 80) { print "coverage " p "% is below the 80% target"; exit 1 } }'

  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.24"
      - uses: golangci/golangci-lint-action@v6
        with:
          version: latest

  vuln:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.24"
      - run: go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

- [ ] **Step 5: Add the interop workflow**

`.github/workflows/interop.yml`:

```yaml
name: interop

on:
  push:
    branches: [main]
  pull_request:

jobs:
  openssl:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.24"
          check-latest: true
      - name: Install OpenSSL 3.5
        run: |
          set -euo pipefail
          # Ubuntu runners ship OpenSSL 3.0/3.4 without ML-DSA; build 3.5.
          version=3.5.0
          curl -fsSLO "https://github.com/openssl/openssl/releases/download/openssl-${version}/openssl-${version}.tar.gz"
          tar xzf "openssl-${version}.tar.gz"
          cd "openssl-${version}"
          ./Configure --prefix=/opt/openssl35 --openssldir=/opt/openssl35/ssl
          make -j"$(nproc)"
          sudo make install_sw
          echo "/opt/openssl35/bin" >> "$GITHUB_PATH"
      - name: Verify the OpenSSL version
        run: openssl version
      - name: Interop
        run: ./scripts/interop.sh
```

If the 3.5.0 tarball URL 404s, list the available releases (`curl -fsSL https://api.github.com/repos/openssl/openssl/releases | grep tag_name | head`) and pin the newest `openssl-3.5.x`. Do not silently fall back to an older OpenSSL — the whole point of this job is a 3.5+ third-party verifier.

- [ ] **Step 6: Commit**

```bash
git add scripts/interop.sh scripts/parsecert .github/workflows
git commit -m "ci: test, lint, vuln workflows and an OpenSSL 3.5 interoperability proof"
```

---

### Task 15: Documentation

**Files:**
- Create: `README.md`, `LIMITATIONS.md`, `SECURITY.md`, `config.example.yaml`

**Interfaces:**
- Consumes: the finished API and binary.
- Produces: a copy-paste demo that a reader can run in under five minutes (spec §13.2) and an honest limitations document that doubles as the commercial-tier map (spec §13.4).

- [ ] **Step 1: Write `config.example.yaml`**

```yaml
# pqtrust daemon configuration. Every key can be overridden by an environment
# variable; see the table in README.md.
server:
  listen: ":8443"
  tls:
    # Generate an ephemeral ECDSA P-256 certificate at startup. The key exchange
    # is hybrid post-quantum (X25519MLKEM768) regardless of this setting.
    auto_self_signed: true
    hostname: "localhost"
    # cert_file: /etc/pqtrust/tls/cert.pem
    # key_file: /etc/pqtrust/tls/key.pem

database:
  path: "/var/lib/pqtrust/pqtrust.db"

keystore:
  dir: "/var/lib/pqtrust/keys"

issuance:
  max_validity_days: 397
  crl_validity_hours: 168
```

- [ ] **Step 2: Write `README.md`**

It must contain, in this order:
1. One-paragraph description: self-hosted post-quantum certificate authority in Go, issuing ML-DSA (FIPS 204) X.509 certificates, with its own `pqx509` layer because `crypto/x509` rejects PQC signature OIDs.
2. Status badge placeholders for the `ci` and `interop` workflows.
3. **Why** section: NIST finalized FIPS 203/204/205 in August 2024; organizations need PQ-capable PKI to test migration; accessible Go tooling barely exists.
4. **Architecture** diagram as an ASCII/Mermaid block showing `api → ca → {pqx509, keystore, store}` with `config` feeding `cmd/pqtrustd`, and a one-line responsibility per package (copy from the plan's File Structure table).
5. **Five-minute demo**, verbatim runnable:

````markdown
```bash
# 1. Build
git clone https://github.com/fgpelaez/pqtrust && cd pqtrust
make build

# 2. Configure
mkdir -p /tmp/pqtrust && sed \
  -e 's#/var/lib/pqtrust/pqtrust.db#/tmp/pqtrust/pqtrust.db#' \
  -e 's#/var/lib/pqtrust/keys#/tmp/pqtrust/keys#' \
  config.example.yaml > /tmp/pqtrust/config.yaml

# 3. Mint an API token (printed once)
export PQTRUST_TOKEN=$(./bin/pqtrustd token create -config /tmp/pqtrust/config.yaml -name demo)

# 4. Start the daemon
./bin/pqtrustd serve -config /tmp/pqtrust/config.yaml &

# 5. Create a root CA (ML-DSA-87) and an intermediate (ML-DSA-65)
export PASS='demo-passphrase'
ROOT=$(curl -sk -H "Authorization: Bearer $PQTRUST_TOKEN" -H 'Content-Type: application/json' \
  -X POST https://127.0.0.1:8443/v1/ca -d "{
    \"name\":\"Demo Root\",\"algorithm\":\"ML-DSA-87\",
    \"subject\":{\"common_name\":\"Demo Root CA\",\"organization\":[\"pqtrust\"]},
    \"passphrase\":\"$PASS\"}" | jq -r .id)

INTER=$(curl -sk -H "Authorization: Bearer $PQTRUST_TOKEN" -H 'Content-Type: application/json' \
  -X POST https://127.0.0.1:8443/v1/ca -d "{
    \"name\":\"Demo Issuing\",\"parent_id\":\"$ROOT\",\"algorithm\":\"ML-DSA-65\",
    \"subject\":{\"common_name\":\"Demo Issuing CA\"},
    \"passphrase\":\"$PASS\",\"parent_passphrase\":\"$PASS\"}" | jq -r .id)

# 6. Issue an end-entity certificate (ML-DSA-44)
curl -sk -H "Authorization: Bearer $PQTRUST_TOKEN" -H 'Content-Type: application/json' \
  -X POST https://127.0.0.1:8443/v1/certificates -d "{
    \"ca_id\":\"$INTER\",\"passphrase\":\"$PASS\",
    \"subject\":{\"common_name\":\"api.example.com\"},
    \"dns_names\":[\"api.example.com\"]}" > /tmp/pqtrust/issued.json

jq -r .chain_pem /tmp/pqtrust/issued.json > /tmp/pqtrust/chain.pem

# 7. Verify with OpenSSL 3.5+ — third-party proof, not our own code
openssl x509 -in /tmp/pqtrust/chain.pem -noout -text | head -15
```
````

6. **API reference** table (the eight endpoints from Task 12) with the JSON shapes.
7. **Configuration** table: YAML key, environment variable, default.
8. **Development**: `make test`, `make lint`, `make cover`, `./scripts/fetch-acvp.sh`, `./scripts/interop.sh`.
9. **License**: AGPL-3.0, with the one-paragraph rationale from spec §11.
10. Links to `LIMITATIONS.md` and `SECURITY.md`.

- [ ] **Step 3: Write `LIMITATIONS.md`**

Every entry below must appear, phrased honestly, each with a one-line "what a production deployment needs" note where applicable:

- The API's own TLS **server certificate is classical** (ECDSA P-256) because Go's `crypto/tls` cannot parse ML-DSA certificates. The key exchange is hybrid post-quantum (X25519MLKEM768), which is what defeats harvest-now-decrypt-later. Revisited in Phase 2.
- **No CSR flow yet**: keys are generated server-side. PKCS#10 arrives in Phase 2. The returned private key PEM is a **pqtrust-specific format** (`PQTRUST ML-DSA PRIVATE KEY`, a raw 32-byte seed) because PKCS#8 encoding for ML-DSA lands with the Phase 2 CSR work.
- **Stored end-entity keys** (`store_key: true`) are sealed with the same passphrase used to unlock the issuing CA. Separate per-key passphrases are a Phase 2 item.
- **No HSM/PKCS#11**: `keystore.Backend` is an interface, but only the file backend exists. → commercial tier.
- **No RA, approval workflow, ACME, EST or SCEP**; the API issues immediately on an authenticated request. → commercial tier.
- **No Certificate Transparency**, no OCSP responder. CRLs only.
- **Unsupported X.509 features**: name constraints, certificate policies, policy mapping, inhibit anyPolicy. Certificates presenting these as **critical** are rejected outright.
- **Path validation** implements signatures, validity, name chaining, basicConstraints and CA keyUsage only; revocation is checked through the `CheckRevocation` hook, not inside `Verify`.
- **CRLDistributionPoints** is not emitted in Phase 1, so relying parties must fetch CRLs out of band from `GET /v1/ca/{id}/crl`.
- **Single node, single SQLite file**; no clustering, no replication, no multi-tenancy. → commercial tier.
- **No audit log and no metrics**; issuance and revocation are the natural hooks. → commercial tier.
- **404 and 405 responses** from unmatched routes are plain text from `http.ServeMux`, not `problem+json`.
- **Passphrases travel in request bodies and one header** over TLS and are never stored; there is no session or key-caching layer, so every issuance costs one Argon2id derivation (~50–100 ms at 64 MiB).
- **The root CA is only "offline-capable"**: nothing enforces air-gapping. Operating the root offline is a procedure, not a feature.

Close with a table mirroring spec §11.1 (open vs. future commercial tier).

- [ ] **Step 4: Write `SECURITY.md`**

Must state:
- Supported version: `main` only, pre-1.0.
- How to report: a private disclosure channel (GitHub Security Advisories on this repository), 90-day coordinated disclosure, no bug bounty.
- Explicit **not-yet-production** warning: pqtrust has not been audited; do not use it as a trust anchor for anything you cannot afford to reissue.
- Cryptographic posture: ML-DSA via CIRCL, keys sealed with AES-256-GCM under Argon2id (t=3, m=64 MiB, p=2), hybrid PQ TLS key exchange, tokens stored as SHA-256 hashes.
- Operator responsibilities: protect the keystore directory (0700) and the SQLite file, keep the root passphrase offline, rotate API tokens, back up `pqtrust.db` and `keys/` together (a backup of one without the other is useless).

- [ ] **Step 5: Verify the README demo end to end**

Run the demo block exactly as written, from a clean `/tmp/pqtrust`, and fix any command that does not work. This is a hard gate: the spec's success criterion is a demo *anyone* can run.

```bash
rm -rf /tmp/pqtrust
# ... paste and run every command from the README demo ...
```

Expected: step 7 prints an ML-DSA certificate. Note `jq` is a prerequisite — say so in the README.

- [ ] **Step 6: Final full verification**

```bash
make test
make lint
make cover
CGO_ENABLED=0 go build ./...
```

Expected: all green; `pqx509` coverage ≥ 80%.

- [ ] **Step 7: Commit**

```bash
git add README.md LIMITATIONS.md SECURITY.md config.example.yaml
git commit -m "docs: README with a five-minute demo, honest LIMITATIONS and SECURITY policy"
```

---

## Self-Review Notes

Checked against the spec, section by section:

| Spec section | Covered by |
|---|---|
| §2 goals: two-level hierarchy | Task 11 (profiles enforce root → intermediate → leaf) |
| §2 goals: interoperable DER | Tasks 4, 6, 14 (OpenSSL 3.5 verify) |
| §2 goals: REST + bearer auth over hybrid TLS | Tasks 12, 13 |
| §2 goals: revocation + CRL | Tasks 6, 11, 12 |
| §2 goals: single static binary, pure Go, SQLite | Tasks 0, 9, 13 (`CGO_ENABLED=0` everywhere) |
| §2 goals: ACVP, DER round-trips, path validation, OpenSSL CI | Tasks 4, 5, 7, 14 |
| §3 technology choices | Tasks 0, 1, 8, 9, 13 |
| §4 architecture / unit responsibilities | File Structure table; one task per package |
| §5.1 algorithms and OIDs, encoding rules | Task 1 (tests assert absent parameters and raw SPKI) |
| §5.2 hierarchy, constraints, serials, SKID/AKID | Tasks 1, 4, 11 |
| §5.3 key storage, Argon2id, `store_key`, Backend interface | Task 8, Task 11 |
| §5.4 transport | Task 13 (X25519MLKEM768 asserted in a test) |
| §6.1 pqx509 surface | Tasks 1, 4, 5, 6 (`CertificateRequest` deferred to Phase 2 per §6.1) |
| §6.2 supported extensions, critical-unknown rejection | Task 3, Task 4 |
| §6.3 path validation scope | Task 5 |
| §7 REST API, all eight endpoints, issuance/revocation flows, tokens | Tasks 12, 13 |
| §8 data model, migrations at startup | Task 9 |
| §9 error handling, sentinels, problem+json mapping, strictness | Tasks 1, 5, 8, 9, 11, 12 |
| §10 testing strategy, every row | Tasks 4–9, 11–14 |
| §11 deployment, AGPL, README/SECURITY/CI | Tasks 0, 14, 15 |
| §11.1 open-core boundary constraints | `/v1` versioning (Task 12), `keystore.Backend` (Task 8), all state via `store` (Task 9), LIMITATIONS table (Task 15) |
| §12 Phase 1 exit criteria | Task 14 (OpenSSL verifies in CI) + Task 15 (curl demo) |
| §13 success criteria | Tasks 14, 15; coverage gate in CI |

Deliberately deferred (spec §12 Phase 2/3, not gaps): PKCS#10 `CertificateRequest`, `cmd/pqtrust` CLI, SLH-DSA, composite certificates, CRLDistributionPoints, Dockerfile and compose, dashboard, OCSP, metrics.

Known consistency decisions locked in across tasks:
- `pqx509.Certificate` is the single certificate type; `ca` and `api` never build DER themselves.
- Serial numbers are lowercase hexadecimal strings at every boundary above `pqx509` (`ca.SerialHex`), and `*big.Int` inside it.
- Passphrases are `[]byte` everywhere below `api`, `string` only in JSON.
- `ca.ErrNotFound` wraps `store.ErrNotFound`, so `api` matches on the `ca` sentinel alone.
- `Options.Now` is the only clock; no package calls `time.Now` directly except `cmd` and `api` token creation.
