# pqtrust — Post-Quantum PKI-as-a-Service

**Date:** 2026-08-16
**Status:** Approved
**Goal:** Dual — (1) professional portfolio piece demonstrating PQC engineering depth
(X.509 internals, FIPS 204/205, service design); (2) a foundation that can be
commercialized later as an open-core product (self-hosted PQC CA today, enterprise
features as paid tiers tomorrow).

## 1. Overview

pqtrust is a self-contained certificate authority (CA) service, written in Go, that issues
post-quantum X.509 certificates (ML-DSA per FIPS 204, SLH-DSA per FIPS 205 in Phase 2).
It exposes a REST API for managing a two-level CA hierarchy, issuing and revoking
end-entity certificates, and publishing CRLs.

The technical centerpiece is `internal/pqx509`: a from-scratch X.509 layer that builds,
parses, and verifies certificates carrying PQC signature algorithms — work that Go's
`crypto/x509` cannot do, since it rejects unknown signature algorithm OIDs.

**Why this matters:** NIST finalized FIPS 203/204/205 in August 2024. Organizations must
stand up PQ-capable PKI before they can even test migration. Accessible, open tooling for
PQC certificate issuance in Go barely exists.

## 2. Goals and non-goals

### Goals

- Two-level hierarchy: offline-capable root CA, online intermediate CA, end-entity issuance.
- Correct, interoperable DER output — verifiable by third-party tooling (OpenSSL 3.5+).
- REST API with bearer-token authentication, served over hybrid post-quantum TLS.
- Revocation with CRL publication (RFC 5280 §5).
- Single static binary; pure-Go dependencies; SQLite persistence (no cgo).
- Test suite proving correctness: NIST ACVP vectors, DER round-trips, path validation,
  and an OpenSSL interop job in CI.

### Non-goals (YAGNI)

- RA/enrollment approval workflows, ACME, EST, SCEP.
- Certificate Transparency logging.
- Real HSM/PKCS#11 integration (keystore interface leaves the door open).
- Name constraints, certificate policies beyond basic marking, policy mapping,
  inhibit anyPolicy (rejected if critical; documented as unsupported).
- Web dashboard, OCSP responder (Phase 3 stretch only).

## 3. Technology choices

| Decision | Choice | Rationale |
|---|---|---|
| Language | Go 1.24+ (developed against latest stable) | `crypto/mlkem` in stdlib; native hybrid TLS; single-binary deploys |
| PQC signatures | `github.com/cloudflare/circl/sign/mldsa`, `.../slhdsa` | Pure Go, FIPS 204/205 final versions, actively maintained |
| PQC KEM (transport) | Go stdlib `crypto/mlkem` + `crypto/tls` | X25519MLKEM768 negotiated by default since Go 1.24 |
| X.509 layer | Own package (`internal/pqx509`) on `encoding/asn1` | Go's `crypto/x509` rejects PQC signature OIDs |
| Database | SQLite via `modernc.org/sqlite` | Pure Go, zero ops, embedded |
| HTTP | stdlib `net/http` with Go 1.22+ method-pattern ServeMux | No framework dependency |
| Key encryption at rest | AES-256-GCM, wrapping key via Argon2id (`golang.org/x/crypto`) | Strong default, passphrase-operated |

## 4. Architecture

```
pqtrust/
├── cmd/
│   ├── pqtrustd/            # CA daemon binary (REST API server; also `token create` subcommand)
│   └── pqtrust/             # CLI client (added in Phase 2)
├── internal/
│   ├── pqx509/              # X.509 DER build/parse/verify for PQC algorithms (no I/O, no state)
│   ├── ca/                  # CA engine: hierarchy rules, issuance profiles, revocation, CRL
│   ├── keystore/            # key generation + AES-256-GCM sealed private key storage
│   ├── api/                 # HTTP handlers, authn middleware, problem+json errors
│   ├── store/               # SQLite persistence: CAs, certificates, revocation state, API tokens
│   └── config/              # YAML/env configuration loading and validation
├── testdata/                # ACVP vectors, golden DER fixtures
└── docs/
```

**Unit responsibilities** (each independently testable, depending only on the units below it):

- `pqx509`: pure functions and types. `Certificate`, `CreateCertificate`, `ParseCertificate`,
  `CreateCRL`, `ParseCRL`, `Verify` (path validation), `Signer` interface. No disk, no network.
- `ca`: domain logic. Decides *what* may be issued (profiles, constraints), uses `pqx509`
  to build/sign, `keystore` for keys, `store` for records.
- `keystore`: `Generate(alg)`, `Load(keyID, passphrase)` → unsealed signer; `Seal`/`Unseal`.
- `store`: CRUD over SQLite; transactions around issuance + revocation.
- `api`: request validation, authn, maps domain errors to RFC 7807; thin over `ca`.
- `config`: file + env loading, validation, defaults.

## 5. Cryptographic design

### 5.1 Algorithms and OIDs

| Use | Algorithm | OID (NIST CSOR) |
|---|---|---|
| Root CA signature | ML-DSA-87 | `2.16.840.1.101.3.4.3.19` |
| Intermediate CA signature | ML-DSA-65 | `2.16.840.1.101.3.4.3.18` |
| End-entity (default) | ML-DSA-44 | `2.16.840.1.101.3.4.3.17` |
| Phase 2 | SLH-DSA (12 parameter sets) | `2.16.840.1.101.3.4.3.20`–`.31` |

Encoding rules follow `draft-ietf-lamps-dilithium-certificates`: signature algorithm
`AlgorithmIdentifier.parameters` **absent**; public key placed raw in the SPKI BIT STRING;
pure-sign mode (no pre-hash).

Reference sizes (FIPS 204): ML-DSA-44 pk 1312 B / sig 2420 B; ML-DSA-65 pk 1952 B / sig
3309 B; ML-DSA-87 pk 2592 B / sig 4627 B; private keys handled as 32-byte seeds, expanded
by CIRCL.

### 5.2 Hierarchy and constraints

- **Root:** self-signed ML-DSA-87, `cA=TRUE, pathlen=1`, KU `keyCertSign|cRLSign`,
  validity 10 years. Passphrase required to unseal; intended to stay offline except when
  signing intermediates or CRLs.
- **Intermediate:** ML-DSA-65, signed by root, `cA=TRUE, pathlen=0`, KU
  `keyCertSign|cRLSign`, validity 5 years.
- **End-entity:** ML-DSA-44 (default) or ML-DSA-65, `cA=FALSE`, KU `digitalSignature`,
  EKU `serverAuth` and/or `clientAuth`, max validity 397 days (CA/B-forum-like hygiene).
- Serial numbers: 128-bit random positive integers (≤ 20 octets).
- SKID/AKID: RFC 7093 §2 method 1 (SHA-256 over SPKI BIT STRING, truncated to 160 bits).

### 5.3 Key storage

- CA and (optionally) end-entity private keys sealed with AES-256-GCM; nonce random
  96-bit; wrapping key = Argon2id(passphrase, salt, t=3, m=64 MiB, p=2, keyLen=32).
- End-entity keys are **not stored by default** (returned once in the issuance response);
  opt-in `store_key: true` stores them sealed.
- `keystore.Backend` interface allows a future HSM/PKCS#11 implementation.

### 5.4 Transport

The API is served over TLS with Go's default curve preferences (X25519MLKEM768 hybrid
key exchange — the property that defeats harvest-now-decrypt-later). The API's own server
certificate is classical (ECDSA P-256) because Go's `crypto/tls` cannot yet parse ML-DSA
certificates; documented limitation. Hybrid PQ client/server authentication is revisited
in Phase 2 alongside the composite-certificate work.

## 6. pqx509 package specification

### 6.1 Surface (Phase 1)

```go
type Algorithm int                       // MLDSA44, MLDSA65, MLDSA87 (+ SLH-DSA in P2)
type PublicKey / type PrivateKey         // algorithm-tagged key material
type Signer interface {                  // implemented by keystore-loaded keys
    Public() PublicKey
    Sign(rand io.Reader, msg []byte) (sig []byte, err error)
    Algorithm() Algorithm
}

type Certificate struct { /* TBSCertificate fields + SignatureAlgorithm + SignatureValue */ }
type CertificateRequest struct { /* Phase 2: PKCS#10 */ }
type RevocationList struct { /* RFC 5280 §5 */ }

func CreateCertificate(rand io.Reader, tmpl, parent *Certificate, pub PublicKey, signer Signer) (der []byte, err error)
func ParseCertificate(der []byte) (*Certificate, error)
func (c *Certificate) VerifySignatureFrom(parent *Certificate) error
func (c *Certificate) Verify(opts VerifyOptions) (chains [][]*Certificate, err error) // RFC 5280 §6, simplified
func CreateRevocationList(rand io.Reader, issuer *Certificate, signer Signer, entries []RevocationEntry, thisUpdate, nextUpdate time.Time) (der []byte, err error)
func ParseRevocationList(der []byte) (*RevocationList, error)
```

### 6.2 Supported extensions

BasicConstraints, KeyUsage, ExtKeyUsage, SubjectKeyId, AuthorityKeyId, SubjectAltName
(DNS/IP/email), CRLDistributionPoints (Phase 2). Any other extension marked **critical**
causes a hard parse/issuance error; non-critical unknown extensions are preserved on parse
but never emitted by issuance.

### 6.3 Path validation scope

Implemented: signature checks, validity window, name chaining, basicConstraints (cA flag,
pathlen), keyUsage for CA certs. Not implemented (explicit errors if required): policies,
name constraints, CRL-based revocation checking in `Verify` (a `CheckRevocation` hook on
`VerifyOptions` accepts a CRL fetcher instead).

## 7. REST API

Base path `/v1`, JSON bodies, `Authorization: Bearer <token>`, errors as
`application/problem+json` (RFC 7807) with per-endpoint `type` URNs.

| Method & path | Description |
|---|---|
| `POST /v1/ca` | Create root (`parent_id: null`) or intermediate CA. Body: name, algorithm, validity, `passphrase` (sent over TLS; used only to seal the generated key, never stored). |
| `GET /v1/ca` | List CAs (metadata only). |
| `GET /v1/ca/{id}` | CA details + certificate chain (PEM). |
| `POST /v1/certificates` | Issue end-entity cert. Body: `ca_id`, subject DN fields, SANs, algorithm, validity, `store_key`. Response: cert PEM, chain PEM, private key PEM (once, unless `store_key`). |
| `GET /v1/certificates/{serial}` | Fetch certificate (PEM + metadata). |
| `POST /v1/certificates/{serial}/revoke` | Revoke with RFC 5280 reason code. |
| `GET /v1/ca/{id}/crl` | Current CRL (DER or PEM via Accept header). |
| `GET /v1/health` | Liveness. |

**Issuance data flow:** `api` validates request → `ca` resolves issuing CA and checks
profile constraints → `keystore` unseals the CA key → `pqx509.CreateCertificate` → `store`
persists the certificate record transactionally → response assembled (cert, chain, key).

**Revocation flow:** `api` → `ca` marks record revoked in `store` → CRL regenerated lazily
on next `GET .../crl` (cached until next revocation or `nextUpdate`).

**Tokens:** stored as SHA-256 hashes; created via a `pqtrustd token create` CLI subcommand
(no auth bootstrap hole).

## 8. Data model (SQLite)

```sql
cas(id TEXT PK, name TEXT, parent_id TEXT NULL, algorithm TEXT, cert_pem TEXT,
    key_id TEXT, status TEXT, created_at TIMESTAMP);
certificates(serial TEXT PK, ca_id TEXT FK, subject_dn TEXT, sans TEXT,
             algorithm TEXT, cert_pem TEXT, key_id TEXT NULL, status TEXT,
             not_before TIMESTAMP, not_after TIMESTAMP,
             revoked_at TIMESTAMP NULL, revocation_reason INTEGER NULL);
tokens(id TEXT PK, name TEXT, token_hash TEXT, created_at TIMESTAMP);
```

Schema migrations via plain SQL files applied at startup (embedded `migrate` package,
no external tool).

## 9. Error handling

- Each package defines sentinel errors (`pqx509.ErrUnknownAlgorithm`,
  `ca.ErrConstraintViolation`, `store.ErrNotFound`, …); callers wrap with `%w`.
- `api` maps domain errors to problem+json: 400 (validation), 401 (auth), 404, 409
  (state conflict, e.g. already revoked), 422 (constraint violation), 500.
- Strictness rules: malformed DER, unknown critical extensions, algorithm/profile
  mismatches, and pathlen violations are always hard errors — never warnings.

## 10. Testing strategy

| Layer | Tests |
|---|---|
| `pqx509` | NIST ACVP ML-DSA sign/verify vectors; DER round-trip property tests (`Parse(Create(x)) == x`); golden-file DER fixtures; path-validation table tests (expired, wrong signer, pathlen exceeded, KU misuse, broken name chain) |
| `ca` | Profile/constraint enforcement; issuance + revocation lifecycle; CRL contents after revocation |
| `keystore` | Seal/unseal round-trip; wrong-passphrase failure; zeroization of unsealed material on close |
| `api` | `httptest` integration: full flows, authn failures, problem+json shapes |
| **Interop (CI)** | GitHub Actions job on an OpenSSL 3.5 image: `openssl verify -CAfile` against pqtrust-issued chains; `openssl x509 -text` parses our certs; our parser reads OpenSSL-generated ML-DSA certs |
| Meta | `golangci-lint`, `govulncheck`, race detector; target ≥ 80% coverage on `pqx509` |

## 11. Deployment, licensing & commercialization path

- Single static binary (`CGO_ENABLED=0`); config via `/etc/pqtrust/config.yaml` + env overrides.
- Multi-stage Dockerfile → `FROM scratch` (Phase 2), plus a compose demo (Phase 2).
- **License: AGPL-3.0.** Rationale: preserves the future open-core/commercial model —
  anyone can self-host and audit, but a cloud vendor cannot offer pqtrust as a competing
  managed service without releasing their changes; dual-licensing stays possible because
  there are no external contributors yet. (Easy to relax to Apache-2.0 later; hard to go
  the other way. Revisit at first public release.)
- README with architecture diagram and a copy-paste demo, SECURITY.md, CI: test / lint /
  vuln / interop.

### 11.1 Open-core boundary (future, not built now)

| Open (AGPL) | Future commercial tier |
|---|---|
| `pqx509`, CA engine, REST API, CLI, CRL, composite certs | HA/clustering, HSM/KMS backends, web dashboard, RA/approval workflows, audit logging, multi-tenancy, support/SLA |

Design constraints that keep the commercial path open **without adding scope now**:
API is versioned (`/v1`); `keystore.Backend` is already an interface; all state flows
through `store` so a multi-tenant schema (`tenant_id`) can be introduced later without
touching `pqx509` or `ca`; issuance/revocation events are the natural future hook for
audit logging and metering.

## 12. Phasing

| Phase | Scope | Exit criteria |
|---|---|---|
| **1** (weeks 1–3) | `pqx509` (ML-DSA), hierarchy, `store`, `keystore`, REST API, CRL, server-side keygen | OpenSSL 3.5 verifies a pqtrust-issued chain in CI; full issuance/revocation demo via curl |
| **2** (weeks 4–6) | PKCS#10 CSR flow, `pqtrust` CLI, SLH-DSA, composite (hybrid) certs per `draft-ietf-lamps-pq-composite-sigs`, Dockerfile + compose | End-to-end demo: CSR → cert → hybrid-TLS handshake |
| **3** (stretch) | Web dashboard, OCSP responder, Prometheus metrics, public write-up | — |

## 13. Success criteria

1. Third-party proof of correctness: OpenSSL interop job green on every commit.
2. A README demo anyone can run in under 5 minutes (portfolio + adoption funnel).
3. `pqx509` documented and tested well enough to stand alone technically
   (RFC 5280 + FIPS 204 fluency) and legally (clean AGPL licensing story).
4. Honest LIMITATIONS.md that doubles as the commercial tier's pitch: what a production
   deployment adds (HA, HSM, RA, audit, multi-tenancy) — each item already mapped to the
   open-core boundary in §11.1.
5. Nothing in the Phase 1 architecture forecloses the commercial tier (checked against
   the §11.1 constraints).
