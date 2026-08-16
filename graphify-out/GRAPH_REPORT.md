# Graph Report - pqtrust  (2026-08-16)

## Corpus Check
- cluster-only mode — file stats not available

## Summary
- 494 nodes · 1245 edges · 25 communities (21 shown, 4 thin omitted)
- Extraction: 80% EXTRACTED · 20% INFERRED · 0% AMBIGUOUS · INFERRED: 243 edges (avg confidence: 0.8)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `2ea0a512`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- context.Context
- testCA
- extensions.go
- testing.T
- net/http.ResponseWriter
- encoding/asn1.RawValue
- newApp
- CreateRevocationList
- pqtrust — Post-Quantum PKI-as-a-Service
- Seal
- time.Time
- Algorithm
- newHarness
- 2026-08-16-pqtrust-phase1.md
- Load
- AGENTS.md
- fetch-acvp.sh
- interop.sh
- Store
- github.com/fernando/pqtrust

## God Nodes (most connected - your core abstractions)
1. `testCA()` - 34 edges
2. `GenerateKey()` - 30 edges
3. `ParseCertificate()` - 28 edges
4. `Algorithm` - 28 edges
5. `CreateRevocationList()` - 26 edges
6. `ParseRevocationList()` - 20 edges
7. `CreateCertificate()` - 19 edges
8. `GenerateSerialNumber()` - 18 edges
9. `Certificate` - 18 edges
10. `Engine` - 17 edges

## Surprising Connections (you probably didn't know these)
- `runTokenCreate()` --calls--> `NewKeyID()`  [EXTRACTED]
  cmd/pqtrustd/token.go → internal/keystore/keystore.go
- `main()` --calls--> `ParseCertificate()`  [EXTRACTED]
  scripts/parsecert/main.go → internal/pqx509/certificate.go
- `runTokenCreate()` --calls--> `GenerateToken()`  [EXTRACTED]
  cmd/pqtrustd/token.go → internal/api/auth.go
- `runTokenCreate()` --calls--> `HashToken()`  [EXTRACTED]
  cmd/pqtrustd/token.go → internal/api/auth.go
- `app` --references--> `Config`  [EXTRACTED]
  cmd/pqtrustd/serve.go → internal/config/config.go

## Import Cycles
- None detected.

## Communities (25 total, 4 thin omitted)

### Community 0 - "context.Context"
Cohesion: 0.09
Nodes (27): IssueRequest, IssueResult, Options, context.Context, sync.Mutex, time.Duration, Engine, EncodePrivateKeyPEM() (+19 more)

### Community 1 - "testCA"
Cohesion: 0.11
Nodes (43): io.Reader, CreateCertificate(), GenerateSerialNumber(), ParseCertificate(), Certificate, testCA(), TestCreateCertificateValidation(), TestCreateEndEntityUnderCA() (+35 more)

### Community 2 - "extensions.go"
Cohesion: 0.08
Nodes (39): net.IP, buildExtensions(), Certificate, Extension, ExtKeyUsage, KeyUsage, SANs, isSupportedExtension() (+31 more)

### Community 3 - "testing.T"
Cohesion: 0.13
Nodes (36): Engine, testing.T, TestCRLEmptyThenRevoked(), TestCRLIsCachedUntilRevocationChanges(), TestCRLUnknownCA(), New(), createIntermediate(), createRoot() (+28 more)

### Community 4 - "net/http.ResponseWriter"
Cohesion: 0.14
Nodes (21): caResponse, createCARequest, problem, subjectJSON, net/http.Request, net/http.ResponseWriter, Server, toCAResponse() (+13 more)

### Community 5 - "encoding/asn1.RawValue"
Cohesion: 0.13
Nodes (25): CreateCARequest, encoding/asn1.BitString, encoding/asn1.ObjectIdentifier, encoding/asn1.RawValue, extension, Name, isPrintableString(), marshalDirectoryString() (+17 more)

### Community 6 - "newApp"
Cohesion: 0.10
Nodes (23): main(), run(), TestSelfSignedTLSCert(), TestTokenCreateThenServeAndAuthenticate(), usage(), selfSignedTLSCert(), newApp(), serve() (+15 more)

### Community 7 - "CreateRevocationList"
Cohesion: 0.14
Nodes (22): math/big.Int, CreateRevocationList(), Certificate, ParseRevocationList(), TestCreateParseCRLRoundTrip(), TestEmptyCRLIsValid(), TestIsRevoked(), TestParseRevocationListRejectsDuplicateExtensions() (+14 more)

### Community 8 - "pqtrust — Post-Quantum PKI-as-a-Service"
Cohesion: 0.08
Nodes (24): 10. Testing strategy, 11.1 Open-core boundary (future, not built now), 11. Deployment, licensing & commercialization path, 12. Phasing, 13. Success criteria, 1. Overview, 2. Goals and non-goals, 3. Technology choices (+16 more)

### Community 9 - "Seal"
Cohesion: 0.18
Nodes (16): crypto/cipher.AEAD, validateKeyID(), aad(), newGCM(), Seal(), TestSealRejectsEmptyPassphrase(), TestSealUnsealRoundTrip(), TestSealUsesDistinctSaltAndNonce() (+8 more)

### Community 10 - "time.Time"
Cohesion: 0.17
Nodes (16): certificateResponse, issueRequest, issueResponse, revokeRequest, crlCacheEntry, time.Time, marshalTime(), parseTime() (+8 more)

### Community 11 - "Algorithm"
Cohesion: 0.11
Nodes (14): caProfile, checkEndEntityAlgorithm(), checkExtKeyUsage(), loadJSON(), pubFromSK(), sigSize(), TestACVPMLDSASigGen(), TestACVPMLDSASigVer() (+6 more)

### Community 12 - "newHarness"
Cohesion: 0.21
Nodes (15): harness, net/http.Handler, net/http/httptest.ResponseRecorder, decode(), newHarness(), TestAuthFailures(), TestErrorMapping(), TestFullIssuanceAndRevocationFlow() (+7 more)

### Community 13 - "2026-08-16-pqtrust-phase1.md"
Cohesion: 0.10
Nodes (20): ACVP test vectors, certificate chain issued by pqtrust. Run locally or from CI., Downloads the NIST ACVP ML-DSA sigVer vectors used by internal/pqx509/acvp_test.go., File Structure, Global Constraints, Large third-party ACVP vectors; refetch with ./scripts/fetch-acvp.sh, ... paste and run every command from the README demo ..., pqtrust daemon configuration. Every key can be overridden by an environment (+12 more)

### Community 14 - "Load"
Cohesion: 0.20
Nodes (15): DatabaseConfig, IssuanceConfig, KeystoreConfig, ServerConfig, TLSConfig, Default(), Config, Load() (+7 more)

### Community 15 - "AGENTS.md"
Cohesion: 0.33
Nodes (5): Architecture, Commands (run in the worktree), Crypto / X.509 conventions (hard rules, enforced in tests), Sources of truth, Where the code actually is

## Knowledge Gaps
- **54 isolated node(s):** `revokeRequest`, `acvpSigGenExpected`, `acvpSigGenPrompt`, `acvpSigVerExpected`, `acvpSigVerPrompt` (+49 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **4 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Algorithm` connect `Algorithm` to `context.Context`, `testCA`, `extensions.go`, `net/http.ResponseWriter`, `encoding/asn1.RawValue`, `CreateRevocationList`, `Seal`?**
  _High betweenness centrality (0.076) - this node is a cross-community bridge._
- **Why does `CreateRevocationList()` connect `CreateRevocationList` to `context.Context`, `testCA`, `extensions.go`, `time.Time`, `Algorithm`?**
  _High betweenness centrality (0.050) - this node is a cross-community bridge._
- **Why does `ParseCertificate()` connect `testCA` to `context.Context`, `extensions.go`, `net/http.ResponseWriter`, `encoding/asn1.RawValue`, `CreateRevocationList`, `time.Time`, `newHarness`?**
  _High betweenness centrality (0.044) - this node is a cross-community bridge._
- **Are the 21 inferred relationships involving `testCA()` (e.g. with `CreateCertificate()` and `GenerateSerialNumber()`) actually correct?**
  _`testCA()` has 21 INFERRED edges - model-reasoned connections that need verification._
- **Are the 16 inferred relationships involving `GenerateKey()` (e.g. with `testCA()` and `TestCreateCertificateValidation()`) actually correct?**
  _`GenerateKey()` has 16 INFERRED edges - model-reasoned connections that need verification._
- **Are the 21 inferred relationships involving `ParseCertificate()` (e.g. with `algorithmFromOID()` and `parseAuthorityKeyID()`) actually correct?**
  _`ParseCertificate()` has 21 INFERRED edges - model-reasoned connections that need verification._
- **What connects `revokeRequest`, `acvpSigGenExpected`, `acvpSigGenPrompt` to the rest of the system?**
  _54 weakly-connected nodes found - possible documentation gaps or missing edges._