# pqtrust Phase 2 — CSR flow + PKCS#8 + DN completeness

**Date:** 2026-09-12
**Status:** Approved (design sections approved 2026-09-12)
**Parent:** `docs/superpowers/specs/2026-08-16-pqtrust-design.md` §12, Phase 2, item 1 of 5.
**Goal:** Let clients enroll certificates under their own keys via PKCS#10 CSRs,
export private keys as standard PKCS#8, and accept the full DN string/DER surface
that third-party tooling produces — closing the three Phase 2 gaps tagged in
`LIMITATIONS.md` that belong to enrollment.

## 1. Decisions (locked during brainstorming)

| # | Decision | Choice |
|---|---|---|
| 1 | API surface | Extend `POST /v1/certificates` with optional `csr_pem`; no new endpoint |
| 2 | Field ownership | CSR owns identity (subject + SANs from CSR); request owns authorization (EKU, validity); algorithm implied by the CSR's SPKI and checked against the end-entity profile |
| 3 | Implementation shape | Additive types in `pqx509`, thin wiring in `ca`/`api`; no enrollment abstraction layer, no keystore format change |

Rejected alternatives: a separate `/from-csr` endpoint (two endpoints, one job);
an enrollment pipeline abstraction (protocols are §2 non-goals); re-wrapping
keystore secrets as PKCS#8 with per-key passphrases (separate bounded task).

## 2. pqx509 additions

### 2.1 PKCS#10 CSR — new `csr.go`

```go
type CertificateRequest struct {
    Raw                []byte      // complete CertificationRequest DER
    RawTBSCSR          []byte      // DER of CertificationRequestInfo (the signed portion)
    Subject            Name        // existing pqx509.Name
    PublicKey          PublicKey   // parsed from SPKI: raw key, parameters absent
    SignatureAlgorithm Algorithm
    Signature          []byte
    DNSNames           []string    // from extensionRequest
    IPAddresses        []net.IP
    EmailAddresses     []string
}

func CreateCertificateRequest(rand io.Reader, subj Name, pub PublicKey, signer Signer, sans SANs) ([]byte, error)
func ParseCertificateRequest(der []byte) (*CertificateRequest, error)
func (csr *CertificateRequest) CheckSignature() error
```

`CreateCertificateRequest` exists for tests and the later `pqtrust` CLI; the
server only parses and verifies.

ASN.1 (PKCS#10 per RFC 2986):

```
CertificationRequest ::= SEQUENCE {
    certificationRequestInfo CertificationRequestInfo,
    signatureAlgorithm        AlgorithmIdentifier,
    signature                 BIT STRING }

CertificationRequestInfo ::= SEQUENCE {
    version        INTEGER { v1(0) },
    subject        Name,
    subjectPKInfo  SubjectPublicKeyInfo,
    attributes     [0] IMPLICIT SET OF Attribute }
```

Strictness rules (all hard errors, never warnings):

- `version` must be INTEGER 0.
- `signatureAlgorithm.parameters` must be **absent** — NULL is a hard error,
  identical to the certificate rule. Pure-sign mode, empty ML-DSA context.
- Trailing bytes after the outer SEQUENCE are rejected.
- Malformed DER anywhere — including inside attributes — is a hard error.
- `CheckSignature` verifies the pure-mode signature over `RawTBSCSR` with the
  CSR's own SPKI public key.

### 2.2 extensionRequest policy

The PKCS#9 `extensionRequest` attribute (OID `1.2.840.113549.1.9.14`) carries an
X.509 `Extensions` SEQUENCE. Policy:

- **SubjectAltName is honored** (DNS, IP, email — same accepted set as issuance).
- **Everything else is ignored** — EKU, BasicConstraints, and any unknown
  extension requested there never reaches the certificate. Authorization
  fields come from the request body (decision #2); BasicConstraints is set by
  the end-entity profile (`cA=FALSE`), never by a client.
- Multiple `extensionRequest` attributes in one CSR: hard error (ambiguous).
- An empty subject + no SANs is rejected by the engine profile as today.

The ignore-list is documented in `LIMITATIONS.md` so the behavior is visible.

### 2.3 PKCS#8 — new `pkcs8.go`

```go
func MarshalPKCS8PrivateKey(priv PrivateKey) ([]byte, error)
func ParsePKCS8PrivateKey(der []byte) (PrivateKey, error)
func EncodePrivateKeyPEM(priv PrivateKey) []byte   // PEM type "PRIVATE KEY"
func DecodePrivateKeyPEM(b []byte) (PrivateKey, error)
```

Encoding (per `draft-ietf-lamps-dilithium-certificates`, private key format):

```
OneAsymmetricKey ::= SEQUENCE {
    version                   INTEGER { v0(0) },
    privateKeyAlgorithm       AlgorithmIdentifier,   -- ML-DSA OID, parameters absent
    privateKey                OCTET STRING           -- raw 32-byte seed
}
```

The `privateKey` OCTET STRING carries the raw 32-byte seed — the same seed
model `keys.go` already uses; no public-key field, no attributes. Strict parse:
version 0, parameters absent, seed exactly 32 bytes.

PEM compatibility: `DecodePrivateKeyPEM` accepts both the new `PRIVATE KEY`
(PKCS#8) block and the legacy Phase 1 `PQTRUST ML-DSA PRIVATE KEY` block
(seed body + `Algorithm:` header). Writers emit PKCS#8 only. The API response
field `private_key_pem` switches to PKCS#8 on the keygen path.

### 2.4 DN completeness — `name.go`

- `parseDirectoryString` additionally accepts **BMPString** (UTF-16BE) and
  **UniversalString** (UTF-32BE), converted to UTF-8. Every attribute value
  type the parser accepts on read it can emit on write is now true.
- `ParseNameString` un-escapes RFC 4514 escapes **before** splitting on
  separators: `\<special>`, `\\`, `\#`, and `\<hexpair><hexpair>` forms, where
  special = `, + " \ ; < > =` and space-at-edge. `CN=Smith\, John` parses as
  one RDN with an embedded comma. `String()` already escapes on the way out;
  the round-trip stays symmetric.

## 3. ca engine wiring

`ca.IssueRequest` gains one field:

```go
CSR *pqx509.CertificateRequest // nil = server-side keygen (unchanged)
```

When `CSR != nil`, the engine uses `CSR.Subject`, the CSR's SANs, and
`CSR.PublicKey` — no key generation, no key storage, no private key in the
result. Profile enforcement is re-applied to CSR-sourced values:

- `CSR.PublicKey.Algorithm` must satisfy the end-entity profile (ML-DSA-44/65;
  ML-DSA-87 → `ca.ErrConstraintViolation`).
- Subject/SAN emptiness rules as today.

Everything downstream is the existing flow: passphrase still required to unseal
the issuing CA (a CSR proves the client holds its key; it does not authorize
use of the CA), `pqx509.CreateCertificate` with the CSR public key,
transactional persist, chain assembly. CSRs are never stored.

## 4. REST API contract

`POST /v1/certificates` request body gains `csr_pem` (string, PEM-encoded
PKCS#10). Validation at the handler edge, then XOR:

| Field | keygen path (`csr_pem` absent) | CSR path (`csr_pem` present) |
|---|---|---|
| `ca_id`, `passphrase` | required | required |
| `validity_days`, `ext_key_usage` | optional/allowed | optional/allowed |
| `subject`, `dns_names`, `ip_addresses`, `email_addresses` | allowed | must be absent/empty → else 400 |
| `algorithm` | optional | must be absent → else 400 (algorithm comes from the CSR) |
| `store_key` | optional | must be false/absent → else 400 (server never sees the key) |
| `csr_pem` | must be absent | required, parsed + `CheckSignature` verified |

A violation is exactly one thing: `csr_pem` present while any forbidden field is
non-empty (or `store_key` true) → 400 naming the field. There is no "neither"
case to handle: a keygen request with neither subject nor SANs already fails in
the engine with 422 ("a certificate needs a common name or at least one subject
alternative name"), and the CSR path always carries its own subject. CSR parse
or signature failure returns 400 with the wrapped sentinel detail. Profile
violations remain 422. Response shape is unchanged; on the CSR path
`private_key_pem` is omitted.

**CSR-path data flow:** client keypair + CSR → handler PEM/DER/parse/verify →
engine profile check + CA key unseal → `CreateCertificate(parent=CA,
pub=CSR.PublicKey)` → store → response (cert PEM + chain PEM).

## 5. Error handling

New sentinels in `pqx509` (wrapping causes with `%w`, never bare `errors.New`):

- `ErrInvalidCSR` — structural failures: bad version, trailing bytes, malformed
  attribute, ambiguous extensionRequest.
- `ErrCSRSignature` — `CheckSignature` failure.
- Existing `ErrMalformedDER`, `ErrUnknownAlgorithm`, `ErrInvalidKeySize` are
  reused as wrapped causes where applicable.

API mapping: CSR parse/verify/XOR failures → 400 problem+json (`typeInvalidRequest`,
per-endpoint URNs as today); end-entity algorithm/profile violations → 422
(`ca.ErrConstraintViolation` → existing mapping); CA passphrase/store errors
unchanged.

## 6. Testing

| Layer | New tests |
|---|---|
| `pqx509` | CSR round-trip (`Parse(Create(x)) == x` incl. SANs + non-ASCII DN); `CheckSignature` negatives: flipped signature bit, tampered CRI, NULL params, version ≠ 0, trailing bytes; extensionRequest: SANs honored, EKU ignored, duplicate attribute rejected; PKCS#8 round-trip, legacy PEM decode, wrong-size seed; BMPString/UniversalString hand-built DER fixtures; RFC 4514 escapes: `CN=Smith\, John`, hexpairs, `\\`, round-trip symmetry; golden CSR fixture |
| `ca` | CSR issuance flow (subject/SANs/algorithm from CSR); CSR with ML-DSA-87 → constraint violation; CSR-path result carries no private key |
| `api` | httptest: CSR happy path; forbidden-field violations (`csr_pem` + non-empty `subject`/`algorithm`/SANs or `store_key: true`) → 400 with field name; tampered CSR → 400; CSR response omits `private_key_pem`; keygen path regression (PKCS#8 PEM now) |
| Interop (CI) | Extend `scripts/interop.sh` + interop workflow: OpenSSL 3.5 generates an ML-DSA CSR → pqtrust parses + verifies; pqtrust generates a CSR → `openssl req -verify` accepts; the cert issued from it passes `openssl verify -CAfile` |
| Meta | `pqx509` coverage gate ≥ 80% unchanged; lint / vuln / race unchanged |

## 7. Documentation updates

- `LIMITATIONS.md`: remove "No CSR flow" and the PQTRUST-specific-PEM entry;
  add "extensionRequest: only SANs honored, all other requested extensions
  ignored"; keep DN entries only if any residual gap remains (BMPString and
  RFC 4514 entries removed).
- `README.md`: demo gains a CSR example (generate key + CSR, issue, verify).
- Parent spec §12: mark the CSR/PKCS#8 item delivered when this ships.

## 8. Out of scope (explicit)

- Enrollment abstraction layer (EST/SCEP/ACME shapes) — §2 non-goal.
- Per-key passphrases for stored end-entity keys; keystore re-wrap as PKCS#8 —
  separate bounded task.
- CRLDistributionPoints emission — separate small task.
- SLH-DSA, composite certificates, `pqtrust` CLI, Dockerfile/compose —
  Phase 2 sub-projects 2–5, each with its own spec.
- CSR persistence/audit trail — commercial tier (§11.1).
