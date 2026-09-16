# LIMITATIONS

pqtrust is honest about what it does and does not do. The code on `main` is
Phase 1 plus two Phase 2 slices: PKCS#10 CSR enrollment, PKCS#8 export and
DN completeness; and SLH-DSA (FIPS 205) — all twelve parameter sets, issued
and verified alongside ML-DSA. This file lists the things a reader needs to
know before depending on the daemon for anything beyond a five-minute demo.
Every entry has a one-line "what a production deployment needs" note where
relevant.

## Cryptography and transport

- **The API's own TLS server certificate is classical** (ECDSA P-256) because
  Go's `crypto/tls` cannot parse ML-DSA certificates. The TLS key exchange
  is hybrid post-quantum (X25519MLKEM768), which is what defeats
  harvest-now-decrypt-later; the listener cert is regenerated on every
  startup. Revisited in Phase 2.
- **Private keys are exported as PKCS#8** (`-----BEGIN PRIVATE KEY-----`)
  carrying the raw 32-byte ML-DSA seed per RFC 9881, or the 4n-byte SLH-DSA
  private key per RFC 9909 (64/96/128 bytes). The Phase 1 pqtrust-specific
  PEM remains readable but is no longer written.
- **SLH-DSA `192f`/`256f` (35/50 KB signatures) are parsed and verified but
  never issued**: CA levels allow only `s` sets and end-entity only 128s/f —
  root the 256s sets, intermediates the 192s sets. pqtrust understands all
  twelve FIPS 205 parameter sets on parse and verify.
- **SLH-DSA `s`-set signing costs ~0.1–1 s per signature** (milliseconds for
  ML-DSA), and signatures are 8–50 KB — an SLH-DSA hierarchy is a conscious
  choice, not a default. What a production deployment needs: keep ML-DSA
  where issuance latency matters; SLH-DSA buys hash-based security margins.
- **An SLH-DSA private key must not sign more than 2^64 messages** per key
  (RFC 9909 §8). A non-issue at pqtrust volumes, but a hard operational
  bound when a CA key is reused across many certificates and CRLs.
- **Stored end-entity keys** (`store_key: true`) are sealed with the same
  passphrase used to unlock the issuing CA. Separate per-key passphrases are
  a separate bounded task (explicitly out of the Phase 2 CSR scope).
- **Path validation** implements signatures, validity, name chaining,
  basicConstraints and CA keyUsage only; revocation is checked through a
  separate `CheckRevocation` hook, not inside `Verify`.
- **Unsupported X.509 features**: name constraints, certificate policies,
  policy mapping, inhibit anyPolicy. Certificates presenting these as
  **critical** are rejected outright; presenting them as non-critical is
  silently ignored.

## Distinguished names

- **Two RFC 4514 forms are rejected**: hex-encoded attribute values (a leading
  unescaped `#`) and multi-valued RDNs (an unescaped `+`), because pqtrust's
  `Name` model cannot represent them. Everything else — `\,`, `\+`, hexpair
  escapes — round-trips, and BMPString/UniversalString attributes now parse.

## Operations and deployment

- **No HSM/PKCS#11**: `keystore.Backend` is an interface, but only the file
  backend exists. → commercial tier.
- **No RA, approval workflow, ACME, EST or SCEP**; the API issues
  immediately on an authenticated request. → commercial tier.
- **No Certificate Transparency**, no OCSP responder. CRLs only.
- **No CRLDistributionPoints extension is emitted** (a separate small task),
  so relying parties must fetch CRLs out of band from
  `GET /v1/ca/{id}/crl`. What a production deployment needs: either emit the
  extension with the CA's CRL URL, or stand up a dedicated CRL host.
- **Single node, single SQLite file**; no clustering, no replication, no
  multi-tenancy. → commercial tier.
- **No audit log and no metrics**; issuance and revocation events are the
  natural hooks. → commercial tier.
- **The root CA is only "offline-capable"**: nothing in the daemon enforces
  air-gapping. Operating the root offline is a procedure, not a feature.
- **Passphrases travel in request bodies and in one header** (`X-PQTrust-
  Passphrase` for CRL fetches) over TLS and are never stored; there is no
  session or key-caching layer, so every issuance costs one Argon2id
  derivation (~50–100 ms at 64 MiB). What a production deployment needs:
  move to short-lived unlock tokens or an HSM that performs the
  derivation internally.

## API surface

- **extensionRequest in CSRs: only subjectAltName is honored.** Every other
  requested extension (EKU, basicConstraints, anything unknown) is ignored and
  never reaches the certificate; EKU comes from the request body.
- **404 and 405 responses** from unmatched routes are plain text from
  `http.ServeMux`, not `application/problem+json` like the rest of the
  API. What a production deployment needs: wrap the mux with a small
  fallback handler.

## Open vs. commercial tier

The split mirrors spec §11.1 — where each capability is planned to land —
and nothing in the open codebase forecloses the commercial path. The
`pqtrust` CLI in the open column is still pending (later in Phase 2).

| Open (AGPL) | Future commercial tier |
|---|---|
| `pqx509` (ML-DSA, SLH-DSA), CA engine, REST API, CLI, CRL | HA / clustering |
| Hybrid PQ TLS, server-side keygen | HSM / KMS backends |
| SQLite-backed single-node deployment | Web dashboard |
| Bearer-token auth, sealed file keystore | RA / approval workflows |
| | Audit logging and metrics |
| | Multi-tenancy |
| | Support / SLA |
