# LIMITATIONS

pqtrust Phase 1 is honest about what it does and does not do. This file lists
the things a reader needs to know before depending on the daemon for anything
beyond a five-minute demo. Every entry has a one-line "what a production
deployment needs" note where relevant.

## Cryptography and transport

- **The API's own TLS server certificate is classical** (ECDSA P-256) because
  Go's `crypto/tls` cannot parse ML-DSA certificates. The TLS key exchange
  is hybrid post-quantum (X25519MLKEM768), which is what defeats
  harvest-now-decrypt-later; the listener cert is regenerated on every
  startup. Revisited in Phase 2.
- **No CSR flow yet**: keys are generated server-side. PKCS#10 arrives in
  Phase 2.
- **Private-key PEM format is pqtrust-specific.** The format is
  `-----BEGIN PQTRUST ML-DSA PRIVATE KEY-----`, the body is a raw 32-byte
  seed, and the header carries `Algorithm: ML-DSA-XX`. PKCS#8 encoding for
  ML-DSA lands with the Phase 2 CSR work; until then, only `pqx509` can read
  these files.
- **Stored end-entity keys** (`store_key: true`) are sealed with the same
  passphrase used to unlock the issuing CA. Separate per-key passphrases are
  a Phase 2 item.
- **Path validation** implements signatures, validity, name chaining,
  basicConstraints and CA keyUsage only; revocation is checked through a
  separate `CheckRevocation` hook, not inside `Verify`.
- **Unsupported X.509 features**: name constraints, certificate policies,
  policy mapping, inhibit anyPolicy. Certificates presenting these as
  **critical** are rejected outright; presenting them as non-critical is
  silently ignored.

## Distinguished names

- **`parseDirectoryString` accepts IA5String/T61String but rejects
  BMPString/UniversalString**, so a third-party certificate whose
  distinguished name uses those attribute types is hard-rejected during
  parsing. Most real-world DNs are UTF8String/PrintableString, so this
  rarely bites, but a legacy cert with BMPString will fail to load.
  What a production deployment needs: extend `parseDirectoryString` to
  cover `asn1.TagBMPString` and `asn1.TagUniversalString` (Phase 2).
- **`ParseNameString` splits on `,` without un-escaping**, so a human-typed
  `CN=Smith, John` mis-parses: the `,` becomes a separator and the second
  half lands in the wrong attribute. The `String()` round-trip is symmetric
  for values produced by pqtrust, because the encoder escapes `,` itself;
  this is purely a human-input hazard. What a production deployment needs:
  parse RFC 4514 escapes (`\,`, `\=`, etc.) before splitting.

## Operations and deployment

- **No HSM/PKCS#11**: `keystore.Backend` is an interface, but only the file
  backend exists. → commercial tier.
- **No RA, approval workflow, ACME, EST or SCEP**; the API issues
  immediately on an authenticated request. → commercial tier.
- **No Certificate Transparency**, no OCSP responder. CRLs only.
- **No CRLDistributionPoints extension is emitted** in Phase 1, so relying
  parties must fetch CRLs out of band from `GET /v1/ca/{id}/crl`. What a
  production deployment needs: either emit the extension with the CA's CRL
  URL, or stand up a dedicated CRL host.
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

- **404 and 405 responses** from unmatched routes are plain text from
  `http.ServeMux`, not `application/problem+json` like the rest of the
  API. What a production deployment needs: wrap the mux with a small
  fallback handler.

## Open vs. commercial tier

The split mirrors spec §11.1; nothing in Phase 1 forecloses the commercial
path.

| Open (AGPL) | Future commercial tier |
|---|---|
| `pqx509` (ML-DSA), CA engine, REST API, CLI, CRL | HA / clustering |
| Hybrid PQ TLS, server-side keygen | HSM / KMS backends |
| SQLite-backed single-node deployment | Web dashboard |
| Bearer-token auth, sealed file keystore | RA / approval workflows |
| | Audit logging and metrics |
| | Multi-tenancy |
| | Support / SLA |
