# pqtrust Phase 2 — SLH-DSA (FIPS 205) support

**Date:** 2026-09-15
**Status:** Shipped (2026-09-16)
**Parent:** `docs/superpowers/specs/2026-08-16-pqtrust-design.md` §12, Phase 2,
item 3 of 5.
**Goal:** pqtrust issues and verifies certificates, CRLs, CSRs and PKCS#8 keys
for all 12 SLH-DSA parameter sets (FIPS 205), per RFC 9909 — the second
post-quantum signature family, and the prerequisite for the composite-cert
slice (ML-DSA+SLH-DSA combos).

## 1. Decisions (locked during brainstorming)

| # | Decision | Choice |
|---|---|---|
| 1 | Slice order | SLH-DSA first among the remaining Phase 2 items (CLI, composite, Docker) — it is the only one composite depends on |
| 2 | Issuance policy | Level-mapped allow-lists: root + 256s, intermediate + 192s, end-entity + 128s/f (SHA2 and SHAKE each). pqx509 knows all 12 sets; `ca` issues 8 of them |
| 3 | Implementation shape | Generalized scheme registry: one dispatch point per operation (generate / signer / verify), two family implementations (ML-DSA, SLH-DSA); the per-set switches in `keys.go` disappear |

Rejected alternatives: operator's-choice (any set at any level — discards the
existing "root must be ML-DSA-87" hard rule and the profile story with it);
end-entity-only (no full SLH-DSA hierarchies, which is the thing a migration
tester wants to build); additive switch-cases (36 new cases across three
switches, five more edit sites when composite lands).

## 2. Verified external facts (researched 2026-09-15)

- **Binding RFC: 9909** (SLH-DSA for X.509, December 2025; was
  `draft-ietf-lamps-x509-slhdsa`). ML-DSA's counterpart is RFC 9881.
- **OIDs** (NIST CSOR, `2.16.840.1.101.3.4.3.x`): `id-slh-dsa-sha2-128s` = 20,
  `sha2-128f` = 21, `sha2-192s` = 22, `sha2-192f` = 23, `sha2-256s` = 24,
  `sha2-256f` = 25, `shake-128s` = 26, `shake-128f` = 27, `shake-192s` = 28,
  `shake-192f` = 29, `shake-256s` = 30, `shake-256f` = 31. HashSLH-DSA
  (`.35`–`.46`) is out of scope.
- **Formats**: SPKI `subjectPublicKey` BIT STRING carries the raw 2n-byte
  `PK.seed‖PK.root` — no ASN.1 wrapping. PKCS#8 (OneAsymmetricKey v0)
  `privateKey` OCTET STRING carries the raw 4n-byte
  `SK.seed‖SK.prf‖PK.seed‖PK.root`. Signatures are the raw `R‖SIG_FORS‖SIG_HT`.
  `AlgorithmIdentifier.parameters` **absent** for public key, signature and
  private key algorithm identifiers — NULL is a hard error, identical to the
  ML-DSA rule. X.509 use is Pure SLH-DSA with the **empty context string only**
  (RFC 9909 §1).
- **Sizes** (FIPS 205 final; confirmed empirically against circl v1.6.5 and
  OpenSSL 3.5 docs):

  | Set | n | public key | private key | signature |
  |---|---|---|---|---|
  | 128s / 128f | 16 | 32 | 64 | 7,856 / 17,088 |
  | 192s / 192f | 24 | 48 | 96 | 16,224 / 35,664 |
  | 256s / 256f | 32 | 64 | 128 | 29,792 / 49,856 |

  (SHA2 and SHAKE variants share sizes.) Note 192f = 35,664 — FIPS 205 final,
  not the SPHINCS+-era 35,216.
- **circl v1.6.5** `sign/slhdsa`: `GenerateKey(rand, ID)`,
  `SignDeterministic(priv, *Message, ctx)`, `Verify(pub, *Message, sig, ctx)`,
  12 `ID` constants. `PublicKey`/`PrivateKey` implement
  `encoding.BinaryMarshaler` and marshal to exactly the RFC 9909 raw layouts
  (2n / 4n); `UnmarshalBinary` requires the embedded `ID` field to be set
  first. Deterministic, empty-context signing verifies against OpenSSL.
- **OpenSSL 3.5+**: all 12 sets, names `SLH-DSA-SHA2-128s`…
  `SLH-DSA-SHAKE-256f` (case-insensitive on the CLI); rejects NULL SPKI
  parameters, same as pqtrust.
- **ACVP** (`usnistgov/ACVP-Server`): `SLH-DSA-sigVer-FIPS205` and
  `SLH-DSA-sigGen-FIPS205` directories, same prompt/expectedResults layout as
  ML-DSA (a `keyGen` directory also exists; unused here).
- **Operational** (RFC 9909 §1, §8): `s` sets have smaller signatures **and
  faster verification**; `f` sets sign faster. A private key must not exceed
  2^64 signatures (non-issue at pqtrust volumes; documented).

## 3. pqx509 changes

### 3.1 Algorithm registry — `algorithm.go`, `keys.go`

Twelve new constants, `SLHDSA_SHA2_128s` … `SLHDSA_SHAKE_256f` (circl-style
casing); `String()` returns the canonical FIPS 205 name
(`SLH-DSA-SHA2-128s`). `algorithmInfo` gains a family discriminator and a
per-algorithm seed size, and each family provides one implementation of an
internal dispatch:

```go
// one implementation per family, selected by the registry entry
type algorithmFamily interface {
    generateKey(rand io.Reader, alg Algorithm) (PublicKey, PrivateKey, error)
    signer(keyMaterial []byte, alg Algorithm) (Signer, error)
    verify(pub PublicKey, msg, sig []byte) error
}
```

`GenerateKey`, `PrivateKey.Signer` and `Verify` in `keys.go` become registry
lookups — the three per-set switches are deleted. `Algorithm.SeedSize()`
replaces the hardcoded 32: 32 for ML-DSA seeds, 64/96/128 for SLH-DSA 4n key
material. `ParseAlgorithm` (case-insensitive) and `algorithmFromOID` learn the
12 names/OIDs. Everything downstream — SPKI, `VerifySignatureFrom`, path
validation, CRLs, CSRs, SKID/AKID (SHA-256 over SPKI bits), PKCS#8 — is already
algorithm-generic and rides the registry.

### 3.2 Private key material

`PrivateKey.Seed` becomes variable-length: the 32-byte ML-DSA seed or the
4n-byte RFC 9909 SLH-DSA blob, validated via `Algorithm.SeedSize()`. SLH-DSA
signs deterministically in pure mode with an empty context — the exact mirror
of the ML-DSA rule. The `PQTRUST ML-DSA PRIVATE KEY` legacy PEM block remains
readable for any known algorithm (its `Algorithm:` header already carries the
name); writers keep emitting standard `PRIVATE KEY` (PKCS#8) only, whose
`privateKey` OCTET STRING is simply the seed/key-material bytes.

### 3.3 Non-negotiables

- ML-DSA DER output must remain **byte-identical** through the refactor — the
  existing golden fixtures are the regression guard, and they must not be
  regenerated to make a diff pass.
- Strictness rules unchanged and family-general: parameters absent, exact key
  and signature sizes, malformed DER and unknown-critical-extension hard
  errors, `ErrInvalidKeySize`/`ErrUnknownAlgorithm`/`ErrBadSignature` sentinels
  reused with `%w` wrapping.

## 4. keystore, ca and api wiring

- **keystore**: no envelope format change (algorithm name + key bytes already
  stored); only length assertions become `SeedSize()`-driven. `Generate`
  produces the 4n blob via circl and seals it; Argon2id + AES-256-GCM
  untouched. Old ML-DSA envelopes decode unchanged.
- **ca profiles**: `caProfile.algorithm` becomes an allow-list per level, and
  the violation error lists the allowed set (still `ca.ErrConstraintViolation`,
  still a hard 422):

  | Level | Allowed algorithms |
  |---|---|
  | Root | ML-DSA-87, SLH-DSA-SHA2-256s, SLH-DSA-SHAKE-256s |
  | Intermediate | ML-DSA-65, SLH-DSA-SHA2-192s, SLH-DSA-SHAKE-192s |
  | End-entity | ML-DSA-44, ML-DSA-65, SLH-DSA-SHA2-128s/f, SLH-DSA-SHAKE-128s/f |

  Rationale: CA levels get `s` sets only — smaller signatures (8–30 KB) and
  faster verification on every chain walk and CRL check; EE additionally gets
  the fast-signing 128f sets (17 KB). `192f`/`256f` (35/50 KB) are
  parse/verify-only — never issued. CSR-based issuance routes the CSR's SPKI
  algorithm through the same end-entity allow-list (an SLH-DSA-192f CSR is a
  422 constraint violation, not a parse error). Defaults are unchanged: no
  `algorithm` field → ML-DSA-44.
- **api**: no new endpoints, no new config keys, no store schema change (the
  algorithm is persisted as its name; `ParseAlgorithm` reads the new names).
  The `algorithm` field accepts the 12 canonical names case-insensitively;
  responses echo them. An SLH-DSA CA signs certs and CRLs with its own
  algorithm — that path is already generic.
- **Operational note** (→ LIMITATIONS): SLH-DSA `s`-set signing costs
  ~0.1–1 s per signature (vs ~ms for ML-DSA) and signatures are 8–50 KB, so an
  SLH-DSA hierarchy is a conscious choice, not a default.

## 5. Testing and exit criteria

| Layer | New tests |
|---|---|
| `pqx509` | ACVP `SLH-DSA-sigVer` (incl. negatives) and `sigGen` (expected signature verified against the sk-derived public key, exactly as the ML-DSA test does) for all sets — this pins sizes and FIPS 205 final params; round-trip/property tests table-driven over all 15 algorithms (keygen, SPKI, PKCS#8, CSR, cert, CRL); new golden DER fixtures for 128s/192s/256s; existing ML-DSA goldens assert byte-identity; wrong-size key material (64/96/128 vs 32) per algorithm |
| `ca` | Allow-list rejections (root+ML-DSA-44 still rejected, root+256f rejected, EE+192f rejected, intermediate+128s rejected); full SLH-DSA hierarchy issuance (256s root → 192s intermediate → 128s leaf); SLH-DSA CA signs a CRL; CSR path with SLH-DSA SPKI (allowed and rejected sets) |
| `api` | httptest: create SLH-DSA root/intermediate/EE via API names (case variants); unknown name → 400; profile violation → 422 problem+json with allowed-set detail |
| Interop (CI) | Extend `scripts/interop.sh` + workflow: OpenSSL 3.5 generates an `SLH-DSA-SHA2-128s` CSR → pqtrust issues → `openssl verify`; pqtrust issues a 256s→192s→128s chain → OpenSSL verifies and `openssl x509 -text` parses. Open risk to resolve at implementation: exact `openssl req -newkey` spelling for SLH-DSA (fallback `genpkey` + `req -key`) |
| Meta | `make test/lint/cover/race` clean; pqx509 ≥ 80% coverage gate intact |

**Exit criteria:** ACVP vectors green for SLH-DSA; interop job proves both
directions with OpenSSL 3.5; ML-DSA goldens byte-identical; a curl-driven full
SLH-DSA hierarchy demo documented in the README.

## 6. Documentation updates

- `LIMITATIONS.md`: drop "SLH-DSA (Phase 2)" from the not-built list; add the
  parse-only note for 192f/256f, signature sizes/signing latency, and the 2^64
  signature limit note.
- `README.md`: algorithm table gains the 12 names; demo gains an optional
  SLH-DSA step; update the ML-DSA citation from
  `draft-ietf-lamps-dilithium-certificates` to **RFC 9881**.
- `AGENTS.md`: conventions block gains SLH-DSA OIDs/sizes and the issuance
  allow-list policy.
- Parent spec §12: mark the SLH-DSA item delivered when this ships.

## 7. Out of scope (explicit)

- HashSLH-DSA (pre-hash, OIDs `.35`–`.46`) — parse-reject as unknown OIDs,
  exactly like any other unsupported algorithm.
- Composite/hybrid certificates — Phase 2 item 4, own spec; lands on top of
  the registry introduced here.
- `pqtrust` CLI, Dockerfile/compose, CRLDistributionPoints, per-key
  passphrases, problem+json 404/405 — remaining Phase 2 items, each its own
  slice.
- Randomized SLH-DSA signing (deterministic only — reproducible output and
  consistent with the existing ML-DSA signer path, which also ignores its rand
  argument).
