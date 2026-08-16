# SECURITY

## Not yet production

pqtrust has **not been audited**. It is a Phase 1 implementation of a
post-quantum certificate authority and the maintainers make no claims about
its fitness as a trust anchor. Do not use it to issue certificates you cannot
afford to reissue.

The cryptographic primitives are real (ML-DSA via CIRCL, Argon2id, AES-256-GCM,
TLS 1.3 with X25519MLKEM768), but the integration has not been reviewed by a
third party. Treat the binary as research-grade until it says otherwise.

## Supported versions

Only `main` is supported. pqtrust is pre-1.0; there are no tagged releases
yet, no long-term-support branches, and no backport policy. Pull requests
against `main` are the only thing receiving security fixes.

## Reporting a vulnerability

Please use **GitHub Security Advisories** on this repository:
<https://github.com/fernando/pqtrust/security/advisories/new>. The advisory
form gives you a private channel; do not file a public issue for anything
that could affect a running deployment.

The expected coordinated-disclosure window is **90 days** from the moment the
advisory opens. We will confirm receipt within three working days, aim to ship
a fix within that window, and credit you in the eventual advisory if you want
credit.

There is **no bug bounty**. The project is not funded for one; please report
anyway.

## Cryptographic posture

- **Signatures**: ML-DSA-44, ML-DSA-65 and ML-DSA-87 (FIPS 204) via the CIRCL
  library.
- **Key sealing**: AES-256-GCM. The Argon2id parameters are `t=3, m=64 MiB,
  p=2`. The nonce is fresh per envelope; the salt is fresh per key.
- **TLS**: TLS 1.3 only, with the hybrid X25519MLKEM768 key exchange (Go's
  default, no override). The listener certificate is ephemeral ECDSA P-256
  and is regenerated on every daemon start.
- **API tokens**: 256 bits from `crypto/rand`, encoded as base64url. Only the
  SHA-256 hash of the token is stored in SQLite; the plaintext token is shown
  exactly once at creation.
- **Path validation**: signatures, validity, name chaining, basicConstraints
  and CA keyUsage, plus a `CheckRevocation` hook for callers that want
  revocation-aware verification.

## Operator responsibilities

A few things are deliberately left to you, the operator, because they are
procedures and not features:

- **Protect the keystore directory** (`keystore.dir` in the config; default
  `/var/lib/pqtrust/keys`). Mode `0700`, owned by the daemon user. Anything
  readable by a second user is a confidentiality breach.
- **Protect the SQLite file** (`database.path`). Mode `0600`. The database
  holds token hashes, certificate metadata, and CA state.
- **Keep the root CA passphrase offline.** The root should issue zero
  certificates after boot; it should not even be loaded most of the time.
  Use a separate intermediate for everyday issuance.
- **Rotate API tokens.** A token is a bearer credential; rotate it on
  operator departure and on any suspected exposure. There is no
  end-to-end-TTL, so revocation is by deleting the row.
- **Back up `pqtrust.db` and `keys/` together.** A backup of one without
  the other is useless: the database references sealed-key files by ID,
  and a sealed-key file without its row in the database is opaque garbage.
  Test the restore by booting a fresh daemon against the backup.

## Out of scope for Phase 1

These are intentionally absent and should not be reported as bugs:

- HSM / PKCS#11 backends. `keystore.Backend` is an interface, but only the
  filesystem backend ships.
- OCSP responder. Revocation today is CRL only.
- Web dashboard, multi-tenancy, audit log, metrics.
- Anything in `LIMITATIONS.md`.
