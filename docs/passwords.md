# Passphrase protection

pqtrust seals every CA private key with AES-256-GCM; the wrapping key is
derived from a user-supplied passphrase via Argon2id (`t=3, m=64 MiB, p=2`).

## How it works

- **Generate** — a new key is created and immediately sealed under the
  passphrase. The plaintext seed never touches disk.
- **Load / unseal** — the sealed envelope is opened by re-deriving the same
  wrapping key from the passphrase. A wrong passphrase returns
  `keystore.ErrWrongPassphrase`.
- **Zeroization** — unsealed material is zeroed on close.

## Operational rules

| Rule | Why |
|---|---|
| Root CA passphrase stays offline | The root should not load keys except when signing intermediates or CRLs. |
| Use a separate intermediate for day-to-day issuance | Keeps the offline root unloaded most of the time. |
| Passphrases travel over TLS only | Sent in the request body or `X-PQTrust-Passphrase` header; never stored. |
| Rotate API tokens on operator departure | Tokens are bearer credentials; there is no session or key-caching layer. |
| Back up `pqtrust.db` and `keys/` together | A backup of one without the other is unusable. |

## Production notes

Every issuance costs one Argon2id derivation (~50–100 ms at 64 MiB). For
production deployments, migrate to short-lived unlock tokens or an HSM that
performs the derivation internally (see `keystore.Backend` interface).
