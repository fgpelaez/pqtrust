# AGENTS.md

## Where the code actually is

This checkout (`main`) contains **only design docs**. All Go code lives in the git worktree:

- **`.worktrees/pqtrust-phase1/`** — branch `feat/phase1`, ~22 commits ahead of `main`, fully implemented and green (`go test ./...` passes).
- `.worktrees/` is gitignored, so worktree work is not committed from here — commit/push from inside the worktree (it is a normal checkout of `feat/phase1`).

Do not expect `internal/`, `cmd/`, `go.mod` etc. at the repo root. Work inside the worktree unless the task is writing docs.

## Sources of truth

- `docs/superpowers/specs/2026-08-16-pqtrust-design.md` — design spec (architecture, crypto, API, data model).
- `docs/superpowers/plans/2026-08-16-pqtrust-phase1.md` — implementation plan with exact interfaces, code, and per-commit checkboxes.
- `.worktrees/pqtrust-phase1/README.md`, `LIMITATIONS.md`, `SECURITY.md`.

## Commands (run in the worktree)

```bash
make test     # go test ./... -count=1; CGO_ENABLED=0
make lint     # golangci-lint run ./... (golangci-lint v2 config)
make cover    # coverage; CI gate: internal/pqx509 >= 80%
make vuln     # govulncheck
make race     # only target that needs CGO_ENABLED=1
make build    # static binary → bin/pqtrustd
make tidy
```

- `CGO_ENABLED=0` for every build/test; never add a cgo dependency.
- ACVP vectors are gitignored — fetch before testing pqx509:
  `./scripts/fetch-acvp.sh` (populates `testdata/acvp/`).
- Interop proof: `./scripts/interop.sh` requires **OpenSSL 3.5+** on `PATH` (Ubuntu doesn't ship it; CI builds 3.5.7 from source). It builds the daemon, issues a chain, and has OpenSSL verify/parse it.

## Architecture

Bottom-up dependency rule: `pqx509` → `keystore`/`store`/`config` → `ca` → `api` → `cmd/pqtrustd`. Packages only depend on ones below them.

- `internal/pqx509` — pure DER build/parse/verify for ML-DSA certs + CRLs, no I/O. The technical centerpiece; Go's `crypto/x509` can't do this (rejects PQC OIDs).
- `internal/keystore` — `Backend` interface, Argon2id + AES-256-GCM sealed keys (filesystem backend; HSM future).
- `internal/store` — SQLite (modernc.org/sqlite, pure Go), embedded SQL migrations.
- `internal/ca` — profiles, hierarchy rules, issuance, revocation, lazy CRL.
- `internal/api` — stdlib `net/http`, bearer auth, RFC 7807 problem+json.
- `cmd/pqtrustd` — `serve` + `token create` subcommands.

## Crypto / X.509 conventions (hard rules, enforced in tests)

- ML-DSA `AlgorithmIdentifier.parameters` must be **ABSENT** (never NULL); public key **raw** in the SPKI BIT STRING (no OCTET STRING wrapper); pure-sign mode, empty context.
- OIDs: ML-DSA-44 `.17`, ML-DSA-65 `.18`, ML-DSA-87 `.19` under `2.16.840.1.101.3.4.3`.
- Key/sig sizes: 44→1312/2420, 65→1952/3309, 87→2592/4627. Private keys are 32-byte seeds.
- Serial: 128-bit random positive. SKID/AKID: SHA-256 over SPKI bits, leftmost 160 bits (RFC 7093 §2 method 1).
- Validity: root 10y, intermediate 5y, end-entity max 397 days.
- Strictness: malformed DER, unknown **critical** extensions, algorithm/profile mismatch, pathlen violations are hard errors — never warnings.
- Every package defines sentinel errors; callers wrap with `%w`. No bare `errors.New` on exported funcs.
- API TLS listener cert is classical ECDSA P-256 (Go can't parse ML-DSA certs); the key exchange is hybrid X25519MLKEM768.
- License AGPL-3.0; **no per-file license headers**.