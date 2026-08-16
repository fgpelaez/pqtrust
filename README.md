# pqtrust

[![ci](https://github.com/fernando/pqtrust/actions/workflows/ci.yml/badge.svg)](https://github.com/fernando/pqtrust/actions/workflows/ci.yml)
[![interop](https://github.com/fernando/pqtrust/actions/workflows/interop.yml/badge.svg)](https://github.com/fernando/pqtrust/actions/workflows/interop.yml)

pqtrust is a self-hosted post-quantum certificate authority written in Go. It
issues X.509 certificates signed with ML-DSA (FIPS 204, the NIST post-quantum
signature standard), exposes a small REST API for hierarchy management and
issuance, and ships its own `pqx509` layer because Go's `crypto/x509` rejects
the ML-DSA signature OIDs.

The daemon is one static binary, pure Go (`CGO_ENABLED=0` everywhere),
SQLite-backed, and uses a hybrid post-quantum TLS key exchange
(X25519MLKEM768) on every connection.

## Why

NIST finalized FIPS 203, 204 and 205 in August 2024. Harvest-now-decrypt-later
adversaries are already collecting classical TLS handshakes; organisations
that care about long-lived secrets need PKI tooling they can use to test the
migration today. Production-quality open-source PQ CAs barely exist; the goal
of pqtrust is to give engineers a small, honest daemon they can run on a laptop
to issue ML-DSA hierarchies and to give protocol designers something they can
interoperate with.

This is Phase 1 of three. Phase 2 adds PKCS#10 CSR flow, the `pqtrust` CLI,
SLH-DSA and composite (hybrid) certificates per
`draft-ietf-lamps-pq-composite-sigs`. Phase 3 is the web dashboard and OCSP
responder. See [`LIMITATIONS.md`](./LIMITATIONS.md) for what is intentionally
not built yet.

## Architecture

```
                ┌─────────────┐
                │ cmd/pqtrustd│  flag/subcommand dispatch, wiring, TLS
                └──────┬──────┘
                       │
                       ▼
   ┌────────────┐    ┌──────────┐    ┌────────────────┐
   │ config     │───▶│ api      │───▶│ ca             │
   │ YAML + env │    │ mux+routes│    │ engine+profiles│
   └────────────┘    └────┬─────┘    └────────┬───────┘
                          │                   │
                          │            ┌──────┼──────────┬────────────┐
                          ▼            ▼      ▼          ▼            ▼
                      ┌───────┐  ┌─────────┐ ┌────────┐ ┌─────────┐ ┌────────┐
                      │ store │  │ pqx509  │ │keystore│ │ store   │ │ pqx509 │
                      │ SQLite│  │ DER/CMS │ │ sealed │ │ (read)  │ │ (CRL)  │
                      └───────┘  └─────────┘ └────────┘ └─────────┘ └────────┘
```

Responsibility per package (see the plan for the full table):

| Path | Responsibility |
|---|---|
| `internal/pqx509` | DER/CMS layer: ML-DSA algorithms, keys, certificate, CRL, extensions, verify, PEM |
| `internal/keystore` | `Backend` interface, Argon2id+AES-256-GCM sealed envelope, filesystem backend |
| `internal/store` | SQLite persistence with embedded migrations for CAs, certificates and tokens |
| `internal/config` | YAML configuration with environment overrides and validation |
| `internal/ca` | Issuance profiles, hierarchy constraints, chain assembly, revocation, CRL generation |
| `internal/api` | HTTP routes, RFC 7807 problem responses, bearer-token middleware |
| `cmd/pqtrustd` | `serve` and `token create` subcommands, hybrid PQ TLS server |

## Five-minute demo

The demo runs against a fresh state in `/tmp/pqtrust`, requires `make`, `curl`,
`jq` and `openssl` (OpenSSL 3.5+ for step 7), and ends with a real
ML-DSA-signed certificate on disk.

```bash
# 1. Build
git clone https://github.com/fernando/pqtrust && cd pqtrust
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

The demo passes when `jq -r .id` returns the CA IDs in step 5 and
`/tmp/pqtrust/chain.pem` contains three `BEGIN CERTIFICATE` blocks in step 6.
Step 7 is informational: it shows that a third-party parser (OpenSSL 3.5+)
also reads pqtrust's ML-DSA DER. On systems whose `openssl` is older than 3.5,
step 7 will fail because the local OpenSSL does not understand ML-DSA OIDs; the
demonstration is correct for the documented environment.

## API reference

All endpoints respond with `application/problem+json` on error and require a
bearer token in `Authorization`, except `GET /v1/health`.

| Method | Path | Purpose | Request body | Notable response |
|---|---|---|---|---|
| `GET` | `/v1/health` | Liveness check | — | `{"status":"ok","version":"..."}` |
| `POST` | `/v1/ca` | Create a root CA, or an intermediate when `parent_id` is set | `{name, parent_id?, algorithm, subject, validity_days?, passphrase, parent_passphrase?}` | `201` with `{id, certificate_pem, chain_pem, subject_dn, not_before, not_after, ...}` |
| `GET` | `/v1/ca` | List every CA | — | `200` with `{cas: [...]}` |
| `GET` | `/v1/ca/{id}` | Fetch a single CA | — | `200` with the same shape as `POST /v1/ca` |
| `GET` | `/v1/ca/{id}/crl` | Fetch the CA's CRL | `X-PQTrust-Passphrase` header; `Accept: application/x-pem-file` to get PEM | DER or PEM CRL |
| `POST` | `/v1/certificates` | Issue an end-entity certificate (server-generated key) | `{ca_id, passphrase, subject, dns_names?, ip_addresses?, email_addresses?, algorithm?, validity_days?, ext_key_usage?, store_key?}` | `201` with `{serial, certificate_pem, chain_pem, private_key_pem?, not_before, not_after}` |
| `GET` | `/v1/certificates/{serial}` | Fetch a certificate by serial | — | `200` with `{serial, ca_id, subject_dn, sans, algorithm, status, certificate_pem, revoked_at?, ...}` |
| `POST` | `/v1/certificates/{serial}/revoke` | Revoke a certificate | `{reason: 0..10}` (RFC 5280 reason code) | `200` with `{serial, status:"revoked", revoked_at, reason}` |

Subjects accept: `common_name`, `organization`, `organizational_unit`,
`country`, `locality`, `province` (string or array of strings). The `algorithm`
field accepts `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87`. Issuing keys are
generated server-side; the private-key PEM uses a pqtrust-specific format
documented in [`LIMITATIONS.md`](./LIMITATIONS.md).

## Configuration

Every key may be set in `config.yaml` or via the environment; environment wins.
Booleans are parsed with `strconv.ParseBool`; integers with `strconv.Atoi`.

| YAML key | Environment variable | Default | Description |
|---|---|---|---|
| `server.listen` | `PQTRUST_LISTEN` | `:8443` | TLS listener address |
| `server.tls.auto_self_signed` | `PQTRUST_TLS_AUTO_SELF_SIGNED` | `true` | Generate an ephemeral ECDSA P-256 listener cert at startup |
| `server.tls.hostname` | `PQTRUST_TLS_HOSTNAME` | `localhost` | CN/SAN for the self-signed listener cert |
| `server.tls.cert_file` | `PQTRUST_TLS_CERT_FILE` | — | PEM cert path (required when `auto_self_signed=false`) |
| `server.tls.key_file` | `PQTRUST_TLS_KEY_FILE` | — | PEM key path (required when `auto_self_signed=false`) |
| `database.path` | `PQTRUST_DB_PATH` | `/var/lib/pqtrust/pqtrust.db` | SQLite database file |
| `keystore.dir` | `PQTRUST_KEYSTORE_DIR` | `/var/lib/pqtrust/keys` | Sealed-key directory (0700) |
| `issuance.max_validity_days` | `PQTRUST_MAX_VALIDITY_DAYS` | `397` | Upper bound on end-entity validity |
| `issuance.crl_validity_hours` | `PQTRUST_CRL_VALIDITY_HOURS` | `168` | CRL `nextUpdate` lifetime |

The default paths point at `/var/lib/pqtrust/` and require root; the demo above
substitutes them into `/tmp/pqtrust/` with `sed` instead of copying the file
unchanged.

## Development

```bash
make test     # run the full test suite
make lint     # golangci-lint with the repo's .golangci.yml
make cover    # per-package coverage; the CI gate enforces pqx509 >= 80%
make vuln     # govulncheck against the live advisory database
make race     # tests with the race detector (requires CGO_ENABLED=1)
make build    # static binary into ./bin/pqtrustd
make tidy     # go mod tidy

./scripts/fetch-acvp.sh   # populate testdata/acvp/ with NIST ML-DSA vectors
./scripts/interop.sh      # build, run, issue, and verify with OpenSSL 3.5+
```

Tests use `CGO_ENABLED=0` by default; `make race` flips it for the race job.
The OpenSSL 3.5 interop script requires a working `openssl` 3.5 or newer on
`PATH` (Ubuntu does not ship one; the CI workflow builds 3.5.7 from source).

## License

[AGPL-3.0](./LICENSE). The choice preserves the future open-core model: anyone
who runs pqtrust as a network service must publish their changes, which keeps
the AGPL path viable; because there are no external contributors yet, a future
relaxation to Apache-2.0 remains possible if commercial needs change.
This is easy to loosen later and impossible to tighten, which is the right
default for a project with a planned commercial tier.

See also [`LIMITATIONS.md`](./LIMITATIONS.md) for what is intentionally not
built yet and [`SECURITY.md`](./SECURITY.md) for the disclosure policy.
