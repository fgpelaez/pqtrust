#!/usr/bin/env bash
# Proves third-party interoperability: OpenSSL 3.5+ must parse and verify a
# certificate chain issued by pqtrust. Run locally or from CI.
set -euo pipefail

work="$(mktemp -d)"
trap 'kill "${PID:-}" 2>/dev/null || true; rm -rf "$work"' EXIT

echo "== OpenSSL version =="
openssl version
if ! openssl version | grep -Eq 'OpenSSL 3\.(5|[6-9]|[1-9][0-9])'; then
	echo "FAIL: OpenSSL 3.5 or newer is required for ML-DSA support" >&2
	exit 1
fi

echo "== building pqtrustd =="
CGO_ENABLED=0 go build -o "$work/pqtrustd" ./cmd/pqtrustd

cat > "$work/config.yaml" <<EOF
server:
  listen: "127.0.0.1:18443"
  tls:
    auto_self_signed: true
    hostname: localhost
database:
  path: $work/pqtrust.db
keystore:
  dir: $work/keys
EOF

pass="interop-passphrase"
token="$("$work/pqtrustd" token create -config "$work/config.yaml" -name interop)"

"$work/pqtrustd" serve -config "$work/config.yaml" &
PID=$!

base="https://127.0.0.1:18443"
for _ in $(seq 1 100); do
	if curl -sk "$base/v1/health" >/dev/null 2>&1; then break; fi
	sleep 0.1
done
curl -fsk "$base/v1/health" >/dev/null

api() {
	curl -fsk -H "Authorization: Bearer $token" -H 'Content-Type: application/json' "$@"
}

echo "== creating the root CA =="
root_id="$(api -X POST "$base/v1/ca" -d "{
	\"name\":\"Interop Root\",
	\"algorithm\":\"ML-DSA-87\",
	\"subject\":{\"common_name\":\"pqtrust Interop Root CA\",\"organization\":[\"pqtrust\"]},
	\"passphrase\":\"$pass\"
}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"

echo "== creating the intermediate CA =="
inter_json="$(api -X POST "$base/v1/ca" -d "{
	\"name\":\"Interop Issuing\",
	\"parent_id\":\"$root_id\",
	\"algorithm\":\"ML-DSA-65\",
	\"subject\":{\"common_name\":\"pqtrust Interop Issuing CA\",\"organization\":[\"pqtrust\"]},
	\"passphrase\":\"$pass\",
	\"parent_passphrase\":\"$pass\"
}")"
inter_id="$(printf '%s' "$inter_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"

echo "== issuing an end-entity certificate =="
api -X POST "$base/v1/certificates" -d "{
	\"ca_id\":\"$inter_id\",
	\"passphrase\":\"$pass\",
	\"subject\":{\"common_name\":\"interop.example.com\"},
	\"dns_names\":[\"interop.example.com\"]
}" > "$work/issued.json"

# Split the returned chain into leaf, intermediate and root PEM files.
WORK="$work" python3 - <<'PY'
import json, os, re
work = os.environ["WORK"]
d = json.load(open(os.path.join(work, "issued.json")))
open(os.path.join(work, "serial.txt"), "w").write(d["serial"])
blocks = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", d["chain_pem"], re.S)
assert len(blocks) == 3, f"expected 3 certificates in the chain, got {len(blocks)}"
for name, block in zip(["leaf.pem", "intermediate.pem", "root.pem"], blocks):
    open(os.path.join(work, name), "w").write(block + "\n")
PY

echo "== openssl x509 -text must parse our ML-DSA certificates =="
for f in leaf intermediate root; do
	echo "--- $f ---"
	openssl x509 -in "$work/$f.pem" -noout -text | head -20
	openssl x509 -in "$work/$f.pem" -noout -text | grep -q 'ML-DSA' \
		|| { echo "FAIL: openssl did not report an ML-DSA algorithm for $f" >&2; exit 1; }
done

echo "== openssl verify must accept the chain =="
openssl verify -CAfile "$work/root.pem" -untrusted "$work/intermediate.pem" "$work/leaf.pem"

echo "== revoke, then verify the CRL with openssl =="
serial="$(cat "$work/serial.txt")"
api -X POST "$base/v1/certificates/$serial/revoke" -d '{"reason":1}' >/dev/null
curl -fsk -H "Authorization: Bearer $token" -H "X-PQTrust-Passphrase: $pass" \
	-H 'Accept: application/x-pem-file' "$base/v1/ca/$inter_id/crl" -o "$work/crl.pem"
openssl crl -in "$work/crl.pem" -noout -text | head -20
openssl crl -in "$work/crl.pem" -noout -text | grep -qi "$serial" \
	|| { echo "FAIL: the revoked serial is not on the CRL according to openssl" >&2; exit 1; }
openssl crl -in "$work/crl.pem" -CAfile "$work/intermediate.pem" -noout -verify

echo "== our parser must read an OpenSSL-generated ML-DSA certificate =="
# -config /dev/null keeps req independent of openssl.cnf (CI builds install_sw
# only, so no config file exists); -addext forces a v3 cert, which our parser requires.
openssl req -x509 -newkey ml-dsa-65 -keyout "$work/ossl.key" -out "$work/ossl.pem" \
	-days 30 -nodes -subj "/CN=openssl-generated" \
	-config /dev/null -addext "basicConstraints=critical,CA:TRUE"
CGO_ENABLED=0 go run ./scripts/parsecert "$work/ossl.pem"

echo "== CSR: openssl generates, pqtrust parses and verifies =="
# -config /dev/null keeps req independent of openssl.cnf (CI installs no config).
openssl req -new -newkey ml-dsa-44 -nodes -keyout "$work/ossl-csr.key" \
	-out "$work/ossl-csr.pem" -subj "/CN=openssl-csr.example.com" -config /dev/null
CGO_ENABLED=0 go run ./scripts/parsecsr "$work/ossl-csr.pem"

echo "== issuing a certificate from an openssl CSR over the API =="
INTER_ID="$inter_id" PASS="$pass" WORK="$work" python3 - <<'PY'
import json, os
env = os.environ
csr = open(os.path.join(env["WORK"], "ossl-csr.pem")).read()
body = {"ca_id": env["INTER_ID"], "passphrase": env["PASS"], "csr_pem": csr}
open(os.path.join(env["WORK"], "csr-issue.json"), "w").write(json.dumps(body))
PY
api -X POST "$base/v1/certificates" -d @"$work/csr-issue.json" > "$work/csr-issued.json"
WORK="$work" python3 - <<'PY'
import json, os
work = os.environ["WORK"]
d = json.load(open(os.path.join(work, "csr-issued.json")))
assert not d.get("private_key_pem"), "CSR issuance must not return a private key"
assert d.get("certificate_pem"), "CSR issuance must return a certificate"
open(os.path.join(work, "csr-leaf.pem"), "w").write(d["certificate_pem"])
PY
openssl verify -CAfile "$work/root.pem" -untrusted "$work/intermediate.pem" "$work/csr-leaf.pem"

echo "== CSR: pqtrust generates, openssl verifies =="
CGO_ENABLED=0 go run ./scripts/mkcsr -dir "$work"
openssl req -verify -noout -in "$work/pqtrust-csr.pem" -config /dev/null
openssl req -in "$work/pqtrust-csr.pem" -noout -text -config /dev/null | grep -q 'ML-DSA' \
	|| { echo "FAIL: openssl did not report an ML-DSA algorithm for the pqtrust CSR" >&2; exit 1; }
openssl pkey -in "$work/pqtrust-key.pem" -noout -text 2>/dev/null | head -2 \
	|| { echo "FAIL: openssl cannot read the PKCS#8 ML-DSA seed key" >&2; exit 1; }

echo "ALL INTEROP CHECKS PASSED"
