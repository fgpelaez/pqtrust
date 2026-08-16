#!/usr/bin/env bash
# Downloads the NIST ACVP ML-DSA sigVer vectors used by internal/pqx509/acvp_test.go.
set -euo pipefail

dest="testdata/acvp"
mkdir -p "$dest"

base="https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files"

fetch() {
	local dir="$1" file="$2" out="$3"
	echo "fetching ${dir}/${file}"
	curl -fsSL "${base}/${dir}/${file}" -o "${dest}/${out}"
}

fetch "ML-DSA-sigVer-FIPS204" "prompt.json" "mldsa-sigver-prompt.json"
fetch "ML-DSA-sigVer-FIPS204" "expectedResults.json" "mldsa-sigver-expected.json"
fetch "ML-DSA-sigGen-FIPS204" "prompt.json" "mldsa-siggen-prompt.json"
fetch "ML-DSA-sigGen-FIPS204" "expectedResults.json" "mldsa-siggen-expected.json"

echo "done; vectors in ${dest}"
