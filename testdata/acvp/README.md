# ACVP test vectors

ML-DSA (FIPS 204) signature verification vectors from the NIST ACVP server
repository: <https://github.com/usnistgov/ACVP-Server> (`gen-val/json-files/`).

Refresh with `./scripts/fetch-acvp.sh`. These files are inputs to
`internal/pqx509/acvp_test.go` and are not covered by pqtrust's license.
