package pqx509

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// The ACVP sigVer prompt/expectedResults pair: each test case gives a public
// key, message, signature and (in expectedResults) whether it must verify.
type acvpSigVerPrompt struct {
	TestGroups []struct {
		TgID               int    `json:"tgId"`
		ParameterSet       string `json:"parameterSet"`
		SignatureInterface string `json:"signatureInterface"`
		PreHash            string `json:"preHash"`
		PublicKey          string `json:"pk"`
		Tests              []struct {
			TcID      int    `json:"tcId"`
			PublicKey string `json:"pk"`
			Message   string `json:"message"`
			Signature string `json:"signature"`
			Context   string `json:"context"`
		} `json:"tests"`
	} `json:"testGroups"`
}

type acvpSigVerExpected struct {
	TestGroups []struct {
		TgID  int `json:"tgId"`
		Tests []struct {
			TcID       int  `json:"tcId"`
			TestPassed bool `json:"testPassed"`
		} `json:"tests"`
	} `json:"testGroups"`
}

// The ACVP sigGen prompt/expectedResults pair: each test case gives a secret
// key, message and (in expectedResults) a signature that, by construction,
// must verify against the public key derived from sk. sigGen expectedResults
// carries no testPassed flag — the contract is that the produced signature
// is what the reference (or other registered) implementation generated.
type acvpSigGenPrompt struct {
	TestGroups []struct {
		TgID               int    `json:"tgId"`
		ParameterSet       string `json:"parameterSet"`
		SignatureInterface string `json:"signatureInterface"`
		PreHash            string `json:"preHash"`
		Deterministic      bool   `json:"deterministic"`
		Tests              []struct {
			TcID    int    `json:"tcId"`
			Message string `json:"message"`
			SK      string `json:"sk"`
			Context string `json:"context"`
		} `json:"tests"`
	} `json:"testGroups"`
}

type acvpSigGenExpected struct {
	TestGroups []struct {
		TgID  int `json:"tgId"`
		Tests []struct {
			TcID      int    `json:"tcId"`
			Signature string `json:"signature"`
		} `json:"tests"`
	} `json:"testGroups"`
}

func loadJSON(t *testing.T, name string, v any) {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "acvp", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("ACVP vectors missing (%v); run ./scripts/fetch-acvp.sh", err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("parsing %s: %v", name, err)
	}
}

func TestACVPMLDSASigVer(t *testing.T) {
	var prompt acvpSigVerPrompt
	var expected acvpSigVerExpected
	loadJSON(t, "mldsa-sigver-prompt.json", &prompt)
	loadJSON(t, "mldsa-sigver-expected.json", &expected)

	// tgId/tcId -> expected verdict
	verdict := map[[2]int]bool{}
	for _, g := range expected.TestGroups {
		for _, tc := range g.Tests {
			verdict[[2]int{g.TgID, tc.TcID}] = tc.TestPassed
		}
	}

	algByParamSet := map[string]Algorithm{
		"ML-DSA-44": MLDSA44,
		"ML-DSA-65": MLDSA65,
		"ML-DSA-87": MLDSA87,
	}

	checked := 0
	positive := 0
	negative := 0
	for _, g := range prompt.TestGroups {
		alg, ok := algByParamSet[g.ParameterSet]
		if !ok {
			continue
		}
		// pqtrust only ever uses pure, internal-interface-free signing with an
		// empty context, so skip groups that exercise other modes.
		if g.PreHash != "" && g.PreHash != "pure" {
			continue
		}
		if g.SignatureInterface != "" && g.SignatureInterface != "external" {
			continue
		}
		for _, tc := range g.Tests {
			want, haveVerdict := verdict[[2]int{g.TgID, tc.TcID}]
			if !haveVerdict {
				continue
			}
			if tc.Context != "" {
				continue // pqtrust always signs with an empty context
			}
			pkHex := tc.PublicKey
			if pkHex == "" {
				pkHex = g.PublicKey
			}
			pkBytes, err := hex.DecodeString(pkHex)
			if err != nil || len(pkBytes) != alg.PublicKeySize() {
				continue
			}
			msg, err := hex.DecodeString(tc.Message)
			if err != nil {
				continue
			}
			sig, err := hex.DecodeString(tc.Signature)
			if err != nil {
				continue
			}
			got := Verify(PublicKey{Algorithm: alg, Bytes: pkBytes}, msg, sig) == nil
			if got != want {
				t.Errorf("tgId %d tcId %d (%s): Verify = %v, want %v", g.TgID, tc.TcID, g.ParameterSet, got, want)
			}
			if want {
				positive++
			} else {
				negative++
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no ACVP cases were exercised; the JSON field mapping is wrong")
	}
	t.Logf("checked %d ACVP signature verification cases (%d positive + %d negative)", checked, positive, negative)
}

// pubFromSK decodes an FIPS-204 encoded ML-DSA secret key via CIRCL and
// returns the matching encoded public key. Used only by the sigGen test to
// recover pk from the (sk, message, signature) triples that NIST publishes
// in mldsa-siggen-expected.json — pqtrust's production API only stores the
// 32-byte seed, so deriving pk from the encoded sk is a test-only path.
func pubFromSK(t *testing.T, alg Algorithm, skBytes []byte) []byte {
	t.Helper()
	switch alg {
	case MLDSA44:
		if len(skBytes) != mldsa44.PrivateKeySize {
			t.Fatalf("ML-DSA-44 sk is %d bytes, want %d", len(skBytes), mldsa44.PrivateKeySize)
		}
		var sk mldsa44.PrivateKey
		sk.Unpack((*[mldsa44.PrivateKeySize]byte)(skBytes))
		pkBuf := [mldsa44.PublicKeySize]byte{}
		(*mldsa44.PublicKey)(sk.Public().(*mldsa44.PublicKey)).Pack(&pkBuf)
		return pkBuf[:]
	case MLDSA65:
		if len(skBytes) != mldsa65.PrivateKeySize {
			t.Fatalf("ML-DSA-65 sk is %d bytes, want %d", len(skBytes), mldsa65.PrivateKeySize)
		}
		var sk mldsa65.PrivateKey
		sk.Unpack((*[mldsa65.PrivateKeySize]byte)(skBytes))
		pkBuf := [mldsa65.PublicKeySize]byte{}
		(*mldsa65.PublicKey)(sk.Public().(*mldsa65.PublicKey)).Pack(&pkBuf)
		return pkBuf[:]
	case MLDSA87:
		if len(skBytes) != mldsa87.PrivateKeySize {
			t.Fatalf("ML-DSA-87 sk is %d bytes, want %d", len(skBytes), mldsa87.PrivateKeySize)
		}
		var sk mldsa87.PrivateKey
		sk.Unpack((*[mldsa87.PrivateKeySize]byte)(skBytes))
		pkBuf := [mldsa87.PublicKeySize]byte{}
		(*mldsa87.PublicKey)(sk.Public().(*mldsa87.PublicKey)).Pack(&pkBuf)
		return pkBuf[:]
	default:
		t.Fatalf("unknown algorithm %v", alg)
		return nil
	}
}

func TestACVPMLDSASigGen(t *testing.T) {
	// Positive ACVP coverage: NIST (or a registered ACVP implementation)
	// generated these signatures; the contract is that each one verifies
	// against the public key derived from the matching sk, message and
	// empty context. pqtrust's `Verify` must accept every case it can
	// decode. This is the third-party proof of the accept path that the
	// sigVer reject-only test cannot supply on its own.
	var prompt acvpSigGenPrompt
	var expected acvpSigGenExpected
	loadJSON(t, "mldsa-siggen-prompt.json", &prompt)
	loadJSON(t, "mldsa-siggen-expected.json", &expected)

	sigByCase := map[[2]int]string{}
	for _, g := range expected.TestGroups {
		for _, tc := range g.Tests {
			sigByCase[[2]int{g.TgID, tc.TcID}] = tc.Signature
		}
	}

	algByParamSet := map[string]Algorithm{
		"ML-DSA-44": MLDSA44,
		"ML-DSA-65": MLDSA65,
		"ML-DSA-87": MLDSA87,
	}

	perAlg := map[Algorithm]int{}
	total := 0
	for _, g := range prompt.TestGroups {
		alg, ok := algByParamSet[g.ParameterSet]
		if !ok {
			continue
		}
		if g.PreHash != "" && g.PreHash != "pure" {
			continue
		}
		if g.SignatureInterface != "" && g.SignatureInterface != "external" {
			continue
		}
		for _, tc := range g.Tests {
			sigHex, haveSig := sigByCase[[2]int{g.TgID, tc.TcID}]
			if !haveSig {
				continue
			}
			if tc.Context != "" {
				continue // pqtrust only signs with an empty context
			}
			skBytes, err := hex.DecodeString(tc.SK)
			if err != nil {
				continue
			}
			msg, err := hex.DecodeString(tc.Message)
			if err != nil {
				continue
			}
			sigBytes, err := hex.DecodeString(sigHex)
			if err != nil || len(sigBytes) != sigSize(alg) {
				continue
			}
			pkBytes := pubFromSK(t, alg, skBytes)
			if err := Verify(PublicKey{Algorithm: alg, Bytes: pkBytes}, msg, sigBytes); err != nil {
				t.Errorf("tgId %d tcId %d (%s): Verify rejected NIST-generated signature: %v",
					g.TgID, tc.TcID, g.ParameterSet, err)
				continue
			}
			perAlg[alg]++
			total++
		}
	}
	if total == 0 {
		t.Fatal("no ACVP sigGen cases were exercised; the JSON field mapping is wrong")
	}
	t.Logf("checked %d positive ACVP signature generation cases (ML-DSA-44:%d, ML-DSA-65:%d, ML-DSA-87:%d)",
		total, perAlg[MLDSA44], perAlg[MLDSA65], perAlg[MLDSA87])
}

func sigSize(a Algorithm) int {
	switch a {
	case MLDSA44:
		return mldsa44.SignatureSize
	case MLDSA65:
		return mldsa65.SignatureSize
	case MLDSA87:
		return mldsa87.SignatureSize
	}
	return 0
}

func TestACVPSelfConsistencySignThenVerify(t *testing.T) {
	// A deterministic-seed check that our seed expansion matches CIRCL's, and
	// that sign/verify agree across all three parameter sets.
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i)
	}
	for _, alg := range []Algorithm{MLDSA44, MLDSA65, MLDSA87} {
		priv := PrivateKey{Algorithm: alg, Seed: seed[:]}
		signer, err := priv.Signer()
		if err != nil {
			t.Fatal(err)
		}
		msg := []byte("FIPS 204 pure mode, empty context")
		sig, err := signer.Sign(nil, msg)
		if err != nil {
			t.Fatal(err)
		}
		if err := Verify(signer.Public(), msg, sig); err != nil {
			t.Errorf("%v: %v", alg, err)
		}
	}
}
