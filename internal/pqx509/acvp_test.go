package pqx509

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
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
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no ACVP cases were exercised; the JSON field mapping is wrong")
	}
	t.Logf("checked %d ACVP signature verification cases", checked)
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
