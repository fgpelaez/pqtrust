package pqx509

import (
	"bytes"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"
)

func TestCreateParseCRLRoundTrip(t *testing.T) {
	ca, signer := testCA(t, MLDSA65, 0)
	now := time.Now().UTC().Truncate(time.Second)
	entries := []RevocationEntry{
		{SerialNumber: big.NewInt(0x1234), RevocationTime: now.Add(-2 * time.Hour), ReasonCode: 1},
		{SerialNumber: big.NewInt(0x5678), RevocationTime: now.Add(-time.Hour), ReasonCode: 0},
	}
	der, err := CreateRevocationList(rand.Reader, ca, signer, big.NewInt(3), entries, now, now.Add(7*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	crl, err := ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	if crl.SignatureAlgorithm != MLDSA65 {
		t.Errorf("signature algorithm = %v", crl.SignatureAlgorithm)
	}
	if !bytes.Equal(crl.RawIssuer, ca.RawSubject) {
		t.Error("CRL issuer must equal the CA subject bytes")
	}
	if crl.Number == nil || crl.Number.Cmp(big.NewInt(3)) != 0 {
		t.Errorf("CRL number = %v, want 3", crl.Number)
	}
	if !bytes.Equal(crl.AuthorityKeyID, ca.SubjectKeyID) {
		t.Error("CRL AKID must equal the CA SKID")
	}
	if !crl.ThisUpdate.Equal(now) || !crl.NextUpdate.Equal(now.Add(7*24*time.Hour)) {
		t.Errorf("update times = %v / %v", crl.ThisUpdate, crl.NextUpdate)
	}
	if len(crl.Entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(crl.Entries))
	}
	if crl.Entries[0].SerialNumber.Cmp(big.NewInt(0x1234)) != 0 || crl.Entries[0].ReasonCode != 1 {
		t.Errorf("entry 0 = %+v", crl.Entries[0])
	}
	if crl.Entries[1].ReasonCode != 0 {
		t.Errorf("entry 1 reason = %d, want 0", crl.Entries[1].ReasonCode)
	}
	if !crl.Entries[0].RevocationTime.Equal(entries[0].RevocationTime) {
		t.Errorf("revocation time = %v, want %v", crl.Entries[0].RevocationTime, entries[0].RevocationTime)
	}
	if err := crl.VerifySignatureFrom(ca); err != nil {
		t.Errorf("CRL signature must verify: %v", err)
	}
}

func TestEmptyCRLIsValid(t *testing.T) {
	ca, signer := testCA(t, MLDSA44, 0)
	now := time.Now().UTC().Truncate(time.Second)
	der, err := CreateRevocationList(rand.Reader, ca, signer, big.NewInt(1), nil, now, now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	crl, err := ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(crl.Entries) != 0 {
		t.Errorf("got %d entries, want 0", len(crl.Entries))
	}
	if err := crl.VerifySignatureFrom(ca); err != nil {
		t.Errorf("empty CRL must verify: %v", err)
	}
}

func TestCRLVerifySignatureFromRejects(t *testing.T) {
	ca, signer := testCA(t, MLDSA44, 0)
	now := time.Now().UTC().Truncate(time.Second)
	der, err := CreateRevocationList(rand.Reader, ca, signer, big.NewInt(1), nil, now, now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	crl, err := ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("nil issuer", func(t *testing.T) {
		if err := crl.VerifySignatureFrom(nil); err == nil {
			t.Error("nil issuer must be rejected")
		}
	})

	t.Run("issuer DN mismatch", func(t *testing.T) {
		pub, priv, err := GenerateKey(rand.Reader, MLDSA44)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := priv.Signer()
		if err != nil {
			t.Fatal(err)
		}
		serial, err := GenerateSerialNumber(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		other, err := CreateCertificate(rand.Reader, &Certificate{
			SerialNumber:          serial,
			SignatureAlgorithm:    MLDSA44,
			Subject:               Name{CommonName: "a-different-ca"},
			NotBefore:             now,
			NotAfter:              now.Add(24 * time.Hour),
			BasicConstraints:      BasicConstraints{IsCA: true, MaxPathLen: 0, MaxPathLenSet: true},
			BasicConstraintsValid: true,
			KeyUsage:              KeyUsageKeyCertSign | KeyUsageCRLSign,
		}, &Certificate{
			SignatureAlgorithm: MLDSA44,
			Subject:            Name{CommonName: "a-different-ca"},
			NotBefore:          now,
			NotAfter:           now.Add(24 * time.Hour),
		}, pub, signer)
		if err != nil {
			t.Fatal(err)
		}
		otherCert, err := ParseCertificate(other)
		if err != nil {
			t.Fatal(err)
		}
		if err := crl.VerifySignatureFrom(otherCert); !errors.Is(err, ErrUnknownAuthority) {
			t.Errorf("want ErrUnknownAuthority, got %v", err)
		}
	})

	t.Run("algorithm mismatch", func(t *testing.T) {
		wrongAlg, wrongSigner := testCA(t, MLDSA65, 0)
		der, err := CreateRevocationList(rand.Reader, wrongAlg, wrongSigner, big.NewInt(1), nil, now, now.Add(24*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		crl, err := ParseRevocationList(der)
		if err != nil {
			t.Fatal(err)
		}
		if err := crl.VerifySignatureFrom(ca); !errors.Is(err, ErrBadSignature) {
			t.Errorf("want ErrBadSignature, got %v", err)
		}
	})
}

func TestIsRevoked(t *testing.T) {
	ca, signer := testCA(t, MLDSA44, 0)
	now := time.Now().UTC().Truncate(time.Second)
	der, _ := CreateRevocationList(rand.Reader, ca, signer, big.NewInt(1),
		[]RevocationEntry{{SerialNumber: big.NewInt(42), RevocationTime: now, ReasonCode: 4}}, now, now.Add(time.Hour))
	crl, err := ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := crl.IsRevoked(big.NewInt(42))
	if !ok || entry.ReasonCode != 4 {
		t.Errorf("IsRevoked(42) = %+v, %v", entry, ok)
	}
	if _, ok := crl.IsRevoked(big.NewInt(43)); ok {
		t.Error("IsRevoked(43) must be false")
	}
}

func TestCreateRevocationListValidation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	t.Run("issuer lacks cRLSign", func(t *testing.T) {
		root, rootSigner := testCA(t, MLDSA87, 1)
		pub, priv, _ := GenerateKey(rand.Reader, MLDSA65)
		s, _ := GenerateSerialNumber(rand.Reader)
		noCRLSign := issue(t, &Certificate{
			SerialNumber:          s,
			SignatureAlgorithm:    MLDSA87,
			Subject:               Name{CommonName: "no-crl-sign"},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.Add(24 * time.Hour),
			BasicConstraints:      BasicConstraints{IsCA: true, MaxPathLen: 0, MaxPathLenSet: true},
			BasicConstraintsValid: true,
			KeyUsage:              KeyUsageKeyCertSign,
		}, root, pub, rootSigner)
		signer, _ := priv.Signer()
		if _, err := CreateRevocationList(rand.Reader, noCRLSign, signer, big.NewInt(1), nil, now, now.Add(time.Hour)); !errors.Is(err, ErrKeyUsageNotPermitted) {
			t.Errorf("want ErrKeyUsageNotPermitted, got %v", err)
		}
	})

	t.Run("nextUpdate before thisUpdate", func(t *testing.T) {
		ca, signer := testCA(t, MLDSA44, 0)
		if _, err := CreateRevocationList(rand.Reader, ca, signer, big.NewInt(1), nil, now, now.Add(-time.Hour)); err == nil {
			t.Error("nextUpdate before thisUpdate must be an error")
		}
	})

	t.Run("nil CRL number", func(t *testing.T) {
		ca, signer := testCA(t, MLDSA44, 0)
		if _, err := CreateRevocationList(rand.Reader, ca, signer, nil, nil, now, now.Add(time.Hour)); err == nil {
			t.Error("nil CRL number must be an error")
		}
	})
}

func TestParseRevocationListRejectsTrailingData(t *testing.T) {
	ca, signer := testCA(t, MLDSA44, 0)
	now := time.Now().UTC().Truncate(time.Second)
	der, _ := CreateRevocationList(rand.Reader, ca, signer, big.NewInt(1), nil, now, now.Add(time.Hour))
	if _, err := ParseRevocationList(append(der, 0x00)); err == nil {
		t.Error("trailing data must be rejected")
	}
}

func TestParseRevocationListRejectsTBSParameters(t *testing.T) {
	ca, signer := testCA(t, MLDSA44, 0)
	now := time.Now().UTC().Truncate(time.Second)
	der, _ := CreateRevocationList(rand.Reader, ca, signer, big.NewInt(1), nil, now, now.Add(time.Hour))

	var outer certificateListDER
	if _, err := asn1.Unmarshal(der, &outer); err != nil {
		t.Fatalf("unmarshal outer: %v", err)
	}
	var tbs tbsCertList
	if _, err := asn1.Unmarshal(outer.TBSCertList.FullBytes, &tbs); err != nil {
		t.Fatalf("unmarshal TBS: %v", err)
	}
	tbs.SignatureAlgorithm.Parameters = asn1.RawValue{FullBytes: []byte{0x05, 0x00}}
	newTBS, err := asn1.Marshal(tbs)
	if err != nil {
		t.Fatalf("re-marshal TBS: %v", err)
	}
	outer.TBSCertList.FullBytes = newTBS
	crafted, err := asn1.Marshal(outer)
	if err != nil {
		t.Fatalf("re-marshal outer: %v", err)
	}

	if _, err := ParseRevocationList(crafted); err == nil {
		t.Fatal("ParseRevocationList must reject a TBS signature AlgorithmIdentifier carrying parameters")
	} else if !errors.Is(err, ErrMalformedDER) {
		t.Errorf("err = %v, want one wrapping ErrMalformedDER", err)
	}
}

func TestParseRevocationListRejectsSignatureUnusedBits(t *testing.T) {
	ca, signer := testCA(t, MLDSA44, 0)
	now := time.Now().UTC().Truncate(time.Second)
	der, _ := CreateRevocationList(rand.Reader, ca, signer, big.NewInt(1), nil, now, now.Add(time.Hour))

	var outer certificateListDER
	if _, err := asn1.Unmarshal(der, &outer); err != nil {
		t.Fatalf("unmarshal outer: %v", err)
	}
	outer.SignatureValue.BitLength = outer.SignatureValue.BitLength - 1
	crafted, err := asn1.Marshal(outer)
	if err != nil {
		t.Fatalf("re-marshal outer: %v", err)
	}

	if _, err := ParseRevocationList(crafted); err == nil {
		t.Fatal("ParseRevocationList must reject a signature BIT STRING with unused bits")
	} else if !errors.Is(err, ErrMalformedDER) {
		t.Errorf("err = %v, want one wrapping ErrMalformedDER", err)
	}
}

func TestParseRevocationListRejectsSignatureWrongSize(t *testing.T) {
	ca, signer := testCA(t, MLDSA44, 0)
	now := time.Now().UTC().Truncate(time.Second)
	der, _ := CreateRevocationList(rand.Reader, ca, signer, big.NewInt(1), nil, now, now.Add(time.Hour))

	var outer certificateListDER
	if _, err := asn1.Unmarshal(der, &outer); err != nil {
		t.Fatalf("unmarshal outer: %v", err)
	}
	outer.SignatureValue.Bytes = outer.SignatureValue.Bytes[:len(outer.SignatureValue.Bytes)-1]
	outer.SignatureValue.BitLength = len(outer.SignatureValue.Bytes) * 8
	crafted, err := asn1.Marshal(outer)
	if err != nil {
		t.Fatalf("re-marshal outer: %v", err)
	}

	if _, err := ParseRevocationList(crafted); err == nil {
		t.Fatal("ParseRevocationList must reject a signature of wrong length")
	} else if !errors.Is(err, ErrMalformedDER) {
		t.Errorf("err = %v, want one wrapping ErrMalformedDER", err)
	}
}

func TestParseRevocationListRejectsV1WithExtensions(t *testing.T) {
	ca, signer := testCA(t, MLDSA44, 0)
	now := time.Now().UTC().Truncate(time.Second)
	der, _ := CreateRevocationList(rand.Reader, ca, signer, big.NewInt(1), nil, now, now.Add(time.Hour))

	var outer certificateListDER
	if _, err := asn1.Unmarshal(der, &outer); err != nil {
		t.Fatalf("unmarshal outer: %v", err)
	}
	var tbs tbsCertList
	if _, err := asn1.Unmarshal(outer.TBSCertList.FullBytes, &tbs); err != nil {
		t.Fatalf("unmarshal TBS: %v", err)
	}
	tbs.Version = 0
	newTBS, err := asn1.Marshal(tbs)
	if err != nil {
		t.Fatalf("re-marshal TBS: %v", err)
	}
	outer.TBSCertList.FullBytes = newTBS
	crafted, err := asn1.Marshal(outer)
	if err != nil {
		t.Fatalf("re-marshal outer: %v", err)
	}

	if _, err := ParseRevocationList(crafted); err == nil {
		t.Fatal("ParseRevocationList must reject a v1 CRL that carries extensions")
	} else if !errors.Is(err, ErrMalformedDER) {
		t.Errorf("err = %v, want one wrapping ErrMalformedDER", err)
	}
}

func TestParseRevocationListRejectsDuplicateExtensions(t *testing.T) {
	ca, signer := testCA(t, MLDSA44, 0)
	now := time.Now().UTC().Truncate(time.Second)
	der, _ := CreateRevocationList(rand.Reader, ca, signer, big.NewInt(1), nil, now, now.Add(time.Hour))

	var outer certificateListDER
	if _, err := asn1.Unmarshal(der, &outer); err != nil {
		t.Fatalf("unmarshal outer: %v", err)
	}
	var tbs tbsCertList
	if _, err := asn1.Unmarshal(outer.TBSCertList.FullBytes, &tbs); err != nil {
		t.Fatalf("unmarshal TBS: %v", err)
	}
	tbs.Extensions = append(tbs.Extensions, tbs.Extensions[0])
	newTBS, err := asn1.Marshal(tbs)
	if err != nil {
		t.Fatalf("re-marshal TBS: %v", err)
	}
	outer.TBSCertList.FullBytes = newTBS
	crafted, err := asn1.Marshal(outer)
	if err != nil {
		t.Fatalf("re-marshal outer: %v", err)
	}

	if _, err := ParseRevocationList(crafted); err == nil {
		t.Fatal("ParseRevocationList must reject duplicate CRL extensions")
	} else if !errors.Is(err, ErrMalformedDER) {
		t.Errorf("err = %v, want one wrapping ErrMalformedDER", err)
	}
}
