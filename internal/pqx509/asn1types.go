package pqx509

import (
	"encoding/asn1"
	"math/big"
)

// algorithmIdentifier encodes an AlgorithmIdentifier whose parameters field is
// optional so that it can be, and for ML-DSA always is, absent.
type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type subjectPublicKeyInfo struct {
	Algorithm algorithmIdentifier
	PublicKey asn1.BitString
}

type extension struct {
	ID       asn1.ObjectIdentifier
	Critical bool `asn1:"optional"`
	Value    []byte
}

type validity struct {
	NotBefore asn1.RawValue
	NotAfter  asn1.RawValue
}

type tbsCertificate struct {
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm algorithmIdentifier
	Issuer             asn1.RawValue
	Validity           validity
	Subject            asn1.RawValue
	PublicKey          subjectPublicKeyInfo
	Extensions         []extension `asn1:"optional,explicit,tag:3"`
}

type certificateDER struct {
	TBSCertificate     asn1.RawValue
	SignatureAlgorithm algorithmIdentifier
	SignatureValue     asn1.BitString
}
