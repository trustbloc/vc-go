/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package eddsa

import (
	"github.com/trustbloc/kms-go/spi/kms"
	"github.com/veraison/go-cose"

	"github.com/trustbloc/vc-go/proof"
)

// Proof describes ed25519 proof type.
type Proof struct {
	supportedVMs []proof.SupportedVerificationMethod
}

const (
	// VerificationMethodType of eddsa.
	VerificationMethodType = "Ed25519VerificationKey2018"
	// JWKKeyType of eddsa.
	JWKKeyType = "OKP"
	// JWKCurve of eddsa.
	JWKCurve = "Ed25519"
	// JWTAlg of eddsa.
	JWTAlg = "EdDSA"
)

// New an instance of ed25519 proof type descriptor.
func New() *Proof {
	p := &Proof{}
	p.supportedVMs = []proof.SupportedVerificationMethod{
		{
			VerificationMethodType: VerificationMethodType,
			KMSKeyType:             kms.ED25519Type,
			JWKKeyType:             JWKKeyType,
			JWKCurve:               JWKCurve,
		},
		{
			VerificationMethodType: "JsonWebKey2020",
			KMSKeyType:             kms.ED25519Type,
			JWKKeyType:             JWKKeyType,
			JWKCurve:               JWKCurve,
			RequireJWK:             true,
		},
	}

	return p
}

// SupportedVerificationMethods returns list of verification methods supported by this proof type.
func (s *Proof) SupportedVerificationMethods() []proof.SupportedVerificationMethod {
	return s.supportedVMs
}

// JWTAlgorithm return jwt alg that corresponds to VerificationMethod.
func (s *Proof) JWTAlgorithm() string {
	return JWTAlg
}

// CWTAlgorithm return cwt algorithm that corresponds to VerificationMethod.
func (s *Proof) CWTAlgorithm() cose.Algorithm {
	return cose.AlgorithmEd25519
}
