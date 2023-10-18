/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package es384

import (
	"github.com/trustbloc/kms-go/spi/kms"

	"github.com/trustbloc/vc-go/proof"
)

// Proof describes es384 proof type.
type Proof struct {
	supportedVMs []proof.SupportedVerificationMethod
}

const (
	// JWKKeyType for es384.
	JWKKeyType = "EC"
	// JWKCurve for es384.
	JWKCurve = "P-384"
	// JWTAlg for es384.
	JWTAlg = "ES384"
)

// New an instance of ed25519 proof type descriptor.
func New() *Proof {
	p := &Proof{}
	p.supportedVMs = []proof.SupportedVerificationMethod{
		{
			VerificationMethodType: "JsonWebKey2020",
			KMSKeyType:             kms.ECDSAP384TypeIEEEP1363,
			JWKKeyType:             JWKKeyType,
			JWKCurve:               JWKCurve,
			RequireJWK:             true,
		},
		{
			VerificationMethodType: "JsonWebKey2020",
			KMSKeyType:             kms.ECDSAP384TypeDER,
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
