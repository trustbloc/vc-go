/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ps256

import (
	"github.com/trustbloc/kms-go/spi/kms"

	"github.com/trustbloc/vc-go/proof"
)

// Proof describes ed25519 proof type.
type Proof struct {
	supportedVMs []proof.SupportedVerificationMethod
}

const (
	//JWKKeyType for ps256.
	JWKKeyType = "RSA"
	//JWTAlg for ps256.
	JWTAlg = "PS256"
)

// New an instance of ed25519 proof type descriptor.
func New() *Proof {
	p := &Proof{}
	p.supportedVMs = []proof.SupportedVerificationMethod{
		{
			VerificationMethodType: "RsaVerificationKey2018",
			KMSKeyType:             kms.RSAPS256Type,
			JWKKeyType:             JWKKeyType,
		},
		{
			VerificationMethodType: "JsonWebKey2020",
			KMSKeyType:             kms.RSAPS256Type,
			JWKKeyType:             JWKKeyType,
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
