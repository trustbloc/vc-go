/*
Copyright Gen Digital Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package kmscrypto

import (
	"github.com/trustbloc/kms-go/wrapper"
	"github.com/trustbloc/vc-go/signature/api"
)

// PublicKeyVerifier implements the verifier.Verifier interface.
type PublicKeyVerifier interface {
	// Verify will verify signature against public key
	Verify(pubKey *api.PublicKey, doc []byte, signature []byte) error
}

// NewPublicKeyVerifier provides a PublicKeyVerifier using the given KMSCryptoVerifier.
func NewPublicKeyVerifier(cryptoVerifier wrapper.KMSCryptoVerifier) PublicKeyVerifier {
	return &pkvImpl{kcv: cryptoVerifier}
}

type pkvImpl struct {
	kcv wrapper.KMSCryptoVerifier
}

func (p *pkvImpl) Verify(pubKey *api.PublicKey, doc []byte, signature []byte) error {
	return p.kcv.Verify(signature, doc, pubKey.JWK)
}
