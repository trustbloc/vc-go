/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signatureutil

import (
	"github.com/trustbloc/kms-go/doc/jose/jwk"
)

// Signer defines generic signer.
type Signer interface {
	// Sign signs the message.
	Sign(msg []byte) ([]byte, error)

	// PublicJWK returns a JWK containing the signer's public key.
	PublicJWK() *jwk.JWK

	// Alg return alg.
	Alg() string
}
