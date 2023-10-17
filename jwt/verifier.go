/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwt

import "github.com/trustbloc/kms-go/doc/jose"

// ProofChecker used to check proof of jwt vc.
type ProofChecker interface {
	// CheckJWTProof check jwt proof.
	CheckJWTProof(headers jose.Headers, payload, msg, signature []byte) error
}
