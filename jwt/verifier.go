/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwt

import "github.com/trustbloc/kms-go/doc/jose"

type ProofChecker interface {
	CheckJWTProof(headers jose.Headers, payload, msg, signature []byte) error
}
