/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"github.com/trustbloc/kms-go/doc/jose"

	"github.com/trustbloc/vc-go/jwt"
)

// MarshalJWS serializes JWT into signed form (JWS).
func (jcc *JWTCredClaims) MarshalJWS(signatureAlg JWSAlgorithm, signer jwt.ProofCreator,
	keyID string) (string, jose.Headers, error) {
	return marshalJWS(jcc, signatureAlg, signer, keyID)
}

// MarshalJWSString serializes JWT into signed form (JWS).
func (jcc *JWTCredClaims) MarshalJWSString(signatureAlg JWSAlgorithm,
	signer jwt.ProofCreator, keyID string) (string, error) {
	strJWT, _, err := marshalJWS(jcc, signatureAlg, signer, keyID)
	return strJWT, err
}
