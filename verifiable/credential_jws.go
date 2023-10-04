/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"errors"

	"github.com/trustbloc/kms-go/doc/jose"

	"github.com/trustbloc/vc-go/jwt"
)

// MarshalJWS serializes JWT into signed form (JWS).
func (jcc *JWTCredClaims) MarshalJWS(signatureAlg JWSAlgorithm, signer jwt.ProofCreator,
	keyID string) (string, jose.Headers, error) {
	return marshalJWS(jcc, signatureAlg, signer, keyID)
}

// MarshalJWSString serializes JWT into signed form (JWS).
func (jcc *JWTCredClaims) MarshalJWSString(signatureAlg JWSAlgorithm, signer jwt.ProofCreator, keyID string) (string, error) {
	strJWT, _, err := marshalJWS(jcc, signatureAlg, signer, keyID)
	return strJWT, err
}

func unmarshalJWSClaims(
	rawJwt string,
	verifier jwt.ProofChecker,
) (jose.Headers, *JWTCredClaims, error) {
	var claims JWTCredClaims

	joseHeaders, err := unmarshalJWS(rawJwt, verifier, &claims)
	if err != nil {
		return nil, nil, err
	}

	return joseHeaders, &claims, err
}

func decodeCredJWS(rawJwt string, checkProof bool, verifier jwt.ProofChecker) (jose.Headers, []byte, error) {
	if checkProof && verifier == nil {
		return nil, nil, errors.New("jwt proofChecker is not defined")
	}

	return decodeCredJWT(rawJwt, func(vcJWTBytes string) (jose.Headers, *JWTCredClaims, error) {
		return unmarshalJWSClaims(rawJwt, verifier)
	})
}
