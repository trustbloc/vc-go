/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import "github.com/trustbloc/vc-go/jwt"

// MarshalJWS serializes JWT presentation claims into signed form (JWS).
func (jpc *JWTPresClaims) MarshalJWS(signatureAlg JWSAlgorithm, signer jwt.ProofCreator, keyID string) (string, error) {
	strJWT, _, err := marshalJWS(jpc, signatureAlg, signer, keyID)
	return strJWT, err
}

func unmarshalPresJWSClaims(vpJWT string, verifier jwt.ProofChecker) (*JWTPresClaims, error) {
	var claims JWTPresClaims

	_, err := unmarshalJWS(vpJWT, verifier, &claims)
	if err != nil {
		return nil, err
	}

	return &claims, err
}

func decodeVPFromJWS(vpJWT string, verifier jwt.ProofChecker) ([]byte, rawPresentation, error) {
	return decodePresJWT(vpJWT, func(vpJWT string) (*JWTPresClaims, error) {
		return unmarshalPresJWSClaims(vpJWT, verifier)
	})
}
