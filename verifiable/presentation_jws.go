/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"fmt"
	"strings"

	"github.com/trustbloc/vc-go/jwt"
)

// MarshalJWS serializes JWT presentation claims into signed form (JWS).
func (jpc *JWTPresClaims) MarshalJWS(signatureAlg JWSAlgorithm, signer jwt.ProofCreator, keyID string) (string, error) {
	strJWT, _, err := marshalJWS(jpc, signatureAlg, signer, keyID)
	return strJWT, err
}

func unmarshalPresJWSClaims(vpJWT string, verifier jwt.ProofChecker) (*JWTPresClaims, error) {
	var claims JWTPresClaims

	headers, err := unmarshalJWT(vpJWT, &claims)
	if err != nil {
		return nil, err
	}

	keyID, ok := headers.KeyID()
	if !ok {
		return nil, fmt.Errorf("key id is missing in jwt header")
	}

	err = jwt.CheckProof(vpJWT, verifier, strings.Split(keyID, "#")[0], nil)
	if err != nil {
		return nil, fmt.Errorf("jwt proof check: %w", err)
	}

	return &claims, err
}

func decodeVPFromJWS(vpJWT string, verifier jwt.ProofChecker) ([]byte, rawPresentation, error) {
	return decodePresJWT(vpJWT, func(vpJWT string) (*JWTPresClaims, error) {
		return unmarshalPresJWSClaims(vpJWT, verifier)
	})
}
