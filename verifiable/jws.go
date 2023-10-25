/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"fmt"

	"github.com/trustbloc/kms-go/doc/jose"

	"github.com/trustbloc/vc-go/jwt"
)

// MarshalJWS serializes JWT presentation claims into signed form (JWS).
func marshalJWS(jwtClaims interface{}, signatureAlg JWSAlgorithm,
	signer jwt.ProofCreator, keyID string) (string, jose.Headers, error) {
	algName, err := signatureAlg.Name()
	if err != nil {
		return "", nil, err
	}

	signParameters := jwt.SignParameters{
		KeyID:  keyID,
		JWTAlg: algName,
	}

	token, err := jwt.NewSigned(jwtClaims, signParameters, signer)
	if err != nil {
		return "", nil, err
	}

	jwtStr, err := token.Serialize(false)
	if err != nil {
		return "", nil, err
	}

	return jwtStr, token.Headers, nil
}

func unmarshalJWT(rawJwt string, claims interface{}) (jose.Headers, error) {
	jsonWebToken, _, err := jwt.Parse(rawJwt,
		jwt.DecodeClaimsTo(claims),
		jwt.WithIgnoreClaimsMapDecoding(true),
	)
	if err != nil {
		return nil, fmt.Errorf("parse JWT: %w", err)
	}

	return jsonWebToken.Headers, nil
}
