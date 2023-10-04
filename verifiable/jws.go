/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"fmt"

	"github.com/trustbloc/kms-go/doc/jose"

	"github.com/trustbloc/vc-go/jwt"
)

// noVerifier is used when no JWT signature verification is needed.
// To be used with precaution.
type noVerifier struct{}

func (v noVerifier) CheckJWTProof(_ jose.Headers, _, _, _ []byte) error {
	return nil
}

// MarshalJWS serializes JWT presentation claims into signed form (JWS).
func marshalJWS(
	jwtClaims interface{}, signatureAlg JWSAlgorithm, signer jwt.ProofCreator, keyID string) (string, jose.Headers, error) {
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

func unmarshalJWS(rawJwt string, verifier jwt.ProofChecker, claims interface{}) (jose.Headers, error) {
	if verifier == nil {
		verifier = &noVerifier{}
	}

	jsonWebToken, claimsRaw, err := jwt.Parse(rawJwt,
		jwt.WithProofChecker(verifier),
		jwt.WithIgnoreClaimsMapDecoding(true),
	)
	if err != nil {
		return nil, fmt.Errorf("parse JWT: %w", err)
	}

	err = json.Unmarshal(claimsRaw, claims)
	if err != nil {
		return nil, err
	}

	return jsonWebToken.Headers, nil
}
