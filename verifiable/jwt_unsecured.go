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

func marshalUnsecuredJWT(claims interface{}) (string, error) {
	token, err := jwt.NewUnsecured(claims)
	if err != nil {
		return "", fmt.Errorf("marshal unsecured JWT: %w", err)
	}

	return token.Serialize(false)
}

func unmarshalUnsecuredJWT(rawJWT string, claims interface{}) (jose.Headers, error) {
	token, _, err := jwt.Parse(rawJWT, jwt.WithProofChecker(jwt.UnsecuredJWTVerifier()))
	if err != nil {
		return nil, fmt.Errorf("unmarshal unsecured JWT: %w", err)
	}

	return token.Headers, token.DecodeClaims(claims)
}
