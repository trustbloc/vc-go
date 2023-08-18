/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"fmt"

	"github.com/trustbloc/kms-crypto-go/doc/jose"
	"github.com/trustbloc/vc-go/jwt"
)

func marshalUnsecuredJWT(headers jose.Headers, claims interface{}) (string, error) {
	token, err := jwt.NewUnsecured(claims, headers)
	if err != nil {
		return "", fmt.Errorf("marshal unsecured JWT: %w", err)
	}

	return token.Serialize(false)
}

func unmarshalUnsecuredJWT(rawJWT string, claims interface{}) error {
	token, _, err := jwt.Parse(rawJWT, jwt.WithSignatureVerifier(jwt.UnsecuredJWTVerifier()))
	if err != nil {
		return fmt.Errorf("unmarshal unsecured JWT: %w", err)
	}

	return token.DecodeClaims(claims)
}
