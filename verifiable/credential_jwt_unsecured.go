/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

// MarshalUnsecuredJWT serialized JWT into unsecured JWT.
func (jcc *JWTCredClaims) MarshalUnsecuredJWT() (string, error) {
	return marshalUnsecuredJWT(jcc)
}

func decodeCredJWTUnsecured(rawJwt string) ([]byte, error) {
	_, vcBytes, err := decodeCredJWT(rawJwt)

	return vcBytes, err
}
