/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vc-go/proof/testsupport"

	ariesjose "github.com/trustbloc/kms-go/doc/jose"
	"github.com/trustbloc/kms-go/spi/kms"
)

func TestJWTCredClaimsMarshalJWS(t *testing.T) {
	proofCreator, proofChecker := testsupport.NewKMSSigVerPair(t, kms.RSARS256Type, "did:123#key1")

	vc, err := parseTestCredential(t, []byte(validCredential), WithDisabledProofCheck())
	require.NoError(t, err)

	jwtClaims, err := vc.JWTClaims(true)
	require.NoError(t, err)

	t.Run("Marshal signed JWT", func(t *testing.T) {
		jws, err := jwtClaims.MarshalJWSString(RS256, proofCreator, "did:123#key1")
		require.NoError(t, err)

		headers, vcBytes, err := decodeCredJWS(jws, true, proofChecker)
		require.NoError(t, err)
		require.Equal(t, ariesjose.Headers{"alg": "RS256", "kid": "did:123#key1"}, headers)

		var vcRaw JSONObject
		err = json.Unmarshal(vcBytes, &vcRaw)
		require.NoError(t, err)

		require.NoError(t, err)
		require.Equal(t, vc.stringJSON(t), jsonObjectToString(t, vcRaw))
	})
}

type invalidCredClaims struct {
	*jwt.Claims

	Credential int `json:"vc,omitempty"`
}

func TestCredJWSDecoderUnmarshal(t *testing.T) {
	verificationKeyID := "did:123#key1"
	otherVerificationKeyID := "did:123#key2"

	proofCreators, proofChecker := testsupport.NewKMSSignersAndVerifier(t, []testsupport.SigningKey{
		{Type: kms.RSARS256, PublicKeyID: verificationKeyID},
		{Type: kms.RSARS256, PublicKeyID: otherVerificationKeyID},
	})

	validJWS := createRS256JWS(t, []byte(jwtTestCredential), proofCreators[0], verificationKeyID, false)
	jwsWithWrongKey := createRS256JWS(t, []byte(jwtTestCredential), proofCreators[0], otherVerificationKeyID, false)

	t.Run("Successful JWS decoding", func(t *testing.T) {
		headers, vcBytes, err := decodeCredJWS(string(validJWS), true, proofChecker)
		require.NoError(t, err)
		require.NotNil(t, headers)

		var vcRaw JSONObject
		err = json.Unmarshal(vcBytes, &vcRaw)
		require.NoError(t, err)

		vc, err := parseTestCredential(t, []byte(jwtTestCredential), WithDisabledProofCheck())
		require.NoError(t, err)
		require.Equal(t, vc.stringJSON(t), jsonObjectToString(t, vcRaw))
	})

	t.Run("Invalid serialized JWS", func(t *testing.T) {
		joseHeaders, jws, err := decodeCredJWS("invalid JWS", true, proofChecker)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unmarshal VC JWT claims")
		require.Nil(t, jws)
		require.Nil(t, joseHeaders)
	})

	t.Run("Invalid format of \"vc\" claim", func(t *testing.T) {
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		key := jose.SigningKey{Algorithm: jose.RS256, Key: privKey}

		signer, err := jose.NewSigner(key, &jose.SignerOptions{})
		require.NoError(t, err)

		claims := &invalidCredClaims{
			Claims:     &jwt.Claims{},
			Credential: 55, // "vc" claim of invalid format
		}

		jwtCompact, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
		require.NoError(t, err)

		joseHeaders, jws, err := decodeCredJWS(jwtCompact, true, proofChecker)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unmarshal VC JWT claims")
		require.Nil(t, jws)
		require.Nil(t, joseHeaders)
	})

	t.Run("Invalid signature of JWS", func(t *testing.T) {
		joseHeaders, jws, err := decodeCredJWS(string(jwsWithWrongKey), true, proofChecker)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unmarshal VC JWT claims")
		require.Nil(t, jws)
		require.Nil(t, joseHeaders)
	})
}
