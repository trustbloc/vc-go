/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vc-go/proof/testsupport"

	"github.com/trustbloc/kms-go/spi/kms"
)

func TestV1JWTCredClaimsMarshalJWS(t *testing.T) {
	proofCreator, proofChecker := testsupport.NewKMSSigVerPair(t, kms.RSARS256Type, "did:example:76e12ec712ebc6f1c221ebfeb1f#key1")

	vc, err := parseTestCredential(t, []byte(v1ValidCredential), WithDisabledProofCheck())
	require.NoError(t, err)

	jwtClaims, err := vc.JWTClaims(true)
	require.NoError(t, err)

	t.Run("Marshal signed JWT", func(t *testing.T) {
		jws, err := jwtClaims.MarshalJWSString(RS256, proofCreator, "did:example:76e12ec712ebc6f1c221ebfeb1f#key1")
		require.NoError(t, err)

		jwtVC, err := ParseCredential([]byte(jws), WithProofChecker(proofChecker))

		require.NoError(t, err)
		require.Equal(t, vc.stringJSON(t), jsonObjectToString(t, jwtVC.ToRawJSON()))
	})
}

func TestV2JWTCredClaimsMarshalJWS(t *testing.T) {
	proofCreator, proofChecker := testsupport.NewKMSSigVerPair(t, kms.RSARS256Type, "did:example:76e12ec712ebc6f1c221ebfeb1f#key1")

	vc, err := parseTestCredential(t, []byte(v2ValidCredential), WithDisabledProofCheck())
	require.NoError(t, err)

	jwtClaims, err := vc.JWTClaims(true)
	require.NoError(t, err)

	t.Run("Marshal signed JWT", func(t *testing.T) {
		jws, err := jwtClaims.MarshalJWSString(RS256, proofCreator, "did:example:76e12ec712ebc6f1c221ebfeb1f#key1")
		require.NoError(t, err)

		jwtVC, err := ParseCredential([]byte(jws), WithProofChecker(proofChecker))

		require.NoError(t, err)
		require.Equal(t, vc.stringJSON(t), jsonObjectToString(t, jwtVC.ToRawJSON()))
	})
}

type invalidCredClaims struct {
	*jwt.Claims

	Credential int `json:"vc,omitempty"`
}

func TestV1CredJWSDecoderUnmarshal(t *testing.T) {
	verificationKeyID := "did:example:76e12ec712ebc6f1c221ebfeb1f#key1"
	otherVerificationKeyID := "did:example:76e12ec712ebc6f1c221ebfeb1f#key2"

	proofCreators, proofChecker := testsupport.NewKMSSignersAndVerifier(t, []*testsupport.SigningKey{
		{Type: kms.RSARS256, PublicKeyID: verificationKeyID},
		{Type: kms.RSARS256, PublicKeyID: otherVerificationKeyID},
	})

	validJWS := createRS256JWS(t, []byte(jwtTestCredential), proofCreators[0], verificationKeyID, false)
	jwsWithWrongKey := createRS256JWS(t, []byte(jwtTestCredential), proofCreators[0], otherVerificationKeyID, false)

	t.Run("Successful JWS decoding", func(t *testing.T) {
		jwtVC, err := ParseCredential(validJWS, WithProofChecker(proofChecker))
		require.NoError(t, err)

		vc, err := parseTestCredential(t, []byte(jwtTestCredential), WithDisabledProofCheck())
		require.NoError(t, err)
		require.Equal(t, vc.stringJSON(t), jsonObjectToString(t, jwtVC.ToRawJSON()))
	})

	t.Run("JWS with 'iss' and issuer.id miss match", func(t *testing.T) {
		original := strings.Split(string(validJWS), ".")

		var claims map[string]interface{}
		claimsBytes, err := base64.RawURLEncoding.DecodeString(original[1])
		require.NoError(t, err)

		require.NoError(t, json.Unmarshal(claimsBytes, &claims))

		claims["iss"] = "did:example:other_issuer"

		claimsBytes, err = json.Marshal(claims)
		require.NoError(t, err)

		jwsWithMissMatch := original[0] + "." + base64.RawURLEncoding.EncodeToString(claimsBytes) + "." + original[2]

		_, err = ParseCredential([]byte(jwsWithMissMatch), WithProofChecker(proofChecker))
		require.ErrorContains(t, err, "iss(did:example:other_issuer) claim and "+
			"vc.issuer.id(did:example:76e12ec712ebc6f1c221ebfeb1f) missmatch")
	})

	t.Run("Invalid serialized JWS", func(t *testing.T) {
		_, err := ParseCredential([]byte(`"invalid JWS"`), WithProofChecker(proofChecker))
		require.Error(t, err)
		require.Contains(t, err.Error(), "unmarshal new credential")
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

		_, err = ParseCredential([]byte(jwtCompact), WithProofChecker(proofChecker))
		require.Error(t, err)
		require.Contains(t, err.Error(), "decode new JWT credential")
	})

	t.Run("Invalid signature of JWS", func(t *testing.T) {
		_, err := ParseCredential(jwsWithWrongKey, WithProofChecker(proofChecker))
		require.Error(t, err)
		require.Contains(t, err.Error(), "JWS proof check")
	})
}
