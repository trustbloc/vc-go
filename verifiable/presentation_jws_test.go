/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vc-go/proof/creator"
	"github.com/trustbloc/vc-go/proof/testsupport"

	"github.com/trustbloc/kms-go/spi/kms"
)

func TestJWTPresClaims_MarshalJWS(t *testing.T) {
	vp, err := newTestPresentation(t, []byte(validPresentation), WithPresDisabledProofCheck())
	require.NoError(t, err)

	proofCreator, proofChecker := testsupport.NewKMSSigVerPair(t, kms.RSARS256Type, "did:123#key1")
	require.NoError(t, err)

	jws := createCredJWS(t, vp, proofCreator)

	_, rawVC, err := decodeVPFromJWS(jws, proofChecker)

	require.NoError(t, err)
	require.Equal(t, vp.stringJSON(t), jsonObjectToString(t, rawVC))
}

type invalidPresClaims struct {
	*jwt.Claims

	Presentation int `json:"vp,omitempty"`
}

func TestUnmarshalPresJWSClaims(t *testing.T) {
	holderProofCreator, proofChecker := testsupport.NewKMSSigVerPair(t, kms.RSARS256Type, "did:123#key1")

	t.Run("Successful JWS decoding", func(t *testing.T) {
		vp, err := newTestPresentation(t, []byte(validPresentation), WithPresDisabledProofCheck())
		require.NoError(t, err)

		jws := createCredJWS(t, vp, holderProofCreator)

		claims, err := unmarshalPresJWSClaims(jws, proofChecker)
		require.NoError(t, err)
		require.Equal(t, vp.stringJSON(t), jsonObjectToString(t, claims.Presentation))
	})

	t.Run("Invalid serialized JWS", func(t *testing.T) {
		claims, err := unmarshalPresJWSClaims("invalid JWS", proofChecker)
		require.Error(t, err)
		require.Contains(t, err.Error(), "parse JWT")
		require.Nil(t, claims)
	})

	t.Run("Invalid format of \"vp\" claim", func(t *testing.T) {
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		key := jose.SigningKey{Algorithm: jose.RS256, Key: privKey}

		signer, err := jose.NewSigner(key, &jose.SignerOptions{})
		require.NoError(t, err)

		claims := &invalidPresClaims{
			Claims:       &jwt.Claims{},
			Presentation: 55, // "vp" claim of invalid format
		}

		token, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
		require.NoError(t, err)

		uc, err := unmarshalPresJWSClaims(token, proofChecker)
		require.Error(t, err)
		require.Contains(t, err.Error(), "parse JWT")
		require.Nil(t, uc)
	})

	t.Run("Invalid signature of JWS", func(t *testing.T) {
		vp, err := newTestPresentation(t, []byte(validPresentation), WithPresDisabledProofCheck())
		require.NoError(t, err)

		jws := createCredJWS(t, vp, holderProofCreator)

		_, otherProofChecker := testsupport.NewKMSSigVerPair(t, kms.RSARS256Type, "did:123#key1")

		uc, err := unmarshalPresJWSClaims(jws, otherProofChecker)
		require.Error(t, err)
		require.Contains(t, err.Error(), "jwt proof check")
		require.Nil(t, uc)
	})
}

func createCredJWS(t *testing.T, vp *Presentation, signer *creator.ProofCreator) string {
	claims, err := newJWTPresClaims(vp, []string{}, false)
	require.NoError(t, err)
	require.NotNil(t, claims)

	jws, err := claims.MarshalJWS(RS256, signer, "did:123#key1")
	require.NoError(t, err)

	return jws
}
