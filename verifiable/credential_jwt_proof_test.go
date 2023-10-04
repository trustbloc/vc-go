/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/kms-go/spi/kms"

	"github.com/trustbloc/vc-go/jwt"
	"github.com/trustbloc/vc-go/proof/testsupport"
)

const jwtTestCredential = `
{
	"@context": [
	  "https://www.w3.org/2018/credentials/v1",
	  "https://www.w3.org/2018/credentials/examples/v1"
	],
	"type": ["VerifiableCredential", "UniversityDegreeCredential"],
	"credentialSubject": {
	  "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
	  "degree": {
		"type": "BachelorDegree",
		"university": "MIT"
	  }
	},
  "issuer": {
    "id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
    "name": "Example University"
  },
  "issuanceDate": "2010-01-01T19:23:24Z",
  "expirationDate": "2020-01-01T19:23:24Z"
}
`

const keyID = "1"

func TestParseCredentialFromJWS(t *testing.T) {
	testCred := []byte(jwtTestCredential)
	issuerKeyID := "did:example:76e12ec712ebc6f1c221ebfeb1f#key-1"
	proofCreator, proofChecker := testsupport.NewKMSSigVerPair(t, kms.ED25519Type, issuerKeyID)

	rsaProofCreator, rsaProofChecker := testsupport.NewKMSSigVerPair(t, kms.ED25519Type, issuerKeyID)

	t.Run("Decoding credential from JWS", func(t *testing.T) {
		vcFromJWT, err := parseTestCredential(t,
			createEdDSAJWS(t, testCred, proofCreator, issuerKeyID, false),
			WithProofChecker(proofChecker))

		require.NoError(t, err)

		vc, err := parseTestCredential(t, testCred, WithDisabledProofCheck())
		require.NoError(t, err)

		require.True(t, vcFromJWT.IsJWT())

		require.Equal(t, vc.Contents(), vcFromJWT.Contents())
	})

	t.Run("Decoding credential from JWS with minimized fields of \"vc\" claim", func(t *testing.T) {
		vcFromJWT, err := parseTestCredential(t,
			createEdDSAJWS(t, testCred, proofCreator, issuerKeyID, true),
			WithProofChecker(proofChecker))

		require.NoError(t, err)

		vc, err := parseTestCredential(t, testCred, WithDisabledProofCheck())
		require.NoError(t, err)

		require.True(t, vcFromJWT.IsJWT())

		require.Equal(t, vc.Contents(), vcFromJWT.Contents())
	})

	t.Run("Failed JWT signature verification of credential", func(t *testing.T) {
		vc, err := parseTestCredential(t,
			createRS256JWS(t, testCred, rsaProofCreator, issuerKeyID, true),
			// passing holder's key, while expecting issuer one
			WithProofChecker(rsaProofChecker))

		require.Error(t, err)
		require.Contains(t, err.Error(), "JWS proof check")
		require.Nil(t, vc)
	})

	t.Run("Not defined public key fetcher", func(t *testing.T) {
		vc, err := parseTestCredential(t, createRS256JWS(t, testCred, rsaProofCreator, issuerKeyID, true))

		require.Error(t, err)
		require.Contains(t, err.Error(), "jwt proofChecker is not defined")
		require.Nil(t, vc)
	})
}

func TestParseCredentialFromJWS_EdDSA(t *testing.T) {
	vcBytes := []byte(jwtTestCredential)

	pubKeyID := "did:example:76e12ec712ebc6f1c221ebfeb1f#key1"
	proofCreator, proofChecker := testsupport.NewKMSSigVerPair(t, kms.ED25519Type, pubKeyID)

	vc, err := parseTestCredential(t, vcBytes, WithDisabledProofCheck())
	require.NoError(t, err)

	vcJWSStr := createEdDSAJWS(t, vcBytes, proofCreator, pubKeyID, false)

	// unmarshal credential from JWS
	vcFromJWS, err := parseTestCredential(t, vcJWSStr, WithProofChecker(proofChecker))
	require.NoError(t, err)

	require.True(t, vcFromJWS.IsJWT())

	// unmarshalled credential must be the same as original one
	require.Equal(t, vc.Contents(), vcFromJWS.Contents())
}

func TestParseCredentialFromUnsecuredJWT(t *testing.T) {
	testCred := []byte(jwtTestCredential)

	t.Run("Unsecured JWT decoding with no fields minimization", func(t *testing.T) {
		vcFromJWT, err := parseTestCredential(t,
			createUnsecuredJWT(t, testCred, false), WithDisabledProofCheck())

		require.NoError(t, err)

		vc, err := parseTestCredential(t, testCred, WithDisabledProofCheck())
		require.NoError(t, err)

		require.Equal(t, vc, vcFromJWT)
	})

	t.Run("Unsecured JWT decoding with minimized fields", func(t *testing.T) {
		vcFromJWT, err := parseTestCredential(t, createUnsecuredJWT(t, testCred, true),
			WithDisabledProofCheck())

		require.NoError(t, err)

		vc, err := parseTestCredential(t, testCred, WithDisabledProofCheck())
		require.NoError(t, err)

		require.Equal(t, vc, vcFromJWT)
	})
}

func TestJwtWithExtension(t *testing.T) {
	pubKeyID := "did:example:76e12ec712ebc6f1c221ebfeb1f#key1"
	proofCreator, proofChecker := testsupport.NewKMSSigVerPair(t, kms.RSARS256Type, pubKeyID)

	vcJWS := createRS256JWS(t, []byte(jwtTestCredential), proofCreator, pubKeyID, true)

	// Decode to base credential.
	cred, err := parseTestCredential(t, vcJWS, WithProofChecker(proofChecker))
	require.NoError(t, err)
	require.NotNil(t, cred)

	// Decode to the Credential extension.
	udc, err := NewUniversityDegreeCredential(t, vcJWS, WithProofChecker(proofChecker))
	require.NoError(t, err)
	require.NotNil(t, udc)

	// Compare that base credentials are the same.
	require.Equal(t, udc.Base, *cred)
}

func TestRefineVcIssuerFromJwtClaims(t *testing.T) {
	t.Run("refine verifiable credential issuer defined by plain id", func(t *testing.T) {
		vcMap := map[string]interface{}{
			"issuer": "id to override",
		}
		refineVCIssuerFromJWTClaims(vcMap, "did:example:76e12ec712ebc6f1c221ebfeb1f")
		require.Equal(t, "did:example:76e12ec712ebc6f1c221ebfeb1f", vcMap["issuer"])
	})

	t.Run("refine verifiable credential issuer defined by structure", func(t *testing.T) {
		issuerMap := map[string]interface{}{"id": "id to override", "name": "Example University"}
		vcMap := map[string]interface{}{
			"issuer": issuerMap,
		}
		refineVCIssuerFromJWTClaims(vcMap, "did:example:76e12ec712ebc6f1c221ebfeb1f")
		// issuer id is refined
		require.Equal(t, "did:example:76e12ec712ebc6f1c221ebfeb1f", issuerMap["id"])
		// issuer name remains the same (i.e. not erased)
		require.Equal(t, "Example University", issuerMap["name"])
	})

	t.Run("refine not defined verifiable credential issuer", func(t *testing.T) {
		vcMap := make(map[string]interface{})
		refineVCIssuerFromJWTClaims(vcMap, "did:example:76e12ec712ebc6f1c221ebfeb1f")
		require.Equal(t, "did:example:76e12ec712ebc6f1c221ebfeb1f", vcMap["issuer"])
	})
}

func createRS256JWS(
	t *testing.T, cred []byte, signer jwt.ProofCreator, verificationKeyID string, minimize bool) []byte {
	vc, err := parseTestCredential(t, cred, WithDisabledProofCheck())
	require.NoError(t, err)

	jwtClaims, err := vc.JWTClaims(minimize)
	require.NoError(t, err)
	vcJWT, err := jwtClaims.MarshalJWSString(RS256, signer, verificationKeyID)
	require.NoError(t, err)

	return []byte(vcJWT)
}

func createEdDSAJWS(
	t *testing.T, cred []byte, signer jwt.ProofCreator, verificationKeyID string, minimize bool) []byte {
	vc, err := parseTestCredential(t, cred, WithDisabledProofCheck())
	require.NoError(t, err)

	jwtClaims, err := vc.JWTClaims(minimize)
	require.NoError(t, err)
	vcJWT, err := jwtClaims.MarshalJWSString(EdDSA, signer, verificationKeyID)
	require.NoError(t, err)

	return []byte(vcJWT)
}

func createUnsecuredJWT(t *testing.T, cred []byte, minimize bool) []byte {
	vc, err := parseTestCredential(t, cred, WithDisabledProofCheck())
	require.NoError(t, err)

	jwtClaims, err := vc.JWTClaims(minimize)
	require.NoError(t, err)
	vcJWT, err := jwtClaims.MarshalUnsecuredJWT()
	require.NoError(t, err)

	return []byte(vcJWT)
}
