/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vc-go/jwt"
	"github.com/trustbloc/vc-go/proof/testsupport"

	"github.com/trustbloc/kms-go/spi/kms"

	utiltime "github.com/trustbloc/did-go/doc/util/time"
)

func TestParsePresentationFromJWS(t *testing.T) {
	vpBytes := []byte(validPresentation)

	holderSigner, proofChecher := testsupport.NewKMSSigVerPair(t, kms.RSARS256Type,
		"did:example:ebfeb1f712ebc6f1c276e12ec21#keys-1")

	_, wrongKeyProofChecher := testsupport.NewKMSSigVerPair(t, kms.RSARS256Type,
		"did:example:ebfeb1f712ebc6f1c276e12ec21#keys-1")

	t.Run("Decoding presentation from JWS", func(t *testing.T) {
		jws := createPresJWS(t, vpBytes, false, holderSigner)
		vpFromJWT, err := newTestPresentation(t, jws, WithPresProofChecker(proofChecher))
		require.NoError(t, err)

		vp, err := newTestPresentation(t, vpBytes, WithPresDisabledProofCheck())
		require.NoError(t, err)

		// Validate the JWT field, then clear it to validate against the original presentation.
		require.Equal(t, string(jws), vpFromJWT.JWT)
		vpFromJWT.JWT = ""

		require.Equal(t, vp, vpFromJWT)
	})

	t.Run("Decoding presentation from JWS with minimized fields of \"vp\" claim", func(t *testing.T) {
		jws := createPresJWS(t, vpBytes, true, holderSigner)
		vpFromJWT, err := newTestPresentation(t, jws, WithPresProofChecker(proofChecher))
		require.NoError(t, err)

		vp, err := newTestPresentation(t, vpBytes, WithPresDisabledProofCheck())
		require.NoError(t, err)

		require.Equal(t, string(jws), vpFromJWT.JWT)
		vpFromJWT.JWT = ""

		require.Equal(t, vp, vpFromJWT)
	})

	t.Run("Failed JWT signature verification of presentation", func(t *testing.T) {
		jws := createPresJWS(t, vpBytes, true, holderSigner)
		vp, err := newTestPresentation(t,
			jws,
			WithPresProofChecker(wrongKeyProofChecher))

		require.Error(t, err)
		require.Contains(t, err.Error(), "decoding of Verifiable Presentation from JWS")
		require.Nil(t, vp)
	})

	t.Run("Not defined public key fetcher", func(t *testing.T) {
		vp, err := newTestPresentation(t, createPresJWS(t, vpBytes, true, holderSigner))

		require.Error(t, err)
		require.Contains(t, err.Error(), "proof checker is not defined")
		require.Nil(t, vp)
	})
}

func TestParsePresentationFromJWS_EdDSA(t *testing.T) {
	vpBytes := []byte(validPresentation)

	vp, err := newTestPresentation(t, vpBytes, WithPresDisabledProofCheck())
	require.NoError(t, err)

	holderKeyID := vp.Holder + "#keys-" + keyID

	proofCreator, proofChecher := testsupport.NewKMSSigVerPair(t, kms.ED25519Type,
		holderKeyID)

	// marshal presentation into JWS using EdDSA (Ed25519 signature algorithm).
	jwtClaims, err := vp.JWTClaims([]string{}, false)
	require.NoError(t, err)

	vpJWSStr, err := jwtClaims.MarshalJWS(EdDSA, proofCreator, holderKeyID)
	require.NoError(t, err)

	// unmarshal presentation from JWS
	vpFromJWS, err := newTestPresentation(t,
		[]byte(vpJWSStr),
		WithPresProofChecker(proofChecher))
	require.NoError(t, err)

	require.Equal(t, vpJWSStr, vpFromJWS.JWT)
	vpFromJWS.JWT = ""

	// unmarshalled presentation must be the same as original one
	require.Equal(t, vp, vpFromJWS)
}

func TestParsePresentationFromUnsecuredJWT(t *testing.T) {
	vpBytes := []byte(validPresentation)

	t.Run("Decoding presentation from unsecured JWT", func(t *testing.T) {
		vpFromJWT, err := newTestPresentation(t, createPresUnsecuredJWT(t, vpBytes, false),
			WithPresDisabledProofCheck())

		require.NoError(t, err)

		vp, err := newTestPresentation(t, vpBytes, WithPresDisabledProofCheck())
		require.NoError(t, err)

		require.Equal(t, vp, vpFromJWT)
	})

	t.Run("Decoding presentation from unsecured JWT with minimized fields of \"vp\" claim", func(t *testing.T) {
		vpFromJWT, err := newTestPresentation(t,
			createPresUnsecuredJWT(t, vpBytes, true),
			WithPresDisabledProofCheck())

		require.NoError(t, err)

		vp, err := newTestPresentation(t, vpBytes, WithPresDisabledProofCheck())
		require.NoError(t, err)

		require.Equal(t, vp, vpFromJWT)
	})
}

func TestParsePresentationWithVCJWT(t *testing.T) {
	r := require.New(t)

	// Create and encode VP.
	issued := time.Date(2010, time.January, 1, 19, 23, 24, 0, time.UTC)
	expired := time.Date(2020, time.January, 1, 19, 23, 24, 0, time.UTC)

	subjBytes, err := json.Marshal(UniversityDegreeSubject{
		ID:     "did:example:ebfeb1f712ebc6f1c276e12ec21",
		Name:   "Jayden Doe",
		Spouse: "did:example:c276e12ec21ebfeb1f712ebc6f1",
		Degree: UniversityDegree{
			Type:       "BachelorDegree",
			University: "MIT",
		},
	})

	require.NoError(t, err)

	var subject Subject

	require.NoError(t, json.Unmarshal(subjBytes, &subject))

	vcc := CredentialContents{
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://www.w3.org/2018/credentials/examples/v1",
		},
		ID: "http://example.edu/credentials/1872",
		Types: []string{
			"VerifiableCredential",
			"UniversityDegreeCredential",
		},
		Subject: []Subject{subject},
		Issuer: &Issuer{
			ID:           "did:example:76e12ec712ebc6f1c221ebfeb1f",
			CustomFields: CustomFields{"name": "Example University"},
		},
		Issued:  utiltime.NewTime(issued),
		Expired: utiltime.NewTime(expired),
		Schemas: []TypedID{},
	}

	vc, err := CreateCredential(vcc, nil)
	r.NoError(err)

	t.Run("Presentation with VC defined as JWS", func(t *testing.T) {
		proofCreators, proofChecker := testsupport.NewKMSSignersAndVerifier(t, []testsupport.SigningKey{
			{Type: kms.RSARS256Type, PublicKeyID: "did:123#issuer-key"},
			{Type: kms.ED25519Type, PublicKeyID: "did:123#holder-key"},
		})

		jwtVC, err := vc.CreateSignedJWTVC(true, RS256, proofCreators[0], "did:123#issuer-key")
		r.NoError(err)
		r.NotNil(jwtVC)

		// Create and encode VP.
		vp, err := NewPresentation(WithCredentials(jwtVC))
		r.NoError(err)

		vp.ID = "urn:uuid:2978344f-8596-4c3a-a978-8fcaba3903c"
		vp.Holder = "did:example:fbfeb1f712ebc6f1c276e12ec21"

		jwtClaims, err := vp.JWTClaims([]string{}, true)
		require.NoError(t, err)

		vpJWS, err := jwtClaims.MarshalJWS(EdDSA, proofCreators[1], "did:123#holder-key")
		r.NoError(err)

		// Decode VP
		vpDecoded, err := newTestPresentation(t, []byte(vpJWS), WithPresProofChecker(proofChecker))
		r.NoError(err)
		vpCreds, err := vpDecoded.MarshalledCredentials()
		r.NoError(err)
		r.Len(vpCreds, 1)

		vcDecoded, err := parseTestCredential(t, vpCreds[0], WithProofChecker(proofChecker))
		r.NoError(err)

		r.Equal(jwtVC.stringJSON(t), vcDecoded.stringJSON(t))
	})

	t.Run("Presentation with VC defined as VC struct", func(t *testing.T) {
		proofCreators, proofCreator := testsupport.NewKMSSignersAndVerifier(t, []testsupport.SigningKey{
			{Type: kms.ED25519Type, PublicKeyID: "did:123#holder-key"},
		})
		// Create and encode VP.
		vp, err := NewPresentation(WithCredentials(vc))
		r.NoError(err)

		vp.ID = "urn:uuid:5978344f-8596-4c3a-a978-8fcaba3903c"
		vp.Holder = "did:example:abfeb1f712ebc6f1c276e12ec21"

		jwtClaims, err := vp.JWTClaims([]string{}, true)
		require.NoError(t, err)

		vpJWS, err := jwtClaims.MarshalJWS(EdDSA, proofCreators[0], "did:123#holder-key")
		r.NoError(err)

		// Decode VP
		vpDecoded, err := newTestPresentation(t, []byte(vpJWS), WithPresProofChecker(proofCreator))
		r.NoError(err)
		vpCreds, err := vpDecoded.MarshalledCredentials()
		r.NoError(err)
		r.Len(vpCreds, 1)

		vcDecoded, err := parseTestCredential(t, vpCreds[0], WithDisabledProofCheck())
		r.NoError(err)

		r.Equal(vc.stringJSON(t), vcDecoded.stringJSON(t))
	})

	t.Run("Failed check of VC due to invalid JWS", func(t *testing.T) {
		proofCreators, _ := testsupport.NewKMSSignersAndVerifier(t, []testsupport.SigningKey{
			{Type: kms.RSARS256Type, PublicKeyID: "did:123#issuer-key"},
		})

		jwtVC, err := vc.CreateSignedJWTVC(true, RS256, proofCreators[0], "did:123#issuer-key")
		r.NoError(err)
		r.NotNil(jwtVC)

		vp, err := NewPresentation(WithCredentials(jwtVC))
		r.NoError(err)

		vp.ID = "urn:uuid:0978344f-8596-4c3a-a978-8fcaba3903c"
		vp.Holder = "did:example:ebfeb2f712ebc6f1c276e12ec21"

		jwtClaims, err := vp.JWTClaims([]string{}, true)
		require.NoError(t, err)

		issuerProofCreator, proofChecker := testsupport.NewKMSSignersAndVerifier(t, []testsupport.SigningKey{
			{Type: kms.RSARS256Type, PublicKeyID: "did:123#issuer-key"},
			{Type: kms.ED25519Type, PublicKeyID: "did:123#holder-key"},
		})
		vpJWS, err := jwtClaims.MarshalJWS(EdDSA, issuerProofCreator[1], "did:123#holder-key")
		r.NoError(err)

		// Decode VP
		vp, err = newTestPresentation(t, []byte(vpJWS), WithPresProofChecker(proofChecker))
		r.Error(err)
		r.Contains(err.Error(), "decode credentials of presentation")
		r.Contains(err.Error(), "JWS proof check")
		r.Nil(vp)
	})
}

func createPresJWS(t *testing.T, vpBytes []byte, minimize bool, signer jwt.ProofCreator) []byte {
	vp, err := newTestPresentation(t, vpBytes, WithPresDisabledProofCheck())
	require.NoError(t, err)

	jwtClaims, err := vp.JWTClaims([]string{}, minimize)
	require.NoError(t, err)

	vpJWT, err := jwtClaims.MarshalJWS(RS256, signer, vp.Holder+"#keys-"+keyID)
	require.NoError(t, err)

	return []byte(vpJWT)
}

func createPresUnsecuredJWT(t *testing.T, cred []byte, minimize bool) []byte {
	vp, err := newTestPresentation(t, cred, WithPresDisabledProofCheck())
	require.NoError(t, err)

	jwtClaims, err := vp.JWTClaims([]string{}, minimize)
	require.NoError(t, err)

	vpJWT, err := jwtClaims.MarshalUnsecuredJWT()
	require.NoError(t, err)

	return []byte(vpJWT)
}
