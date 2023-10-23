/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/bbs-signature-go/bbs12381g2pub"
	jsonld "github.com/trustbloc/did-go/doc/ld/processor"
	"github.com/trustbloc/kms-go/spi/kms"

	"github.com/trustbloc/vc-go/crypto-ext/testutil"
	"github.com/trustbloc/vc-go/proof/creator"
	"github.com/trustbloc/vc-go/proof/defaults"
	"github.com/trustbloc/vc-go/proof/ldproofs/bbsblssignature2020"
	"github.com/trustbloc/vc-go/proof/testsupport"

	jsonutil "github.com/trustbloc/vc-go/util/json"
)

//nolint:lll
func TestCredential_GenerateBBSSelectiveDisclosure(t *testing.T) {
	s := "uBlesrb_p6VIl-DrJ4Kj7DJ2S45uDqq6cJSgwdw_tVXWazl1XnjQxKsIzrY1RqffBqqT1oFTPi5Nwb_3IGMTWvXeGU7xwZOP8K1jybjknN0ADhp3i8JjTDeuUWH_sixv8ydcx4Qpqq-mMOX7nEm7Dg"
	_, err := base64.RawURLEncoding.DecodeString(s)
	require.NoError(t, err)

	vcJSON := `
	{
	 "@context": [
	   "https://www.w3.org/2018/credentials/v1",
	   "https://w3id.org/citizenship/v1",
	   "https://w3id.org/security/bbs/v1"
	 ],
	 "id": "https://issuer.oidp.uscis.gov/credentials/83627465",
	 "type": [
	   "VerifiableCredential",
	   "PermanentResidentCard"
	 ],
	 "issuer": "did:example:489398593",
	 "identifier": "83627465",
	 "name": "Permanent Resident Card",
	 "description": "Government of Example Permanent Resident Card.",
	 "issuanceDate": "2019-12-03T12:19:52Z",
	 "expirationDate": "2029-12-03T12:19:52Z",
	 "credentialSubject": {
	   "id": "did:example:b34ca6cd37bbf23",
	   "type": [
	     "PermanentResident",
	     "Person"
	   ],
	   "givenName": "JOHN",
	   "familyName": "SMITH",
	   "gender": "Male",
	   "image": "data:image/png;base64,iVBORw0KGgokJggg==",
	   "residentSince": "2015-01-01",
	   "lprCategory": "C09",
	   "lprNumber": "999-999-999",
	   "commuterClassification": "C1",
	   "birthCountry": "Bahamas",
	   "birthDate": "1958-07-17"
	 }
	}
	`

	pubKey, privKey, err := bbs12381g2pub.GenerateKeyPair(sha256.New, nil)
	require.NoError(t, err)

	pubKeyBytes, err := pubKey.Marshal()
	require.NoError(t, err)

	vc, err := parseTestCredential(t, []byte(vcJSON), WithDisabledProofCheck())
	require.NoError(t, err)
	require.Len(t, vc.Proofs(), 0)

	bbsKeyFetcher := signVCWithBBS(t, privKey, pubKeyBytes, vc)
	signVCWithEd25519(t, vc)

	revealJSON := `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/citizenship/v1",
    "https://w3id.org/security/bbs/v1"
  ],
  "type": ["VerifiableCredential", "PermanentResidentCard"],
  "@explicit": true,
  "identifier": {},
  "issuer": {},
  "issuanceDate": {},
  "credentialSubject": {
    "@explicit": true,
    "type": ["PermanentResident", "Person"],
    "givenName": {},
    "familyName": {},
    "gender": {}
  }
}
`

	revealDoc, err := jsonutil.ToMap(revealJSON)
	require.NoError(t, err)

	nonce := []byte("nonce")

	vcOptions := []CredentialOpt{WithJSONLDDocumentLoader(createTestDocumentLoader(t))}

	vcWithSelectiveDisclosure, err := vc.GenerateBBSSelectiveDisclosure(revealDoc, nonce,
		&BBSProofCreator{
			ProofDerivation:            bbs12381g2pub.New(),
			VerificationMethodResolver: bbsKeyFetcher,
		},
		vcOptions...)
	require.NoError(t, err)
	require.NotNil(t, vcWithSelectiveDisclosure)
	require.Len(t, vcWithSelectiveDisclosure.Proofs(), 1)

	vcSelectiveDisclosureBytes, err := json.Marshal(vcWithSelectiveDisclosure)
	require.NoError(t, err)

	vcVerified, err := parseTestCredential(t, vcSelectiveDisclosureBytes,
		WithProofChecker(defaults.NewDefaultProofChecker(bbsKeyFetcher)),
	)
	require.NoError(t, err)
	require.NotNil(t, vcVerified)

	// error cases
	t.Run("failed generation of selective disclosure", func(t *testing.T) {
		var (
			anotherPubKey      *bbs12381g2pub.PublicKey
			anotherPubKeyBytes []byte
		)

		anotherPubKey, _, err = bbs12381g2pub.GenerateKeyPair(sha256.New, nil)
		require.NoError(t, err)

		anotherPubKeyBytes, err = anotherPubKey.Marshal()
		require.NoError(t, err)

		bbsAnotherKeyFetcher := testsupport.NewSingleKeyResolver("did:example:123456#key1", anotherPubKeyBytes, "Bls12381G2Key2020", "")

		vcWithSelectiveDisclosure, err = vc.GenerateBBSSelectiveDisclosure(revealDoc, nonce,
			&BBSProofCreator{
				ProofDerivation:            bbs12381g2pub.New(),
				VerificationMethodResolver: bbsAnotherKeyFetcher,
			},
			WithJSONLDDocumentLoader(createTestDocumentLoader(t)))
		require.Error(t, err)
		require.Contains(t, err.Error(), "create VC selective disclosure")
		require.Empty(t, vcWithSelectiveDisclosure)
	})

	t.Run("bbs proof creator not defined", func(t *testing.T) {
		vcWithSelectiveDisclosure, err = vc.GenerateBBSSelectiveDisclosure(revealDoc, nonce,
			nil)
		require.Error(t, err)
		require.EqualError(t, err, "bbs proof creator not defined")
		require.Empty(t, vcWithSelectiveDisclosure)
	})

	t.Run("Reveal document with hidden VC mandatory field", func(t *testing.T) {
		revealJSONWithMissingIssuer := `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/citizenship/v1",
    "https://w3id.org/security/bbs/v1"
  ],
  "type": ["VerifiableCredential", "PermanentResidentCard"],
  "@explicit": true,
  "identifier": {},
  "issuanceDate": {},
  "credentialSubject": {
    "@explicit": true,
    "type": ["PermanentResident", "Person"],
    "givenName": {},
    "familyName": {},
    "gender": {}
  }
}
`

		revealDoc, err = jsonutil.ToMap(revealJSONWithMissingIssuer)
		require.NoError(t, err)

		vcWithSelectiveDisclosure, err = vc.GenerateBBSSelectiveDisclosure(revealDoc, nonce,
			&BBSProofCreator{
				ProofDerivation:            bbs12381g2pub.New(),
				VerificationMethodResolver: bbsKeyFetcher,
			},
			vcOptions...)
		require.Error(t, err)
		require.Contains(t, err.Error(), "issuer is required")
		require.Nil(t, vcWithSelectiveDisclosure)
	})

	t.Run("VC with no embedded proof", func(t *testing.T) {
		vc.ResetProofs(nil)
		vcWithSelectiveDisclosure, err = vc.GenerateBBSSelectiveDisclosure(revealDoc, nonce,
			&BBSProofCreator{
				ProofDerivation:            bbs12381g2pub.New(),
				VerificationMethodResolver: bbsKeyFetcher,
			},
			vcOptions...)
		require.Error(t, err)
		require.EqualError(t, err, "expected at least one proof present")
		require.Empty(t, vcWithSelectiveDisclosure)
	})
}

func signVCWithBBS(t *testing.T, privKey *bbs12381g2pub.PrivateKey, pubKeyBytes []byte,
	vc *Credential) *testsupport.VMResolver {
	t.Helper()

	bbsSigner, err := testutil.NewBBSSigner(privKey)
	require.NoError(t, err)

	bbsProofCreator := creator.New(creator.WithLDProofType(bbsblssignature2020.New(), bbsSigner))

	ldpContext := &LinkedDataProofContext{
		SignatureType:           "BbsBlsSignature2020",
		KeyType:                 kms.BLS12381G2Type,
		SignatureRepresentation: SignatureProofValue,
		ProofCreator:            bbsProofCreator,
		VerificationMethod:      "did:example:123456#key1",
	}

	err = vc.AddLinkedDataProof(ldpContext, jsonld.WithDocumentLoader(createTestDocumentLoader(t)))
	require.NoError(t, err)

	vcSignedBytes, err := json.Marshal(vc)
	require.NoError(t, err)
	require.NotEmpty(t, vcSignedBytes)

	bbsKeyFetcher := testsupport.NewSingleKeyResolver("did:example:123456#key1", pubKeyBytes, "Bls12381G2Key2020", "")

	vcVerified, err := parseTestCredential(t, vcSignedBytes,
		WithProofChecker(defaults.NewDefaultProofChecker(bbsKeyFetcher)),
	)
	require.NoError(t, err)
	require.NotEmpty(t, vcVerified)

	return bbsKeyFetcher
}

func signVCWithEd25519(t *testing.T, vc *Credential) {
	t.Helper()

	signer, _ := testsupport.NewKMSSigVerPair(t, kms.ED25519Type, "did:example:123456#key1")

	ldpContext := &LinkedDataProofContext{
		SignatureType:           "Ed25519Signature2018",
		KeyType:                 kms.ED25519Type,
		SignatureRepresentation: SignatureProofValue,
		ProofCreator:            signer,
		VerificationMethod:      "did:example:123456#key1",
	}

	err := vc.AddLinkedDataProof(ldpContext, jsonld.WithDocumentLoader(createTestDocumentLoader(t)))
	require.NoError(t, err)
}
