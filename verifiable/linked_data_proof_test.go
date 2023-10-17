/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	ldprocessor "github.com/trustbloc/did-go/doc/ld/processor"
	"github.com/trustbloc/kms-go/spi/kms"

	"github.com/trustbloc/vc-go/proof/testsupport"
	"github.com/trustbloc/vc-go/verifiable/lddocument"
)

// This example is generated using https://transmute-industries.github.io/vc-greeting-card
func TestLinkedDataProofSignerAndVerifier(t *testing.T) {
	vcJSON := `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "id": "https://example.com/credentials/1872",
  "type": [
    "VerifiableCredential",
    "UniversityDegreeCredential"
  ],
  "issuer": "did:key:z6Mkj7of2aaooXhTJvJ5oCL9ZVcAS472ZBuSjYyXDa4bWT32",
  "issuanceDate": "2020-01-17T15:14:09.724Z",
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "degree": {
      "type": "BachelorDegree"
    },
    "name": "Jayden Doe",
    "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
  }
}
`

	proofCreators, proofCheker := testsupport.NewKMSSignersAndVerifier(t, []testsupport.SigningKey{
		{Type: kms.ED25519Type, PublicKeyID: "did:example:123456#key1"},
		{Type: kms.ECDSASecp256k1TypeIEEEP1363, PublicKeyID: "did:example:123456#key2"},
	})

	vcWithEd25519Proof := prepareVCWithEd25519LDP(t, vcJSON, proofCreators[0])

	vcWithEd25519ProofBytes, err := vcWithEd25519Proof.MarshalJSON()
	require.NoError(t, err)

	vcWithSecp256k1Proof := prepareVCWithSecp256k1LDP(t, vcJSON, proofCreators[1])

	vcWithSecp256k1ProofBytes, err := vcWithSecp256k1Proof.MarshalJSON()
	require.NoError(t, err)
	require.NotEmpty(t, vcWithSecp256k1ProofBytes)

	t.Run("Single signature suite", func(t *testing.T) {
		vcDecoded, err := parseTestCredential(t, vcWithEd25519ProofBytes,
			WithProofChecker(proofCheker))
		require.NoError(t, err)
		require.Equal(t, vcWithEd25519Proof.ToRawJSON(), vcDecoded.ToRawJSON())
	})

	t.Run("Several signature suites", func(t *testing.T) {
		vcDecoded, err := parseTestCredential(t, vcWithEd25519ProofBytes,
			WithProofChecker(proofCheker))
		require.NoError(t, err)
		require.Equal(t, vcWithEd25519Proof.ToRawJSON(), vcDecoded.ToRawJSON())

		vcDecoded, err = parseTestCredential(t, vcWithSecp256k1ProofBytes,
			WithProofChecker(proofCheker))
		require.NoError(t, err)
		require.Equal(t, vcWithSecp256k1Proof.ToRawJSON(), vcDecoded.ToRawJSON())
	})
}

func prepareVCWithEd25519LDP(t *testing.T, vcJSON string, signer lddocument.ProofCreator) *Credential {
	vc, err := ParseCredential([]byte(vcJSON),
		WithJSONLDDocumentLoader(createTestDocumentLoader(t)),
		WithDisabledProofCheck())
	require.NoError(t, err)
	created, err := time.Parse(time.RFC3339, "2018-03-15T00:00:00Z")
	require.NoError(t, err)

	err = vc.AddLinkedDataProof(&LinkedDataProofContext{
		SignatureType:           "Ed25519Signature2018",
		KeyType:                 kms.ED25519Type,
		ProofCreator:            signer,
		SignatureRepresentation: SignatureJWS,
		Created:                 &created,
		VerificationMethod:      "did:example:123456#key1",
	}, ldprocessor.WithDocumentLoader(createTestDocumentLoader(t)))
	require.NoError(t, err)

	require.Len(t, vc.Proofs(), 1)

	return vc
}

func prepareVCWithSecp256k1LDP(t *testing.T, vcJSON string, signer lddocument.ProofCreator) *Credential {
	vc, err := ParseCredential([]byte(vcJSON),
		WithJSONLDDocumentLoader(createTestDocumentLoader(t)),
		WithDisabledProofCheck())
	require.NoError(t, err)

	err = vc.AddLinkedDataProof(&LinkedDataProofContext{
		SignatureType:           "EcdsaSecp256k1Signature2019",
		KeyType:                 kms.ECDSASecp256k1TypeIEEEP1363,
		ProofCreator:            signer,
		SignatureRepresentation: SignatureJWS,
		VerificationMethod:      "did:example:123456#key2",
	}, ldprocessor.WithDocumentLoader(createTestDocumentLoader(t)))
	require.NoError(t, err)

	require.Len(t, vc.Proofs(), 1)

	return vc
}
