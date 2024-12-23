/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	_ "embed"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/did-go/doc/did"
	jsonldsig "github.com/trustbloc/did-go/doc/ld/processor"
	"github.com/trustbloc/kms-go/spi/kms"

	"github.com/trustbloc/vc-go/proof/testsupport"
)

//go:embed testdata/valid_doc.jsonld
var validDoc []byte //nolint:gochecknoglobals

func Test_AddDIDLinkedDataProof_VerifyDIDProof(t *testing.T) {
	r := require.New(t)

	didDoc, err := did.ParseDocument(validDoc)
	r.NoError(err)

	proofCreator, proofChecker := testsupport.NewKMSSigVerPair(t, kms.ED25519Type,
		"did:example:76e12ec712ebc6f1c221ebfeb1f#key1")

	ldpContext := &LinkedDataProofContext{
		SignatureType:           "Ed25519Signature2018",
		KeyType:                 kms.ED25519Type,
		SignatureRepresentation: SignatureProofValue,
		ProofCreator:            proofCreator,
		VerificationMethod:      "did:example:76e12ec712ebc6f1c221ebfeb1f#key1",
	}

	dl := createTestDocumentLoader(t)

	t.Run("Success LDP", func(t *testing.T) {
		signedDoc, err := AddDIDLinkedDataProof(
			didDoc, ldpContext, jsonldsig.WithDocumentLoader(dl))
		r.NoError(err)

		err = VerifyDIDProof(
			signedDoc,
			WithDIDProofChecker(proofChecker),
			WithDIDJSONLDDocumentLoader(dl),
		)
		r.NoError(err)

		r.Len(signedDoc.Proof, 1)
		r.Empty(signedDoc.Proof[0].JWS)
		r.NotEmpty(signedDoc.Proof[0].ProofValue)
	})

	t.Run("Success JWK", func(t *testing.T) {
		ldpContext.SignatureRepresentation = SignatureJWS

		signedDoc, err := AddDIDLinkedDataProof(
			didDoc, ldpContext, jsonldsig.WithDocumentLoader(dl))
		r.NoError(err)

		err = VerifyDIDProof(
			signedDoc,
			WithDIDProofChecker(proofChecker),
			WithDIDJSONLDDocumentLoader(dl),
		)
		r.NoError(err)

		r.Len(signedDoc.Proof, 1)
		r.NotEmpty(signedDoc.Proof[0].JWS)
		r.Empty(signedDoc.Proof[0].ProofValue)
	})
}
