/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	ldprocessor "github.com/trustbloc/did-go/doc/ld/processor"
	"github.com/trustbloc/kms-go/spi/kms"

	"github.com/trustbloc/vc-go/proof/testsupport"
	jsonutil "github.com/trustbloc/vc-go/util/json"
)

func TestParsePresentationFromLinkedDataProof(t *testing.T) {
	r := require.New(t)

	proofCreator, proofChecker := testsupport.NewKMSSigVerPair(t, kms.ED25519Type, "did:example:123456#key1")

	ldpContext := &LinkedDataProofContext{
		SignatureType:           "Ed25519Signature2018",
		KeyType:                 kms.ED25519Type,
		SignatureRepresentation: SignatureJWS,
		ProofCreator:            proofCreator,
		VerificationMethod:      "did:example:123456#key1",
	}

	vc, err := newTestPresentation(t, []byte(validPresentation), WithPresDisabledProofCheck())
	r.NoError(err)

	err = vc.AddLinkedDataProof(ldpContext, ldprocessor.WithDocumentLoader(createTestDocumentLoader(t)))
	r.NoError(err)

	vcBytes, err := json.Marshal(vc)
	r.NoError(err)

	vcWithLdp, err := newTestPresentation(t, vcBytes, WithPresProofChecker(proofChecker))
	r.NoError(err)

	r.NoError(err)
	r.Equal(vc, vcWithLdp)

	// signature suite is not passed, cannot make a proof check
	vcWithLdp, err = newTestPresentation(t, vcBytes)
	r.Error(err)
	require.Nil(t, vcWithLdp)
}

func TestPresentation_AddLinkedDataProof(t *testing.T) {
	r := require.New(t)

	proofCreator, _ := testsupport.NewKMSSigVerPair(t, kms.ED25519Type, "not used")

	ldpContext := &LinkedDataProofContext{
		SignatureType:           "Ed25519Signature2018",
		KeyType:                 kms.ED25519Type,
		SignatureRepresentation: SignatureProofValue,
		ProofCreator:            proofCreator,
	}

	t.Run("Add a valid Linked Data proof to VC", func(t *testing.T) {
		vp, err := newTestPresentation(t, []byte(validPresentation), WithPresDisabledProofCheck())
		r.NoError(err)

		err = vp.AddLinkedDataProof(ldpContext, ldprocessor.WithDocumentLoader(createTestDocumentLoader(t)))
		r.NoError(err)

		err = vp.AddLinkedDataProof(ldpContext, ldprocessor.WithDocumentLoader(createTestDocumentLoader(t)))
		r.NoError(err)

		err = vp.AddLinkedDataProof(ldpContext, ldprocessor.WithDocumentLoader(createTestDocumentLoader(t)))
		r.NoError(err)

		vpJSON, err := vp.MarshalJSON()
		r.NoError(err)

		vpMap, err := jsonutil.ToMap(vpJSON)
		r.NoError(err)

		r.Contains(vpMap, "proof")
		vpProof := vpMap["proof"]
		vpProofs, ok := vpProof.([]interface{})
		r.True(ok)
		r.Len(vpProofs, 3)
		newVPProof, ok := vpProofs[1].(map[string]interface{})
		r.True(ok)
		r.Contains(newVPProof, "created")
		r.Contains(newVPProof, "proofValue")
		r.Equal("Ed25519Signature2018", newVPProof["type"])
	})
}
