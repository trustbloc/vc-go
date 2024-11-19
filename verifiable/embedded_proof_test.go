/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"testing"

	"github.com/stretchr/testify/require"
	kmsapi "github.com/trustbloc/kms-go/spi/kms"

	"github.com/trustbloc/vc-go/proof/testsupport"
)

func Test_checkEmbeddedProofBytes(t *testing.T) {
	expectedIssuer := "did:example:76e12ec712ebc6f1c221ebfeb1f"

	r := require.New(t)
	nonJSONBytes := []byte("not JSON")
	defaultOpts := &embeddedProofCheckOpts{}

	t.Run("Happy path - single proof", func(t *testing.T) {
		vc, proofChecker := createVCWithLinkedDataProof(t)
		vcBytes := vc.byteJSON(t)

		err := checkEmbeddedProofBytes(vcBytes, &expectedIssuer, &embeddedProofCheckOpts{
			proofChecker:         proofChecker,
			jsonldCredentialOpts: jsonldCredentialOpts{jsonldDocumentLoader: createTestDocumentLoader(t)},
		})

		require.NoError(t, err)
	})

	t.Run("single proof, any expected issuer", func(t *testing.T) {
		vc, proofChecker := createVCWithLinkedDataProof(t)
		vcBytes := vc.byteJSON(t)

		err := checkEmbeddedProofBytes(vcBytes, nil, &embeddedProofCheckOpts{
			proofChecker:         proofChecker,
			jsonldCredentialOpts: jsonldCredentialOpts{jsonldDocumentLoader: createTestDocumentLoader(t)},
		})

		require.NoError(t, err)
	})

	t.Run("Happy path - two proofs", func(t *testing.T) {
		vc, proofChecker := createVCWithTwoLinkedDataProofs(t)
		vcBytes := vc.byteJSON(t)

		err := checkEmbeddedProofBytes(vcBytes, &expectedIssuer, &embeddedProofCheckOpts{
			proofChecker:         proofChecker,
			jsonldCredentialOpts: jsonldCredentialOpts{jsonldDocumentLoader: createTestDocumentLoader(t)},
		})

		require.NoError(t, err)
	})

	t.Run("Does not check the embedded proof if credentialOpts.disabledProofCheck", func(t *testing.T) {
		err := checkEmbeddedProofBytes(nonJSONBytes, nil, &embeddedProofCheckOpts{disabledProofCheck: true})
		r.NoError(err)
	})

	t.Run("error on checking non-JSON embedded proof", func(t *testing.T) {
		err := checkEmbeddedProofBytes(nonJSONBytes, nil, defaultOpts)
		r.Error(err)
		r.Contains(err.Error(), "embedded proof is not JSON")
	})

	t.Run("check embedded proof without \"proof\" element", func(t *testing.T) {
		docWithoutProof := `{
  "@context": "https://www.w3.org/2018/credentials/v1"
}`
		err := checkEmbeddedProofBytes([]byte(docWithoutProof), nil, defaultOpts)
		r.Error(err)
		r.EqualError(err, "proof not found")
	})

	t.Run("error on not map \"proof\" element", func(t *testing.T) {
		docWithNotMapProof := `{
  "@context": "https://www.w3.org/2018/credentials/v1",
  "proof": "some string proof"
}`
		err := checkEmbeddedProofBytes([]byte(docWithNotMapProof), nil, defaultOpts)
		r.Error(err)
		r.EqualError(err, "check embedded proof: invalid proof type")
	})

	t.Run("error on not map \"proof\" element", func(t *testing.T) {
		docWithNotMapProof := `{
  "@context": "https://www.w3.org/2018/credentials/v1",
  "proof": "some string proof"
}`
		err := checkEmbeddedProofBytes([]byte(docWithNotMapProof), nil, defaultOpts)
		r.Error(err)
		r.EqualError(err, "check embedded proof: invalid proof type")
	})

	t.Run("error on not map \"proof\" element inside proofs array", func(t *testing.T) {
		docWithNotMapProof := `
{
  "@context": "https://www.w3.org/2018/credentials/v1",
  "proof": [
    {
      "created": "2020-04-17T16:54:24+03:00",
      "proofPurpose": "assertionMethod",
      "proofValue": "Lxx69YOV08JglTEmAmdVZgsJdBnCw7oWvfGNaTEKdg-_8qMVAKy1u0oTvWZuhAjTbowjuf1oRtu_1N--PA4TBg",
      "type": "Ed25519Signature2018",
      "verificationMethod": "did:example:123456#key1"
    },
    "some string proof"
  ]

}
`
		err := checkEmbeddedProofBytes([]byte(docWithNotMapProof), nil, defaultOpts)
		r.Error(err)
		r.EqualError(err, "check embedded proof: invalid proof type")
	})

	t.Run("error on not supported type of embedded proof", func(t *testing.T) {
		docWithNotSupportedProof := `{
  "@context": "https://www.w3.org/2018/credentials/v1",
  "proof": {
	"created": "2020-01-21T12:59:31+02:00",
    "proofPurpose": "assertionMethod",
    "proofValue": "Lxx69YOV08JglTEmAmdVZgsJdBnCw7oWvfGNaTEKdg-_8qMVAKy1u0oTvWZuhAjTbowjuf1oRtu_1N--PA4TBg",
	"type": "SomethingUnsupported"
  }
}`
		_, proofChecker := testsupport.NewKMSSigVerPair(t, kmsapi.ED25519Type, "did:123#any")
		err := checkEmbeddedProofBytes([]byte(docWithNotSupportedProof), nil, &embeddedProofCheckOpts{
			proofChecker:         proofChecker,
			jsonldCredentialOpts: jsonldCredentialOpts{jsonldDocumentLoader: createTestDocumentLoader(t)},
		})
		r.Error(err)
		r.Contains(err.Error(), "unsupported proof type: SomethingUnsupported")
	})

	t.Run("no public key fetcher defined", func(t *testing.T) {
		docWithNotSupportedProof := `{
  "@context": "https://www.w3.org/2018/credentials/v1",
  "proof": {
	"type": "Ed25519Signature2018",
    "created": "2020-01-21T12:59:31+02:00",
    "creator": "John",
    "proofValue": "invalid value"
  }
}`
		err := checkEmbeddedProofBytes([]byte(docWithNotSupportedProof), nil, defaultOpts)
		r.Error(err)
		r.EqualError(err, "proofChecker is not defined")
	})
}
