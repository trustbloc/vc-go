/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package commontest

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	jsonld "github.com/trustbloc/did-go/doc/ld/processor"
	ldtestutil "github.com/trustbloc/did-go/doc/ld/testutil"
	"github.com/trustbloc/kms-go/spi/kms"
	"github.com/veraison/go-cose"

	"github.com/trustbloc/vc-go/crypto-ext/testutil"
	"github.com/trustbloc/vc-go/cwt"
	"github.com/trustbloc/vc-go/proof/creator"
	"github.com/trustbloc/vc-go/proof/jwtproofs/eddsa"
	"github.com/trustbloc/vc-go/proof/testsupport"
	"github.com/trustbloc/vc-go/verifiable"
)

const testCredential = `
{
	"@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://www.w3.org/2018/credentials/examples/v1",
	  "https://w3id.org/security/jws/v1",
      "https://trustbloc.github.io/context/vc/examples-v1.jsonld",
      "https://w3id.org/security/suites/ed25519-2020/v1",
      "https://w3id.org/security/bbs/v1"
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
    "id": "did:example:12345",
    "name": "Example University"
  },
  "issuanceDate": "2010-01-01T19:23:24Z",
  "expirationDate": "2020-01-01T19:23:24Z"
}
`

type ldTestCase struct {
	SignatureType string
	proofCreator  *creator.ProofCreator
	signingKey    testsupport.SigningKey
	fail          bool
	skipJWS       bool
}

type jwtTestCase struct {
	Alg          verifiable.JWSAlgorithm
	proofCreator *creator.ProofCreator
	signingKey   testsupport.SigningKey
	fail         bool
	verFail      bool
}

type cwtTestCase struct {
	Alg          verifiable.JWSAlgorithm
	CborAlg      cose.Algorithm
	proofCreator *creator.ProofCreator
	signingKey   testsupport.SigningKey
	fail         bool
	verFail      bool
}

// TestAllLDSignersVerifiers tests all supported ld proof types.
func TestAllLDSignersVerifiers(t *testing.T) {
	docLoader, dlErr := ldtestutil.DocumentLoader()
	require.NoError(t, dlErr)

	allKeyTypes := []testsupport.SigningKey{
		{Type: kms.ED25519Type, PublicKeyID: "did:example:12345#key-1"},
		{Type: kms.ECDSASecp256k1TypeIEEEP1363, PublicKeyID: "did:example:12345#key-3"},
		{Type: kms.BLS12381G2Type, PublicKeyID: "did:example:12345#key-8"},
	}

	proofCreators, proofChecker := testsupport.NewKMSSignersAndVerifier(t, allKeyTypes)

	testCases := []ldTestCase{
		{SignatureType: "Ed25519Signature2018", proofCreator: proofCreators[0], signingKey: allKeyTypes[0]},
		{SignatureType: "Ed25519Signature2020", proofCreator: proofCreators[0], signingKey: allKeyTypes[0],
			skipJWS: true},
		{SignatureType: "JsonWebSignature2020", proofCreator: proofCreators[0], signingKey: allKeyTypes[0]},
		{SignatureType: "EcdsaSecp256k1Signature2019", proofCreator: proofCreators[1], signingKey: allKeyTypes[1]},
		{SignatureType: "BbsBlsSignature2020", proofCreator: proofCreators[2], signingKey: allKeyTypes[2],
			skipJWS: true},

		{SignatureType: "Inv", proofCreator: proofCreators[0], signingKey: allKeyTypes[0], fail: true},
		{SignatureType: "Ed25519Signature2018", proofCreator: proofCreators[0], signingKey: allKeyTypes[1], fail: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.SignatureType, func(t *testing.T) {
			vc, err := verifiable.ParseCredential([]byte(testCredential),
				verifiable.WithJSONLDDocumentLoader(docLoader),
				verifiable.WithDisabledProofCheck())
			require.NoError(t, err)

			err = vc.AddLinkedDataProof(&verifiable.LinkedDataProofContext{
				SignatureType:           testCase.SignatureType,
				KeyType:                 testCase.signingKey.Type,
				SignatureRepresentation: verifiable.SignatureProofValue,
				ProofCreator:            testCase.proofCreator,
				VerificationMethod:      testCase.signingKey.PublicKeyID,
			}, jsonld.WithDocumentLoader(docLoader))
			checkError(t, err, testCase.fail)

			if !testCase.skipJWS {
				err = vc.AddLinkedDataProof(&verifiable.LinkedDataProofContext{
					SignatureType:           testCase.SignatureType,
					KeyType:                 testCase.signingKey.Type,
					SignatureRepresentation: verifiable.SignatureJWS,
					ProofCreator:            testCase.proofCreator,
					VerificationMethod:      testCase.signingKey.PublicKeyID,
				}, jsonld.WithDocumentLoader(docLoader))
				checkError(t, err, testCase.fail)
			}

			if testCase.fail {
				return
			}

			err = vc.CheckProof(verifiable.WithJSONLDDocumentLoader(docLoader), verifiable.WithProofChecker(proofChecker))
			require.NoError(t, err)
		})
	}
}

func checkError(t *testing.T, err error, shouldFail bool) {
	if shouldFail {
		require.Error(t, err)
	} else {
		require.NoError(t, err)
	}
}

// TestAllJWTSignersVerifiers tests all supported jwt proof types.
func TestAllJWTSignersVerifiers(t *testing.T) {
	docLoader, ldErr := ldtestutil.DocumentLoader()
	require.NoError(t, ldErr)

	allKeyTypes := []testsupport.SigningKey{
		{Type: kms.ED25519Type, PublicKeyID: "did:example:12345#key-1"},
		{Type: kms.ECDSAP256TypeIEEEP1363, PublicKeyID: "did:example:12345#key-2"},
		{Type: kms.ECDSASecp256k1TypeIEEEP1363, PublicKeyID: "did:example:12345#key-3"},
		{Type: kms.ECDSAP384TypeIEEEP1363, PublicKeyID: "did:example:12345#key-4"},
		{Type: kms.ECDSAP521TypeIEEEP1363, PublicKeyID: "did:example:12345#key-5"},
		{Type: kms.RSARS256Type, PublicKeyID: "did:example:12345#key-6"},
	}

	proofCreators, proofChecker := testsupport.NewKMSSignersAndVerifier(t, allKeyTypes)

	testCases := []jwtTestCase{
		{Alg: verifiable.EdDSA, proofCreator: proofCreators[0], signingKey: allKeyTypes[0]},
		{Alg: verifiable.ECDSASecp256r1, proofCreator: proofCreators[1], signingKey: allKeyTypes[1]},
		{Alg: verifiable.ECDSASecp256k1, proofCreator: proofCreators[2], signingKey: allKeyTypes[2]},
		{Alg: verifiable.ECDSASecp384r1, proofCreator: proofCreators[3], signingKey: allKeyTypes[3]},
		{Alg: verifiable.ECDSASecp521r1, proofCreator: proofCreators[4], signingKey: allKeyTypes[4]},
		{Alg: verifiable.RS256, proofCreator: proofCreators[5], signingKey: allKeyTypes[5]},

		{Alg: verifiable.ECDSASecp256r1, proofCreator: proofCreators[0], signingKey: allKeyTypes[0], verFail: true},
		{Alg: verifiable.JWSAlgorithm(10), proofCreator: proofCreators[0], signingKey: allKeyTypes[0], fail: true},
	}

	for _, testCase := range testCases {
		vc, err := verifiable.ParseCredential([]byte(testCredential),
			verifiable.WithJSONLDDocumentLoader(docLoader),
			verifiable.WithDisabledProofCheck())
		require.NoError(t, err)

		vc, err =
			vc.CreateSignedJWTVC(true, testCase.Alg, testCase.proofCreator, testCase.signingKey.PublicKeyID)
		checkError(t, err, testCase.fail)

		if testCase.fail {
			continue
		}

		err = vc.CheckProof(verifiable.WithJSONLDDocumentLoader(docLoader), verifiable.WithProofChecker(proofChecker))
		checkError(t, err, testCase.verFail)
	}
}

// TestAllCWTSignersVerifiers tests all supported jwt proof types.
func TestAllCWTSignersVerifiers(t *testing.T) {
	_, ldErr := ldtestutil.DocumentLoader()
	require.NoError(t, ldErr)

	allKeyTypes := []testsupport.SigningKey{
		{Type: kms.ED25519Type, PublicKeyID: "did:example:12345#key-1"},
		{Type: kms.ECDSAP256TypeIEEEP1363, PublicKeyID: "did:example:12345#key-2"},
		{Type: kms.ECDSASecp256k1TypeIEEEP1363, PublicKeyID: "did:example:12345#key-3"},
		{Type: kms.ECDSAP384TypeIEEEP1363, PublicKeyID: "did:example:12345#key-4"},
		{Type: kms.ECDSAP521TypeIEEEP1363, PublicKeyID: "did:example:12345#key-5"},
		{Type: kms.RSARS256Type, PublicKeyID: "did:example:12345#key-6"},
	}

	proofCreators, proofChecker := testsupport.NewKMSSignersAndVerifier(t, allKeyTypes)

	testCases := []cwtTestCase{
		{Alg: verifiable.EdDSA, proofCreator: proofCreators[0], signingKey: allKeyTypes[0], CborAlg: cose.AlgorithmEd25519},
		{Alg: verifiable.ECDSASecp256r1, proofCreator: proofCreators[1], signingKey: allKeyTypes[1], CborAlg: cose.AlgorithmES256},
		{Alg: verifiable.ECDSASecp384r1, proofCreator: proofCreators[3], signingKey: allKeyTypes[3], CborAlg: cose.AlgorithmES384},
	}

	for _, testCase := range testCases {
		t.Run(fmt.Sprintf("key id %v and algo %s",
			testCase.signingKey.PublicKeyID,
			testCase.CborAlg.String(),
		), func(t *testing.T) {
			data := "1234567890"
			encoded, err := cbor.Marshal(data)
			assert.NoError(t, err)
			msg := &cose.Sign1Message{
				Headers: cose.Headers{
					Protected: cose.ProtectedHeader{
						cose.HeaderLabelAlgorithm: testCase.CborAlg,
					},
					Unprotected: map[interface{}]interface{}{
						int64(4): []byte(testCase.signingKey.PublicKeyID),
					},
				},
				Payload: encoded,
			}

			signed, err := testCase.proofCreator.SignCWT(cwt.SignParameters{
				KeyID:  testCase.signingKey.PublicKeyID,
				CWTAlg: testCase.CborAlg,
			}, msg)
			assert.NoError(t, err)

			msg.Signature = signed

			assert.NotNil(t, signed)
			assert.NoError(t, cwt.CheckProof(msg, proofChecker, nil))
		})
	}
}

// TestEmbeddedProofChecker tests embedded proof case.
func TestEmbeddedProofChecker(t *testing.T) {
	docLoader, ldErr := ldtestutil.DocumentLoader()
	require.NoError(t, ldErr)

	pubKey, privKey, e := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, e)

	proofChecker := testsupport.NewEd25519Verifier(pubKey)

	proofCreator :=
		creator.New(
			creator.WithJWTAlg(eddsa.New(), testutil.NewEd25519Signer(privKey)))

	vc, err := verifiable.ParseCredential([]byte(testCredential),
		verifiable.WithJSONLDDocumentLoader(docLoader),
		verifiable.WithDisabledProofCheck())
	require.NoError(t, err)

	vc, err =
		vc.CreateSignedJWTVC(true, verifiable.EdDSA, proofCreator, "any")
	require.NoError(t, err)

	_, err =
		vc.CreateSignedJWTVC(true, verifiable.ECDSASecp256r1, proofCreator, "any")
	require.Error(t, err)

	err = vc.CheckProof(verifiable.WithJSONLDDocumentLoader(docLoader), verifiable.WithJWTProofChecker(proofChecker))
	require.NoError(t, err)
}
