/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	_ "embed"
	"net/http"
	"testing"
	"time"

	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/did-go/doc/did"
	ldcontext "github.com/trustbloc/did-go/doc/ld/context"
	"github.com/trustbloc/did-go/doc/ld/testutil"
	"github.com/trustbloc/did-go/method/jwk"
	"github.com/trustbloc/did-go/method/key"
	vdrpkg "github.com/trustbloc/did-go/vdr"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
	kmsapi "github.com/trustbloc/kms-go/spi/kms"

	"github.com/trustbloc/vc-go/dataintegrity"
	"github.com/trustbloc/vc-go/dataintegrity/suite/ecdsa2019"
	"github.com/trustbloc/vc-go/dataintegrity/suite/eddsa2022"
	"github.com/trustbloc/vc-go/internal/testutil/kmscryptoutil"
	"github.com/trustbloc/vc-go/proof/defaults"
	"github.com/trustbloc/vc-go/vermethod"
)

func Test_DataIntegrity_SignVerify(t *testing.T) {
	vcJSON := `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1",
	"https://w3id.org/security/data-integrity/v2"
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

	kmsCrypto := kmscryptoutil.LocalKMSCrypto(t)

	docLoader := createTestDocumentLoader(t)

	key, err := kmsCrypto.Create(kmsapi.ECDSAP256IEEEP1363)
	require.NoError(t, err)

	const signingDID = "did:foo:bar"

	const vmID = "#key-1"

	vm, err := did.NewVerificationMethodFromJWK(signingDID+vmID, "JsonWebKey2020", signingDID, key)
	require.NoError(t, err)

	resolver := resolveFunc(func(id string) (*did.DocResolution, error) {
		return makeMockDIDResolution(signingDID, vm, did.AssertionMethod), nil
	})

	signerSuite := ecdsa2019.NewSignerInitializer(&ecdsa2019.SignerInitializerOptions{
		SignerGetter:     ecdsa2019.WithKMSCryptoWrapper(kmsCrypto),
		LDDocumentLoader: docLoader,
	})

	signer, err := dataintegrity.NewSigner(&dataintegrity.Options{
		DIDResolver: resolver,
	}, signerSuite)
	require.NoError(t, err)

	signContext := &DataIntegrityProofContext{
		SigningKeyID: signingDID + vmID,
		ProofPurpose: "",
		CryptoSuite:  ecdsa2019.SuiteType,
		Created:      nil,
		Domain:       "mock-domain",
		Challenge:    "mock-challenge",
	}

	verifySuite := ecdsa2019.NewVerifierInitializer(&ecdsa2019.VerifierInitializerOptions{
		LDDocumentLoader: docLoader,
	})

	verifier, err := dataintegrity.NewVerifier(&dataintegrity.Options{
		DIDResolver: resolver,
	}, verifySuite)
	require.NoError(t, err)

	t.Run("credential", func(t *testing.T) {
		vc, e := parseTestCredential(t, []byte(vcJSON), WithDisabledProofCheck(), WithStrictValidation())
		require.NoError(t, e)

		e = vc.AddDataIntegrityProof(signContext, signer)
		require.NoError(t, e)

		vcBytes, e := vc.MarshalJSON()
		require.NoError(t, e)

		_, e = parseTestCredential(t, vcBytes, WithDataIntegrityVerifier(verifier),
			WithStrictValidation(), WithDisabledProofCheck())
		require.NoError(t, e)

		t.Run("fail if not provided verifier", func(t *testing.T) {
			_, e = parseTestCredential(t, vcBytes, WithDataIntegrityVerifier(nil))
			require.Error(t, e)
			require.Contains(t, e.Error(), "needs data integrity verifier")
		})
	})

	t.Run("presentation", func(t *testing.T) {
		vp, e := newTestPresentation(t, []byte(validPresentation), WithPresDisabledProofCheck())
		require.NoError(t, e)

		e = vp.AddDataIntegrityProof(signContext, signer)
		require.NoError(t, e)

		vpBytes, e := vp.MarshalJSON()
		require.NoError(t, e)

		_, e = newTestPresentation(t, vpBytes,
			WithPresDataIntegrityVerifier(verifier),
			WithPresExpectedDataIntegrityFields(assertionMethod, "mock-domain", "mock-challenge"),
		)
		require.NoError(t, e)

		t.Run("fail if not provided verifier", func(t *testing.T) {
			_, e = newTestPresentation(t, vpBytes)
			require.Error(t, e)
			require.Contains(t, e.Error(), "needs data integrity verifier")
		})
	})

	t.Run("failure", func(t *testing.T) {
		t.Run("marshal json", func(t *testing.T) {
			vc, err := CreateCredential(CredentialContents{
				CustomContext: []interface{}{make(chan int)},
			}, nil)
			require.NoError(t, err)

			err = vc.AddDataIntegrityProof(&DataIntegrityProofContext{}, &dataintegrity.Signer{})
			require.Error(t, err)
			require.Contains(t, err.Error(), "add data integrity proof to VC")

			vp := &Presentation{
				Proofs: []Proof{
					{
						"foo": make(chan int),
					},
				},
			}

			err = vp.AddDataIntegrityProof(&DataIntegrityProofContext{}, &dataintegrity.Signer{})
			require.Error(t, err)
			require.Contains(t, err.Error(), "add data integrity proof to VP")
		})

		t.Run("add data integrity proof", func(t *testing.T) {
			vc := &Credential{}

			err := vc.AddDataIntegrityProof(&DataIntegrityProofContext{}, &dataintegrity.Signer{})
			require.Error(t, err)
			require.Contains(t, err.Error(), "unsupported cryptographic suite")

			vp := &Presentation{}

			err = vp.AddDataIntegrityProof(&DataIntegrityProofContext{
				Created: &time.Time{},
			}, &dataintegrity.Signer{})
			require.Error(t, err)
			require.Contains(t, err.Error(), "unsupported cryptographic suite")
		})
	})
}

//go:embed testdata/example_presentation_1_ed25519.jsonld
var examplePresentation1Ed25519 []byte

//go:embed testdata/example_presentation_2_ed25519.json
var examplePresentation2Ed25519 []byte

//go:embed testdata/example_presentation_3_ed25519.json
var examplePresentation3Ed25519 []byte

//go:embed testdata/example_presentation_4_p256.json
var examplePresentation4P256 []byte

//go:embed testdata/example_presentation_4_p384.json
var examplePresentation4P384 []byte

//go:embed testdata/context/credential_v2.jsonld
var credentialV2Context []byte

//go:embed testdata/context/citizenship_v2.jsonld
var citizenshipV2Context []byte

//go:embed testdata/context/citizenship_v4rc1.jsonld
var citizenshipV4rc1Context []byte

//go:embed testdata/context/imsglobal_context.jsonld
var imsglobalContext []byte

//go:embed testdata/context/lds_jws2020_v1.jsonld
var ldsJWS2020V1Context []byte

func TestCanParseRDFC2022Presentation(t *testing.T) {
	vdr := vdrpkg.New(vdrpkg.WithVDR(jwk.New()), vdrpkg.WithVDR(key.New()))

	loader := ld.NewDefaultDocumentLoader(http.DefaultClient)
	verifier, err := dataintegrity.NewVerifier(&dataintegrity.Options{
		DIDResolver: vdr,
	}, eddsa2022.NewVerifierInitializer(&eddsa2022.VerifierInitializerOptions{
		LDDocumentLoader: loader,
	}))

	resp, err := ParsePresentation(examplePresentation1Ed25519,
		WithPresDataIntegrityVerifier(verifier),
		WithPresJSONLDDocumentLoader(loader),
		WithPresExpectedDataIntegrityFields("authentication",
			"github.com/w3c/vc-data-model-2.0-test-suite", "ubXbWYV5hUDu1VCy2b75qKg"),
	)
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestCanParsePlaygroundPresentation(t *testing.T) {
	vdr := vdrpkg.New(vdrpkg.WithVDR(jwk.New()), vdrpkg.WithVDR(key.New()))

	loader, e := testutil.DocumentLoader(
		ldcontext.Document{
			URL:     "https://w3id.org/citizenship/v2",
			Content: citizenshipV2Context,
		},
		ldcontext.Document{
			URL:     "https://purl.imsglobal.org/spec/ob/v3p0/context.json",
			Content: imsglobalContext,
		},
		ldcontext.Document{
			URL:     "https://w3id.org/citizenship/v4rc1",
			Content: citizenshipV4rc1Context,
		},
		ldcontext.Document{
			URL:     "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json",
			Content: ldsJWS2020V1Context,
		},
	)
	require.NoError(t, e)

	verifier, e := dataintegrity.NewVerifier(&dataintegrity.Options{
		DIDResolver: vdr,
	}, eddsa2022.NewVerifierInitializer(&eddsa2022.VerifierInitializerOptions{
		LDDocumentLoader: loader,
	}), ecdsa2019.NewVerifierInitializer(&ecdsa2019.VerifierInitializerOptions{
		LDDocumentLoader: loader,
	}))

	require.NoError(t, e)

	proofChecker := defaults.NewDefaultProofChecker(vermethod.NewVDRResolver(vdr))

	tests := []struct {
		name         string
		presentation []byte
		purpose      string
		domain       string
		challenge    string
	}{
		{
			name:         "VP2 Ed25519",
			presentation: examplePresentation2Ed25519,
			purpose:      "authentication",
			domain:       "https://playground.chapi.io",
			challenge:    "3779e883a51a8086039db1d4e773aec26faeb3ee99643706345c572cddded857",
		},
		{
			name:         "VP3 Ed25519",
			presentation: examplePresentation3Ed25519,
			purpose:      "authentication",
			domain:       "https://playground.chapi.io",
			challenge:    "3779e883a51a8086039db1d4e773aec26faeb3ee99643706345c572cddded857",
		},
		{
			name:         "VP4 P256",
			presentation: examplePresentation4P256,
			purpose:      "authentication",
			domain:       "https://qa.veresexchanger.dev/exchangers/z19vRLNoFaBKDeDaMzRjUj8hi/exchanges/z19kwQeqoW6ufvxvcTEtfQjNw/openid/client/authorization/response",
			challenge:    "z19kwQeqoW6ufvxvcTEtfQjNw",
		},
		{
			name:         "VP4 P384",
			presentation: examplePresentation4P384,
			purpose:      "authentication",
			domain:       "https://qa.veresexchanger.dev/exchangers/z19vRLNoFaBKDeDaMzRjUj8hi/exchanges/z19zFqnQzxPqRHRBBSE5J3ZCG/openid/client/authorization/response",
			challenge:    "z19zFqnQzxPqRHRBBSE5J3ZCG",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := ParsePresentation(tt.presentation,
				WithPresDataIntegrityVerifier(verifier),
				WithPresJSONLDDocumentLoader(loader),
				WithPresProofChecker(proofChecker),
				WithPresExpectedDataIntegrityFields(tt.purpose, tt.domain, tt.challenge),
			)

			require.NoError(t, err)
			assert.NotNil(t, resp)
		})
	}
}

type resolveFunc func(id string) (*did.DocResolution, error)

func (f resolveFunc) Resolve(id string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
	return f(id)
}

func makeMockDIDResolution(id string, vm *did.VerificationMethod, vr did.VerificationRelationship) *did.DocResolution {
	ver := []did.Verification{{
		VerificationMethod: *vm,
		Relationship:       vr,
	}}

	doc := &did.Doc{
		ID: id,
	}

	switch vr {
	case did.VerificationRelationshipGeneral:
		doc.VerificationMethod = []did.VerificationMethod{*vm}
	case did.Authentication:
		doc.Authentication = ver
	case did.AssertionMethod:
		doc.AssertionMethod = ver
	}

	return &did.DocResolution{
		DIDDocument: doc,
	}
}
