/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	_ "embed"
	"net/http"
	"testing"

	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/did-go/method/jwk"
	"github.com/trustbloc/did-go/method/key"
	vdrpkg "github.com/trustbloc/did-go/vdr"

	"github.com/trustbloc/vc-go/dataintegrity"
	"github.com/trustbloc/vc-go/dataintegrity/suite/ecdsa2019"
	"github.com/trustbloc/vc-go/dataintegrity/suite/eddsa2022"
	"github.com/trustbloc/vc-go/proof/defaults"
	"github.com/trustbloc/vc-go/vermethod"
)

//go:embed testdata/example_presentation_4.json
var examplePresentation4 []byte

//go:embed testdata/example_presentation_5.json
var examplePresentation5 []byte

func TestMustIncludeHolderProperty(t *testing.T) {
	//A verifiable presentation that includes a self-asserted verifiable credential, which is secured only
	//using the same mechanism as the verifiable presentation, MUST include a holder property.
	vdr := vdrpkg.New(vdrpkg.WithVDR(jwk.New()), vdrpkg.WithVDR(key.New()))

	loader := ld.NewDefaultDocumentLoader(http.DefaultClient)
	verifier, err := dataintegrity.NewVerifier(&dataintegrity.Options{
		DIDResolver: vdr,
	}, eddsa2022.NewVerifierInitializer(&eddsa2022.VerifierInitializerOptions{
		LDDocumentLoader: loader,
	}), ecdsa2019.NewVerifierInitializer(&ecdsa2019.VerifierInitializerOptions{
		LDDocumentLoader: loader,
	}))

	proofChecker := defaults.NewDefaultProofChecker(vermethod.NewVDRResolver(vdr))

	resp, err := ParsePresentation(examplePresentation4,
		WithPresDataIntegrityVerifier(verifier),
		WithPresJSONLDDocumentLoader(loader),
		WithPresProofChecker(proofChecker),
		WithPresExpectedDataIntegrityFields("authentication",
			"github.com/w3c/vc-data-model-2.0-test-suite",
			"ugBYp7yLdKSpAW1yakgot3g",
		),
	)
	require.ErrorContains(t, err, "MUST include a holder property")
	assert.Nil(t, resp)
}

func TestHolderMustBeEqualToIssuer(t *testing.T) {
	//A verifiable presentation that includes a self-asserted verifiable credential, which is secured only
	//using the same mechanism as the verifiable presentation, MUST include a holder property.
	vdr := vdrpkg.New(vdrpkg.WithVDR(jwk.New()), vdrpkg.WithVDR(key.New()))

	loader := ld.NewDefaultDocumentLoader(http.DefaultClient)
	verifier, err := dataintegrity.NewVerifier(&dataintegrity.Options{
		DIDResolver: vdr,
	}, eddsa2022.NewVerifierInitializer(&eddsa2022.VerifierInitializerOptions{
		LDDocumentLoader: loader,
	}), ecdsa2019.NewVerifierInitializer(&ecdsa2019.VerifierInitializerOptions{
		LDDocumentLoader: loader,
	}))

	proofChecker := defaults.NewDefaultProofChecker(vermethod.NewVDRResolver(vdr))

	resp, err := ParsePresentation(examplePresentation5,
		WithPresDataIntegrityVerifier(verifier),
		WithPresJSONLDDocumentLoader(loader),
		WithPresProofChecker(proofChecker),
		WithPresExpectedDataIntegrityFields("authentication",
			"github.com/w3c/vc-data-model-2.0-test-suite",
			"ugBYp7yLdKSpAW1yakgot3g",
		),
	)
	require.ErrorContains(t, err, "MUST be identical to the holder property of the verifiable presentation")
	assert.Nil(t, resp)
}
