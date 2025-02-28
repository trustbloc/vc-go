/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	_ "embed"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	ldcontext "github.com/trustbloc/did-go/doc/ld/context"
	lddocloader "github.com/trustbloc/did-go/doc/ld/documentloader"
	jsonldsig "github.com/trustbloc/did-go/doc/ld/processor"
	ldtestutil "github.com/trustbloc/did-go/doc/ld/testutil"
	kmsapi "github.com/trustbloc/kms-go/spi/kms"

	"github.com/trustbloc/vc-go/proof/checker"
	"github.com/trustbloc/vc-go/proof/testsupport"
)

var (
	//go:embed testdata/v1_valid_credential.jsonld
	v1ValidCredential string //nolint:gochecknoglobals

	//go:embed testdata/v1_credential_without_issuancedate.jsonld
	v1CredentialWithoutIssuanceDate string //nolint:gochecknoglobals

	//go:embed testdata/v2_valid_credential_multi_status.jsonld
	v2ValidCredentialMultiStatus string //nolint:gochecknoglobals
)

var (
	//go:embed testdata/v2_valid_credential.jsonld
	v2ValidCredential string //nolint:gochecknoglobals

	//go:embed testdata/v2_credential_without_issuer.jsonld
	v2CredentialWithoutIssuer string //nolint:gochecknoglobals
)

func (vc *Credential) stringJSON(t *testing.T) string {
	bytes, err := json.Marshal(vc)
	require.NoError(t, err)

	return string(bytes)
}

func jsonObjectToString(t *testing.T, vc JSONObject) string {
	bytes, err := json.Marshal(vc)
	require.NoError(t, err)

	return string(bytes)
}

func (vc *Credential) byteJSON(t *testing.T) []byte {
	bytes, err := json.Marshal(vc)
	require.NoError(t, err)

	return bytes
}

func (vp *Presentation) stringJSON(t *testing.T) string {
	bytes, err := json.Marshal(vp)
	require.NoError(t, err)

	return string(bytes)
}

func createVCWithLinkedDataProof(t *testing.T) (*Credential, *checker.ProofChecker) {
	t.Helper()

	vc, err := ParseCredential([]byte(v1ValidCredential),
		WithJSONLDDocumentLoader(createTestDocumentLoader(t)),
		WithDisabledProofCheck())

	require.NoError(t, err)

	created := time.Now()

	proofCreator, proofChecker := testsupport.NewKMSSigVerPair(t, kmsapi.ED25519Type,
		"did:example:76e12ec712ebc6f1c221ebfeb1f#any")

	err = vc.AddLinkedDataProof(&LinkedDataProofContext{
		SignatureType:           "Ed25519Signature2018",
		KeyType:                 kmsapi.ED25519Type,
		ProofCreator:            proofCreator,
		SignatureRepresentation: SignatureJWS,
		Created:                 &created,
		VerificationMethod:      "did:example:76e12ec712ebc6f1c221ebfeb1f#any",
	}, jsonldsig.WithDocumentLoader(createTestDocumentLoader(t)))

	require.NoError(t, err)

	return vc, proofChecker
}

func createVCWithTwoLinkedDataProofs(t *testing.T) (*Credential, *checker.ProofChecker) {
	t.Helper()

	vc, err := ParseCredential([]byte(v1ValidCredential),
		WithJSONLDDocumentLoader(createTestDocumentLoader(t)),
		WithDisabledProofCheck())

	require.NoError(t, err)

	created := time.Now()

	proofCreators, proofChecker := testsupport.NewKMSSignersAndVerifier(t, []*testsupport.SigningKey{
		{
			Type:        kmsapi.ED25519Type,
			PublicKeyID: "did:example:76e12ec712ebc6f1c221ebfeb1f#key1",
		},
		{
			Type:        kmsapi.ED25519Type,
			PublicKeyID: "did:example:76e12ec712ebc6f1c221ebfeb1f#key2",
		},
	})

	err = vc.AddLinkedDataProof(&LinkedDataProofContext{
		SignatureType:           "Ed25519Signature2018",
		KeyType:                 kmsapi.ED25519Type,
		ProofCreator:            proofCreators[0],
		SignatureRepresentation: SignatureJWS,
		Created:                 &created,
		VerificationMethod:      "did:example:76e12ec712ebc6f1c221ebfeb1f#key1",
	}, jsonldsig.WithDocumentLoader(createTestDocumentLoader(t)))

	require.NoError(t, err)

	err = vc.AddLinkedDataProof(&LinkedDataProofContext{
		SignatureType:           "Ed25519Signature2018",
		KeyType:                 kmsapi.ED25519Type,
		ProofCreator:            proofCreators[1],
		SignatureRepresentation: SignatureJWS,
		Created:                 &created,
		VerificationMethod:      "did:example:76e12ec712ebc6f1c221ebfeb1f#key2",
	}, jsonldsig.WithDocumentLoader(createTestDocumentLoader(t)))

	require.NoError(t, err)

	return vc, proofChecker
}

func createTestDocumentLoader(t *testing.T, extraContexts ...ldcontext.Document) *lddocloader.DocumentLoader {
	t.Helper()

	loader, err := ldtestutil.DocumentLoader(extraContexts...)
	require.NoError(t, err)

	return loader
}

func parseTestCredential(t *testing.T, vcData []byte, opts ...CredentialOpt) (*Credential, error) {
	t.Helper()

	return ParseCredential(vcData,
		append([]CredentialOpt{WithJSONLDDocumentLoader(createTestDocumentLoader(t))}, opts...)...)
}

func newTestPresentation(t *testing.T, vpData []byte, opts ...PresentationOpt) (*Presentation, error) {
	t.Helper()

	return ParsePresentation(vpData,
		append([]PresentationOpt{WithPresJSONLDDocumentLoader(createTestDocumentLoader(t))}, opts...)...)
}
