/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"fmt"

	jsonld "github.com/piprate/json-gold/ld"
	"github.com/trustbloc/did-go/doc/did"
	"github.com/trustbloc/did-go/doc/ld/processor"

	"github.com/trustbloc/vc-go/dataintegrity"
	"github.com/trustbloc/vc-go/verifiable/lddocument"
)

type verifyDIDOpts struct {
	jsonldCredentialOpts

	ldProofChecker      lddocument.ProofChecker
	verifyDataIntegrity *verifyDataIntegrityOpts
}

// VerifyDIDOpt is the DID verification option.
type VerifyDIDOpt func(opts *verifyDIDOpts)

// WithDIDProofChecker indicates that did.Doc should be decoded using provided proofChecker.
func WithDIDProofChecker(checker lddocument.ProofChecker) VerifyDIDOpt {
	return func(opts *verifyDIDOpts) {
		opts.ldProofChecker = checker
	}
}

// WithDIDDataIntegrityVerifier provides the Data Integrity verifier to use when
// the did.Doc being processed has a Data Integrity proof.
func WithDIDDataIntegrityVerifier(v *dataintegrity.Verifier) VerifyDIDOpt {
	return func(opts *verifyDIDOpts) {
		opts.verifyDataIntegrity.Verifier = v
	}
}

// WithDIDExpectedDataIntegrityFields validates that a Data Integrity proof has the
// given purpose, domain, and challenge. Empty purpose means the default,
// assertionMethod, will be expected. Empty domain and challenge will mean they
// are not checked.
func WithDIDExpectedDataIntegrityFields(purpose, domain, challenge string) VerifyDIDOpt {
	return func(opts *verifyDIDOpts) {
		opts.verifyDataIntegrity.Purpose = purpose
		opts.verifyDataIntegrity.Domain = domain
		opts.verifyDataIntegrity.Challenge = challenge
	}
}

// WithDIDJSONLDDocumentLoader defines a JSON-LD document loader.
func WithDIDJSONLDDocumentLoader(documentLoader jsonld.DocumentLoader) VerifyDIDOpt {
	return func(opts *verifyDIDOpts) {
		opts.jsonldDocumentLoader = documentLoader
	}
}

// WithDIDExternalJSONLDContext defines external JSON-LD contexts to be used in JSON-LD validation and
// Linked Data Signatures verification.
func WithDIDExternalJSONLDContext(context ...string) VerifyDIDOpt {
	return func(opts *verifyDIDOpts) {
		opts.externalContext = context
	}
}

// WithDIDJSONLDOnlyValidRDF indicates the need to remove all invalid RDF dataset from normalize document
// when verifying linked data signatures of did.Doc.
func WithDIDJSONLDOnlyValidRDF() VerifyDIDOpt {
	return func(opts *verifyDIDOpts) {
		opts.jsonldOnlyValidRDF = true
	}
}

// AddDIDLinkedDataProof appends proof to the did.Doc.
func AddDIDLinkedDataProof(
	didDoc *did.Doc,
	context *LinkedDataProofContext,
	jsonldOpts ...processor.Opts,
) (*did.Doc, error) {
	jsonldDoc, err := didToMap(didDoc)
	if err != nil {
		return nil, err
	}

	documentSigner := lddocument.NewDocumentSigner(context.ProofCreator)

	err = documentSigner.Sign(mapContext(context), jsonldDoc, jsonldOpts...)
	if err != nil {
		return nil, fmt.Errorf("add linked data proof: %w", err)
	}

	signedDoc, err := json.Marshal(jsonldDoc)
	if err != nil {
		return nil, fmt.Errorf("encode signed did doc: %w", err)
	}

	didDocSignedLDP, err := did.ParseDocument(signedDoc)
	if err != nil {
		return nil, fmt.Errorf("parse signed did doc: %w", err)
	}

	return didDocSignedLDP, nil
}

// VerifyDIDProof verifies proof to the did.Doc.
func VerifyDIDProof(didDoc *did.Doc, opts ...VerifyDIDOpt) error {
	didOpts := &verifyDIDOpts{
		verifyDataIntegrity: &verifyDataIntegrityOpts{},
	}

	for _, opt := range opts {
		opt(didOpts)
	}

	jsonldDoc, err := didToMap(didDoc)
	if err != nil {
		return err
	}

	embeddedProofCheckOptions := &embeddedProofCheckOpts{
		proofChecker:         didOpts.ldProofChecker,
		jsonldCredentialOpts: didOpts.jsonldCredentialOpts,
		dataIntegrityOpts:    didOpts.verifyDataIntegrity,
	}

	var expectedProofIssuer *string

	return checkEmbeddedProof(jsonldDoc, expectedProofIssuer, embeddedProofCheckOptions)
}

func didToMap(didDoc *did.Doc) (map[string]interface{}, error) {
	didBytes, err := didDoc.JSONBytes()
	if err != nil {
		return nil, fmt.Errorf("decode did doc: %w", err)
	}

	var jsonLdObject map[string]interface{}

	err = json.Unmarshal(didBytes, &jsonLdObject)
	if err != nil {
		return nil, fmt.Errorf("unmarshal did doc: %w", err)
	}

	return jsonLdObject, nil
}
