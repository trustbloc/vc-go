/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"fmt"
	"time"

	ldprocessor "github.com/trustbloc/did-go/doc/ld/processor"
	"github.com/trustbloc/did-go/doc/ld/proof"
	"github.com/trustbloc/kms-go/spi/kms"

	"github.com/trustbloc/vc-go/verifiable/lddocument"
)

// SignatureRepresentation is a signature value holder type (e.g. "proofValue" or "jws").
type SignatureRepresentation int

const (
	// SignatureProofValue uses "proofValue" field in a Proof to put/read a digital signature.
	SignatureProofValue SignatureRepresentation = iota

	// SignatureJWS uses "jws" field in a Proof as an element for representation of detached JSON Web Signatures.
	SignatureJWS
)

// LinkedDataProofContext holds options needed to build a Linked Data Proof.
type LinkedDataProofContext struct {
	// TODO: rename to ProofType
	SignatureType           string                  // required
	ProofCreator            lddocument.ProofCreator // required
	KeyType                 kms.KeyType             // required
	SignatureRepresentation SignatureRepresentation // required
	Created                 *time.Time              // optional
	VerificationMethod      string                  // optional
	Challenge               string                  // optional
	Domain                  string                  // optional
	Purpose                 string                  // optional
	// CapabilityChain must be an array. Each element is either a string or an object.
	CapabilityChain []interface{}
}

func checkLinkedDataProof(jsonldBytes map[string]interface{},
	proofChecker lddocument.ProofChecker, expectedProofIssuer string, jsonldOpts *jsonldCredentialOpts) error {
	documentVerifier := lddocument.NewDocumentVerifier(proofChecker)

	processorOpts := mapJSONLDProcessorOpts(jsonldOpts)

	err := documentVerifier.VerifyObject(jsonldBytes, expectedProofIssuer, processorOpts...)
	if err != nil {
		return fmt.Errorf("check linked data proof: %w", err)
	}

	return nil
}

func mapJSONLDProcessorOpts(jsonldOpts *jsonldCredentialOpts) []ldprocessor.Opts {
	var processorOpts []ldprocessor.Opts

	if jsonldOpts.jsonldDocumentLoader != nil {
		processorOpts = append(processorOpts, ldprocessor.WithDocumentLoader(jsonldOpts.jsonldDocumentLoader))
	}

	if jsonldOpts.jsonldOnlyValidRDF {
		processorOpts = append(processorOpts, ldprocessor.WithRemoveAllInvalidRDF())
	} else {
		processorOpts = append(processorOpts, ldprocessor.WithValidateRDF())
	}

	return processorOpts
}

type rawProof struct {
	Proof JSONObject `json:"proof,omitempty"`
}

// addLinkedDataProof adds a new proof to the JSON-LD document (VC or VP). It returns a slice
// of the proofs which were already present appended with a newly created proof.
func addLinkedDataProof(context *LinkedDataProofContext, jsonld JSONObject,
	opts ...ldprocessor.Opts) ([]Proof, error) {
	documentSigner := lddocument.NewDocumentSigner(context.ProofCreator)

	err := documentSigner.Sign(mapContext(context), jsonld, opts...)
	if err != nil {
		return nil, fmt.Errorf("add linked data proof: %w", err)
	}

	proofs, err := parseLDProof(jsonld[jsonFldLDProof])
	if err != nil {
		return nil, err
	}

	return proofs, nil
}

func mapContext(context *LinkedDataProofContext) *lddocument.SigningContext {
	return &lddocument.SigningContext{
		SignatureType:           context.SignatureType,
		SignatureRepresentation: proof.SignatureRepresentation(context.SignatureRepresentation),
		KeyType:                 context.KeyType,
		Created:                 context.Created,
		VerificationMethod:      context.VerificationMethod,
		Challenge:               context.Challenge,
		Domain:                  context.Domain,
		Purpose:                 context.Purpose,
		CapabilityChain:         context.CapabilityChain,
	}
}
