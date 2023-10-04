/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package lddocument

import (
	"encoding/base64"
	"errors"
	"time"

	"github.com/trustbloc/did-go/doc/ld/processor"
	"github.com/trustbloc/did-go/doc/ld/proof"
	afgotime "github.com/trustbloc/did-go/doc/util/time"
	"github.com/trustbloc/kms-go/spi/kms"
)

const defaultProofPurpose = "assertionMethod"

// ProofCreator encapsulates signature methods required for signing documents.
type ProofCreator interface {
	// SignLinkedDocument will sign document and return signature.
	SignLinkedDocument(proof *proof.Proof, keyType kms.KeyType, doc []byte) ([]byte, error)

	// GetLDPCanonicalDocument will return normalized/canonical version of the document
	GetLDPCanonicalDocument(proof *proof.Proof, doc map[string]interface{}, opts ...processor.Opts) ([]byte, error)

	// GetLDPDigest returns document digest
	GetLDPDigest(proof *proof.Proof, doc []byte) ([]byte, error)

	// LDPJWTAlg will return algorithm for jws signature
	LDPJWTAlg(proof *proof.Proof, keyType kms.KeyType) (string, error)
}

// DocumentSigner implements signing of JSONLD documents.
type DocumentSigner struct {
	signer ProofCreator
}

// SigningContext holds signing options and private key.
type SigningContext struct {
	SignatureType           string                        // required
	Creator                 string                        // required
	KeyType                 kms.KeyType                   // required
	SignatureRepresentation proof.SignatureRepresentation // optional
	Created                 *time.Time                    // optional
	Domain                  string                        // optional
	Nonce                   []byte                        // optional
	VerificationMethod      string                        // optional
	Challenge               string                        // optional
	Purpose                 string                        // optional
	CapabilityChain         []interface{}                 // optional
}

// NewDocumentSigner returns new instance of document signer.
func NewDocumentSigner(signer ProofCreator) *DocumentSigner {
	return &DocumentSigner{signer: signer}
}

// Sign  will sign JSON LD document.
func (ds *DocumentSigner) Sign(
	context *SigningContext,
	jsonLdObject map[string]interface{},
	opts ...processor.Opts,
) error {
	return ds.signObject(context, jsonLdObject, opts)
}

// signObject is a helper method that operates on JSON LD objects.
func (ds *DocumentSigner) signObject(context *SigningContext, jsonLdObject map[string]interface{},
	opts []processor.Opts) error {
	if err := isValidContext(context); err != nil {
		return err
	}

	created := context.Created
	if created == nil {
		now := time.Now()
		created = &now
	}

	p := &proof.Proof{
		Type:                    context.SignatureType,
		SignatureRepresentation: context.SignatureRepresentation,
		Creator:                 context.Creator,
		Created:                 wrapTime(*created),
		Domain:                  context.Domain,
		Nonce:                   context.Nonce,
		VerificationMethod:      context.VerificationMethod,
		Challenge:               context.Challenge,
		ProofPurpose:            context.Purpose,
		CapabilityChain:         context.CapabilityChain,
	}

	if p.ProofPurpose == "" {
		p.ProofPurpose = defaultProofPurpose
	}

	if context.SignatureRepresentation == proof.SignatureJWS {
		jwtAlg, err := ds.signer.LDPJWTAlg(p, context.KeyType)
		if err != nil {
			return err
		}

		p.JWS = proof.CreateDetachedJWTHeader(jwtAlg) + ".."
	}

	message, err := proof.CreateVerifyData(&signatureSuiteWrapper{
		wrapped: ds.signer,
		proof:   p,
	}, jsonLdObject, p, append(opts, processor.WithValidateRDF())...)
	if err != nil {
		return err
	}

	s, err := ds.signer.SignLinkedDocument(p, context.KeyType, message)
	if err != nil {
		return err
	}

	ds.applySignatureValue(context, p, s)

	return proof.AddProof(jsonLdObject, p)
}

func (ds *DocumentSigner) applySignatureValue(context *SigningContext, p *proof.Proof, s []byte) {
	switch context.SignatureRepresentation {
	case proof.SignatureProofValue:
		p.ProofValue = s
	case proof.SignatureJWS:
		p.JWS += base64.RawURLEncoding.EncodeToString(s)
	}
}

// isValidContext checks required parameters (for signing).
func isValidContext(context *SigningContext) error {
	if context.SignatureType == "" {
		return errors.New("signature type is missing")
	}

	return nil
}

func wrapTime(t time.Time) *afgotime.TimeWrapper {
	return &afgotime.TimeWrapper{Time: t}
}
