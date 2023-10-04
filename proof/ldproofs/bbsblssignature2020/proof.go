/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbsblssignature2020

// Package bbsblssignature2020 implements the BBS+ Signature Suite 2020 signature suite
// (https://w3c-ccg.github.io/ldp-bbs2020) in conjunction with the signing and verification algorithms of the
// Linked Data Proofs.
// It uses the RDF Dataset Normalization Algorithm to transform the input document into its canonical form.
// It uses SHA-256 [RFC6234] as the statement digest algorithm.
// It uses BBS+ signature algorithm (https://mattrglobal.github.io/bbs-signatures-spec/).
// It uses BLS12-381 pairing-friendly curve (https://tools.ietf.org/html/draft-irtf-cfrg-pairing-friendly-curves-03).

import (
	"github.com/trustbloc/did-go/doc/ld/processor"
	"github.com/trustbloc/kms-go/spi/kms"

	"github.com/trustbloc/vc-go/proof"
)

// Proof implements BbsBlsSignature2020 signature suite.
type Proof struct {
	jsonldProcessor *processor.Processor
	supportedVMs    []proof.SupportedVerificationMethod
}

const (
	// ProofType is the BbsBlsSignature2020 type string.
	ProofType              = "BbsBlsSignature2020"
	VerificationMethodType = "Bls12381G2Key2020"
	JWKKeyType             = "EC"
	JWKCurve               = "BLS12381_G2"
	rdfDataSetAlg          = "URDNA2015"
)

// New an instance of BbsBlsSignature2020 proof descriptor.
func New() *Proof {
	p := &Proof{jsonldProcessor: processor.NewProcessor(rdfDataSetAlg)}
	p.supportedVMs = []proof.SupportedVerificationMethod{
		{
			VerificationMethodType: VerificationMethodType,
			KMSKeyType:             kms.BLS12381G2Type,
			JWKKeyType:             JWKKeyType,
			JWKCurve:               JWKCurve,
		},
		{
			VerificationMethodType: "JsonWebKey2020",
			KMSKeyType:             kms.BLS12381G2Type,
			JWKKeyType:             JWKKeyType,
			JWKCurve:               JWKCurve,
			RequireJWK:             true,
		},
	}

	return p
}

// ProofType return proof type name.
func (s *Proof) ProofType() string {
	return ProofType
}

// SupportedVerificationMethods returns list of verification methods supported by this proof type.
func (s *Proof) SupportedVerificationMethods() []proof.SupportedVerificationMethod {
	return s.supportedVMs
}

// GetCanonicalDocument will return normalized/canonical version of the document.
// BbsBlsSignature2020 signature suite uses RDF Dataset Normalization as canonicalization algorithm.
func (s *Proof) GetCanonicalDocument(doc map[string]interface{}, opts ...processor.Opts) ([]byte, error) {
	return s.jsonldProcessor.GetCanonicalDocument(doc, opts...)
}

// GetDigest returns the doc itself as we would process N-Quads statements as messages to be signed/verified.
func (s *Proof) GetDigest(doc []byte) []byte {
	return doc
}

func (s *Proof) IsJWTAlgSupported(alg string) bool {
	return false
}
