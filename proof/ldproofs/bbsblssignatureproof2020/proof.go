/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbsblssignatureproof2020

// Package bbsblssignatureproof2020 implements the BBS+ Signature Proof Suite 2020 signature suite
// (https://w3c-ccg.github.io/ldp-bbs2020) in conjunction with the signing and verification algorithms of the
// Linked Data Proofs.
// It uses the RDF Dataset Normalization Algorithm to transform the input document into its canonical form.
// It uses SHA-256 [RFC6234] as the statement digest algorithm.
// It uses BBS+ signature algorithm (https://mattrglobal.github.io/bbs-signatures-spec/).
// It uses BLS12-381 pairing-friendly curve (https://tools.ietf.org/html/draft-irtf-cfrg-pairing-friendly-curves-03).

import (
	"strings"

	"github.com/trustbloc/did-go/doc/ld/processor"
	"github.com/trustbloc/kms-go/spi/kms"

	"github.com/trustbloc/vc-go/proof"
)

// Proof implements BbsBlsSignatureProof2020 signature suite.
type Proof struct {
	jsonldProcessor *processor.Processor
	supportedVMs    []proof.SupportedVerificationMethod
}

const (
	// ProofType for bbsblssignatureproof2020.
	ProofType = "BbsBlsSignatureProof2020"
	// VerificationMethodType for bbsblssignatureproof2020.
	VerificationMethodType = "Bls12381G2Key2020"
	rdfDataSetAlg          = "URDNA2015"
)

// New an instance of Linked Data Signatures for the suite.
func New() *Proof {
	p := &Proof{jsonldProcessor: processor.NewProcessor(rdfDataSetAlg)}
	p.supportedVMs = []proof.SupportedVerificationMethod{
		{
			VerificationMethodType: VerificationMethodType,
			KMSKeyType:             kms.BLS12381G2Type,
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
// BbsBlsSignatureProof2020 signature suite uses RDF Dataset Normalization as canonicalization algorithm.
func (s *Proof) GetCanonicalDocument(doc map[string]interface{}, opts ...processor.Opts) ([]byte, error) {
	if v, ok := doc["type"]; ok {
		docType, ok := v.(string)

		if ok && strings.HasSuffix(docType, ProofType) {
			docType = strings.Replace(docType, ProofType, "BbsBlsSignature2020", 1)
			doc["type"] = docType
		}
	}

	return s.jsonldProcessor.GetCanonicalDocument(doc, opts...)
}

// GetDigest returns the doc itself as we would process N-Quads statements as messages to be signed/verified.
func (s *Proof) GetDigest(doc []byte) []byte {
	return doc
}
