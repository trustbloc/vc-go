/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package ed25519signature2020 implements the Ed25519Signature2020 signature suite
// for the Linked Data Signatures [LD-SIGNATURES] specification.
// It uses the RDF Dataset Normalization Algorithm [RDF-DATASET-NORMALIZATION]
// to transform the input document into its canonical form.
// It uses SHA-256 [RFC6234] as the message digest algorithm and
// Ed25519 [ED25519] as the signature algorithm.
package ed25519signature2020

import (
	"crypto/sha256"

	"github.com/trustbloc/did-go/doc/ld/processor"
	"github.com/trustbloc/kms-go/spi/kms"

	"github.com/trustbloc/vc-go/proof"
)

// Proof describe Ed25519Signature2020 proof.
type Proof struct {
	jsonldProcessor *processor.Processor
	supportedVMs    []proof.SupportedVerificationMethod
}

const (
	// ProofType for Ed25519Signature2020.
	ProofType = "Ed25519Signature2020"
	// VerificationMethodType for Ed25519Signature2020.
	VerificationMethodType = "Ed25519VerificationKey2020"
	// JWKKeyType for Ed25519Signature2020.
	JWKKeyType = "OKP"
	// JWKCurve for Ed25519Signature2020.
	JWKCurve = "Ed25519"
	// CorrespondedJWTAlg for Ed25519Signature2020.
	CorrespondedJWTAlg = "EdDSA"
	rdfDataSetAlg      = "URDNA2015"
)

// New an instance of ed25519 proof descriptor.
func New() *Proof {
	p := &Proof{jsonldProcessor: processor.NewProcessor(rdfDataSetAlg)}
	p.supportedVMs = []proof.SupportedVerificationMethod{
		{
			VerificationMethodType: VerificationMethodType,
			KMSKeyType:             kms.ED25519Type,
			JWKKeyType:             JWKKeyType,
			JWKCurve:               JWKCurve,
		},
		{
			VerificationMethodType: "JsonWebKey2020",
			KMSKeyType:             kms.ED25519Type,
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

// IsJWTAlgSupported return jwt alg that corresponds to VerificationMethod.
func (s *Proof) IsJWTAlgSupported(alg string) bool {
	return alg == CorrespondedJWTAlg
}

// GetCanonicalDocument will return normalized/canonical version of the document
// Ed25519Signature2020 signature SignatureSuite uses RDF Dataset Normalization as canonicalization algorithm.
func (s *Proof) GetCanonicalDocument(doc map[string]interface{}, opts ...processor.Opts) ([]byte, error) {
	return s.jsonldProcessor.GetCanonicalDocument(doc, opts...)
}

// GetDigest returns document digest.
func (s *Proof) GetDigest(doc []byte) []byte {
	digest := sha256.Sum256(doc)
	return digest[:]
}
