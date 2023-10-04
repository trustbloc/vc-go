/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package ecdsasecp256k1signature2019 implements the EcdsaSecp256k1Signature2019 signature suite
// for the Linked Data Signatures specification (https://w3c-dvcg.github.io/lds-ecdsa-secp256k1-2019/).
// It uses the RDF Dataset Normalization Algorithm to transform the input document into its canonical form.
// It uses SHA-256 [RFC6234] as the message digest algorithm.
// Supported signature algorithms depend on the signer/verifier provided as options to the New().
package ecdsasecp256k1signature2019

import (
	"crypto/sha256"

	"github.com/trustbloc/did-go/doc/ld/processor"
	"github.com/trustbloc/kms-go/spi/kms"

	"github.com/trustbloc/vc-go/proof"
)

// Proof implements EcdsaSecp256k1Signature2019 proof type.
type Proof struct {
	jsonldProcessor *processor.Processor
	supportedVMs    []proof.SupportedVerificationMethod
}

const (
	ProofType              = "EcdsaSecp256k1Signature2019"
	VerificationMethodType = "EcdsaSecp256k1VerificationKey2019"
	JWKKeyType             = "EC"
	JWKCurve               = "secp256k1"
	CorrespondedJWTAlg     = "ES256K"
	rdfDataSetAlg          = "URDNA2015"
)

// New an instance of Linked Data Signatures for JWS suite.
func New() *Proof {
	p := &Proof{jsonldProcessor: processor.NewProcessor(rdfDataSetAlg)}
	p.supportedVMs = []proof.SupportedVerificationMethod{
		{
			VerificationMethodType: VerificationMethodType,
			// TODO: verify if this kms.ECDSASecp256k1TypeDER or kms.ECDSASecp256k1TypeIEEEP1363
			KMSKeyType: kms.ECDSASecp256k1TypeIEEEP1363,
			JWKKeyType: JWKKeyType,
			JWKCurve:   JWKCurve,
		},
		{
			VerificationMethodType: "JsonWebKey2020",
			KMSKeyType:             kms.ECDSASecp256k1TypeIEEEP1363,
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

// CorrespondedJWTAlg return jwt alg that corresponds to VerificationMethod.
func (s *Proof) IsJWTAlgSupported(alg string) bool {
	return alg == CorrespondedJWTAlg
}

// GetCanonicalDocument will return normalized/canonical version of the document.
// EcdsaSecp256k1Signature2019 signature suite uses RDF Dataset Normalization as canonicalization algorithm.
func (s *Proof) GetCanonicalDocument(doc map[string]interface{}, opts ...processor.Opts) ([]byte, error) {
	return s.jsonldProcessor.GetCanonicalDocument(doc, opts...)
}

// GetDigest returns document digest.
func (s *Proof) GetDigest(doc []byte) []byte {
	digest := sha256.Sum256(doc)
	return digest[:]
}
