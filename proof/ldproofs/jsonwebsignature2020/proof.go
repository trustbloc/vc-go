/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package jsonwebsignature2020 implements the JsonWebSignature2020 signature suite
// for the Linked Data Signatures specification (https://github.com/transmute-industries/lds-jws2020).
// It uses the RDF Dataset Normalization Algorithm
// to transform the input document into its canonical form.
// It uses SHA-256 [RFC6234] as the message digest algorithm.
// Supported signature algorithms depend on the signer/verifier provided as options to the New().
// According to the suite specification, signer/verifier must support the following algorithms:
// kty | crvOrSize | alg
// OKP | Ed25519   | EdDSA
// EC  | secp256k1 | ES256K
// RSA | 2048      | PS256
// EC  | P-256     | ES256
// EC  | P-384     | ES384
// EC  | P-521     | ES512
package jsonwebsignature2020

import (
	"crypto/sha256"

	"github.com/trustbloc/did-go/doc/ld/processor"
	"github.com/trustbloc/kms-go/spi/kms"

	"github.com/trustbloc/vc-go/proof"
)

// Proof describe jsonWebSignature2020 signature suite.
type Proof struct {
	jsonldProcessor *processor.Processor
	supportedVMs    []proof.SupportedVerificationMethod
}

// nolint: golint
const (
	ProofType              = "JsonWebSignature2020"
	VerificationMethodType = "JsonWebKey2020"
	rdfDataSetAlg          = "URDNA2015"

	Ed25519JWKKeyType = "OKP"
	Ed25519JWKCurve   = "Ed25519"

	ECDSASecp256k1JWKKeyType = "EC"
	ECDSASecp256k1JWKCurve   = "secp256k1"

	RSAPS256JWKKeyType = "RSA"

	ECDSAES256JWKKeyType = "EC"
	ECDSAES256JWKCurve   = "P-256"

	ECDSAES384JWKKeyType = "EC"
	ECDSAES384JWKCurve   = "P-384"

	ECDSAES521JWKKeyType = "EC"
	ECDSAES521JWKCurve   = "P-521"
)

// ProofType return proof type name.
func (s *Proof) ProofType() string {
	return ProofType
}

// New an instance of JsonWebSignature2020 proof descriptor.
func New() *Proof {
	p := &Proof{jsonldProcessor: processor.NewProcessor(rdfDataSetAlg)}
	p.supportedVMs = []proof.SupportedVerificationMethod{
		{
			VerificationMethodType: VerificationMethodType,
			KMSKeyType:             kms.ED25519Type,
			JWKKeyType:             Ed25519JWKKeyType,
			JWKCurve:               Ed25519JWKCurve,
			RequireJWK:             true,
		},
		{
			VerificationMethodType: VerificationMethodType,
			KMSKeyType:             kms.ECDSASecp256k1TypeIEEEP1363,
			JWKKeyType:             ECDSASecp256k1JWKKeyType,
			JWKCurve:               ECDSASecp256k1JWKCurve,
			RequireJWK:             true,
		},
		{
			VerificationMethodType: VerificationMethodType,
			KMSKeyType:             kms.RSAPS256Type,
			JWKKeyType:             RSAPS256JWKKeyType,
			RequireJWK:             true,
		},
		{
			VerificationMethodType: VerificationMethodType,
			KMSKeyType:             kms.ECDSAP256TypeIEEEP1363,
			JWKKeyType:             ECDSAES256JWKKeyType,
			JWKCurve:               ECDSAES256JWKCurve,
			RequireJWK:             true,
		},
		{
			VerificationMethodType: VerificationMethodType,
			KMSKeyType:             kms.ECDSAP384TypeIEEEP1363,
			JWKKeyType:             ECDSAES384JWKKeyType,
			JWKCurve:               ECDSAES384JWKCurve,
			RequireJWK:             true,
		},
		{
			VerificationMethodType: VerificationMethodType,
			KMSKeyType:             kms.ECDSAP521TypeIEEEP1363,
			JWKKeyType:             ECDSAES521JWKKeyType,
			JWKCurve:               ECDSAES521JWKCurve,
			RequireJWK:             true,
		},
	}

	return p
}

// SupportedVerificationMethods returns list of verification methods supported by this proof type.
func (s *Proof) SupportedVerificationMethods() []proof.SupportedVerificationMethod {
	return s.supportedVMs
}

// GetCanonicalDocument will return normalized/canonical version of the document
// Ed25519Signature2018 signature SignatureSuite uses RDF Dataset Normalization as canonicalization algorithm.
func (s *Proof) GetCanonicalDocument(doc map[string]interface{}, opts ...processor.Opts) ([]byte, error) {
	return s.jsonldProcessor.GetCanonicalDocument(doc, opts...)
}

// GetDigest returns document digest.
func (s *Proof) GetDigest(doc []byte) []byte {
	digest := sha256.Sum256(doc)
	return digest[:]
}
