/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package proof

import (
	"github.com/trustbloc/did-go/doc/ld/processor"
	"github.com/trustbloc/kms-go/spi/kms"
	"github.com/veraison/go-cose"
)

const (
	// CWTProofType is the proof type for CWT.
	CWTProofType = "application/openid4vci-proof+cwt"

	// COSEKeyHeader is the header for COSE key.
	COSEKeyHeader = "COSE_Key"
)

// SupportedVerificationMethod describes verification methods that supported by proof checker.
type SupportedVerificationMethod struct {
	VerificationMethodType string // verification method type from did. E.g. Ed25519VerificationKey2020, JsonWebKey2020.
	KMSKeyType             kms.KeyType
	JWKKeyType             string
	JWKCurve               string
	RequireJWK             bool
}

// LDProofDescriptor describes ld proof.
type LDProofDescriptor interface {
	// GetCanonicalDocument will return normalized/canonical version of the document
	GetCanonicalDocument(doc map[string]interface{}, opts ...processor.Opts) ([]byte, error)

	// GetDigest returns document digest.
	GetDigest(doc []byte) []byte

	// ProofType return proof type.
	ProofType() string

	SupportedVerificationMethods() []SupportedVerificationMethod
}

// JWTProofDescriptor describes jwt proof.
type JWTProofDescriptor interface {
	JWTAlgorithm() string
	CWTAlgorithm() cose.Algorithm

	SupportedVerificationMethods() []SupportedVerificationMethod
}
