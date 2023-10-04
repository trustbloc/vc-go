package proof

import (
	"github.com/trustbloc/did-go/doc/ld/processor"
	"github.com/trustbloc/kms-go/spi/kms"
)

type SupportedVerificationMethod struct {
	VerificationMethodType string // verification method type from did. E.g. Ed25519VerificationKey2020, JsonWebKey2020.
	KMSKeyType             kms.KeyType
	JWKKeyType             string
	JWKCurve               string
	RequireJWK             bool
}

type LDProofDescriptor interface {
	// GetCanonicalDocument will return normalized/canonical version of the document
	GetCanonicalDocument(doc map[string]interface{}, opts ...processor.Opts) ([]byte, error)

	// GetDigest returns document digest.
	GetDigest(doc []byte) []byte

	// ProofType return proof type.
	ProofType() string

	SupportedVerificationMethods() []SupportedVerificationMethod
}

type JWTProofDescriptor interface {
	JWTAlgorithm() string

	SupportedVerificationMethods() []SupportedVerificationMethod
}
