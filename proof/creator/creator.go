/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package creator

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/trustbloc/did-go/doc/ld/processor"
	"github.com/trustbloc/did-go/doc/ld/proof"
	"github.com/trustbloc/kms-go/doc/jose"
	"github.com/trustbloc/kms-go/spi/kms"
	"github.com/veraison/go-cose"

	"github.com/trustbloc/vc-go/cwt"
	"github.com/trustbloc/vc-go/jwt"
	proofdesc "github.com/trustbloc/vc-go/proof"
)

// ProofCreator incapsulate logic of proof creation.
type ProofCreator struct {
	supportedLDProofs []ldProofCreateDescriptor
	supportedJWTAlgs  []jwtProofCreateDescriptor
}

type ldProofCreateDescriptor struct {
	proofDescriptor     proofdesc.LDProofDescriptor
	cryptographicSigner cryptographicSigner
}

type jwtProofCreateDescriptor struct {
	proofDescriptor     proofdesc.JWTProofDescriptor
	cryptographicSigner cryptographicSigner
}

type cryptographicSigner interface {
	// Sign will sign document and return signature.
	Sign(data []byte) ([]byte, error)
}

// Opt represent ProofCreator creation options.
type Opt func(c *ProofCreator)

// WithLDProofType option to set supported ld proof.
func WithLDProofType(proofDesc proofdesc.LDProofDescriptor, cryptographicSigner cryptographicSigner) Opt {
	return func(c *ProofCreator) {
		c.supportedLDProofs = append(c.supportedLDProofs, ldProofCreateDescriptor{
			proofDescriptor:     proofDesc,
			cryptographicSigner: cryptographicSigner,
		})
	}
}

// WithJWTAlg option to set supported jwt alg.
func WithJWTAlg(proofDesc proofdesc.JWTProofDescriptor, cryptographicSigner cryptographicSigner) Opt {
	return func(c *ProofCreator) {
		c.supportedJWTAlgs = append(c.supportedJWTAlgs, jwtProofCreateDescriptor{
			proofDescriptor:     proofDesc,
			cryptographicSigner: cryptographicSigner,
		})
	}
}

// New creates ProofCreator.
func New(opts ...Opt) *ProofCreator {
	c := &ProofCreator{}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// SignLinkedDocument will sign document and return signature.
func (c *ProofCreator) SignLinkedDocument(proof *proof.Proof, keyType kms.KeyType, doc []byte) ([]byte, error) {
	supportedProof, err := c.getSupportedProof(proof.Type)
	if err != nil {
		return nil, err
	}

	supportedMethods :=
		filterSupportedMethodsByKeyType(keyType, supportedProof.proofDescriptor.SupportedVerificationMethods())

	if len(supportedMethods) == 0 {
		return nil, fmt.Errorf("ld proof %q not support %q keys", proof.Type, keyType)
	}

	return supportedProof.cryptographicSigner.Sign(doc)
}

// GetLDPCanonicalDocument will return normalized/canonical version of the document.
func (c *ProofCreator) GetLDPCanonicalDocument(proof *proof.Proof,
	doc map[string]interface{}, opts ...processor.Opts) ([]byte, error) {
	supportedProof, err := c.getSupportedProof(proof.Type)
	if err != nil {
		return nil, err
	}

	return supportedProof.proofDescriptor.GetCanonicalDocument(doc, opts...)
}

// GetLDPDigest returns document digest.
func (c *ProofCreator) GetLDPDigest(proof *proof.Proof, doc []byte) ([]byte, error) {
	supportedProof, err := c.getSupportedProof(proof.Type)
	if err != nil {
		return nil, err
	}

	return supportedProof.proofDescriptor.GetDigest(doc), nil
}

// LDPJWTAlg will return algorithm for jws signature.
func (c *ProofCreator) LDPJWTAlg(proof *proof.Proof, keyType kms.KeyType) (string, error) {
	supportedProof, err := c.getSupportedProof(proof.Type)
	if err != nil {
		return "", err
	}

	supportedMethods :=
		filterSupportedMethodsByKeyType(keyType, supportedProof.proofDescriptor.SupportedVerificationMethods())

	if len(supportedMethods) == 0 {
		return "", fmt.Errorf("ld proof %q not support %q keys", proof.Type, keyType)
	}

	jwtAlg := c.findJWTAlgByKeyType(keyType)
	if jwtAlg == "" {
		return "", fmt.Errorf("no jwt algs that support %q key", keyType)
	}

	return jwtAlg, nil
}

func filterSupportedMethodsByKeyType(keyType kms.KeyType,
	supportedMethods []proofdesc.SupportedVerificationMethod) []proofdesc.SupportedVerificationMethod {
	var result []proofdesc.SupportedVerificationMethod

	for _, vm := range supportedMethods {
		if vm.KMSKeyType == keyType {
			result = append(result, vm)
		}
	}

	return result
}

func (c *ProofCreator) findJWTAlgByKeyType(keyType kms.KeyType) string {
	for _, supported := range c.supportedJWTAlgs {
		for _, vm := range supported.proofDescriptor.SupportedVerificationMethods() {
			if vm.KMSKeyType == keyType {
				return supported.proofDescriptor.JWTAlgorithm()
			}
		}
	}

	return ""
}

// SignJWT will sign document and return signature.
func (c *ProofCreator) SignJWT(params jwt.SignParameters, data []byte) ([]byte, error) {
	supportedProof, err := c.getSupportedProofByAlg(params.JWTAlg)
	if err != nil {
		return nil, err
	}

	return supportedProof.cryptographicSigner.Sign(data)
}

// SignCWT will sign document and return signature.
func (c *ProofCreator) SignCWT(params cwt.SignParameters, message *cose.Sign1Message) ([]byte, error) {
	supportedProof, err := c.getSupportedProofByCwtAlg(params.CWTAlg)
	if err != nil {
		return nil, err
	}

	var protected cbor.RawMessage
	protected, err = message.Headers.MarshalProtected()
	if err != nil {
		return nil, err
	}

	cborProtectedData, err := deterministicBinaryString(protected)
	if err != nil {
		return nil, err
	}

	sigStructure := []interface{}{
		"Signature1",      // context
		cborProtectedData, // body_protected
		[]byte{},          // external_aad
		message.Payload,   // payload
	}

	cborData, err := cbor.Marshal(sigStructure)
	if err != nil {
		return nil, err
	}

	return supportedProof.cryptographicSigner.Sign(cborData)
}

// CreateJWTHeaders creates correct jwt headers.
func (c *ProofCreator) CreateJWTHeaders(params jwt.SignParameters) (jose.Headers, error) {
	headers := map[string]interface{}{
		jose.HeaderAlgorithm: params.JWTAlg,
	}

	if params.KeyID != "" {
		headers[jose.HeaderKeyID] = params.KeyID
	}

	return headers, nil
}

func (c *ProofCreator) getSupportedProof(proofType string) (ldProofCreateDescriptor, error) {
	for _, supported := range c.supportedLDProofs {
		if supported.proofDescriptor.ProofType() == proofType {
			return supported, nil
		}
	}

	return ldProofCreateDescriptor{}, fmt.Errorf("unsupported proof type: %s", proofType)
}

func (c *ProofCreator) getSupportedProofByCwtAlg(cwtAlg cose.Algorithm) (jwtProofCreateDescriptor, error) {
	for _, supported := range c.supportedJWTAlgs {
		if supported.proofDescriptor.CWTAlgorithm() == cwtAlg {
			return supported, nil
		}
	}

	return jwtProofCreateDescriptor{}, fmt.Errorf("unsupported cwt alg: %s", cwtAlg.String())
}

func (c *ProofCreator) getSupportedProofByAlg(jwtAlg string) (jwtProofCreateDescriptor, error) {
	for _, supported := range c.supportedJWTAlgs {
		if supported.proofDescriptor.JWTAlgorithm() == jwtAlg {
			return supported, nil
		}
	}

	return jwtProofCreateDescriptor{}, fmt.Errorf("unsupported jwt alg: %s", jwtAlg)
}
