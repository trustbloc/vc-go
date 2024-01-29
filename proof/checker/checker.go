/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package checker

import (
	"fmt"

	"github.com/tidwall/gjson"
	"github.com/trustbloc/did-go/doc/ld/processor"
	"github.com/trustbloc/did-go/doc/ld/proof"
	"github.com/trustbloc/kms-go/doc/jose"
	"github.com/trustbloc/kms-go/doc/jose/jwk"
	"github.com/trustbloc/kms-go/spi/kms"
	"github.com/veraison/go-cose"

	"github.com/trustbloc/vc-go/crypto-ext/pubkey"
	proofdesc "github.com/trustbloc/vc-go/proof"
	"github.com/trustbloc/vc-go/vermethod"
)

type verificationMethodResolver interface {
	ResolveVerificationMethod(verificationMethod string, expectedProofIssuer string) (*vermethod.VerificationMethod, error)
}

type signatureVerifier interface {
	// SupportedKeyType checks if verifier supports given key.
	SupportedKeyType(keyType kms.KeyType) bool
	// Verify verifies the signature.
	Verify(sig, msg []byte, pub *pubkey.PublicKey) error
}

type signatureVerifierEx interface {
	// Verify verifies the signature.
	Verify(sig, msg []byte, pub *pubkey.PublicKey, proof *proof.Proof) error
}

type ldCheckDescriptor struct {
	proofDescriptor          proofdesc.LDProofDescriptor
	proofSignatureVerifierEx signatureVerifierEx
}

type jwtCheckDescriptor struct {
	proofDescriptor proofdesc.JWTProofDescriptor
}

type cwtCheckDescriptor struct {
	proofDescriptor proofdesc.JWTProofDescriptor
}

// nolint: gochecknoglobals
var possibleIssuerPath = []string{
	"vc.issuer.id",
	"vc.issuer",
	"issuer.id",
	"issuer",
	"iss",
}

// ProofCheckerBase basic implementation of proof checker.
type ProofCheckerBase struct {
	supportedLDProofs  []ldCheckDescriptor
	supportedJWTProofs []jwtCheckDescriptor
	supportedCWTProofs []cwtCheckDescriptor
	signatureVerifiers []signatureVerifier
}

// ProofChecker checks proofs of jd and jwt documents.
type ProofChecker struct {
	ProofCheckerBase

	verificationMethodResolver verificationMethodResolver
}

// Opt represent checker creation options.
type Opt func(c *ProofCheckerBase)

// WithLDProofTypes option to set supported ld proofs.
func WithLDProofTypes(proofDescs ...proofdesc.LDProofDescriptor) Opt {
	return func(c *ProofCheckerBase) {
		for _, proofDesc := range proofDescs {
			c.supportedLDProofs = append(c.supportedLDProofs, ldCheckDescriptor{
				proofDescriptor: proofDesc,
			})
		}
	}
}

// WithLDProofTypeEx option to set supported ld proofs.
func WithLDProofTypeEx(proofDesc proofdesc.LDProofDescriptor, proofSignatureVerifier signatureVerifierEx) Opt {
	return func(c *ProofCheckerBase) {
		c.supportedLDProofs = append(c.supportedLDProofs, ldCheckDescriptor{
			proofDescriptor:          proofDesc,
			proofSignatureVerifierEx: proofSignatureVerifier,
		})
	}
}

// WithJWTAlg option to set supported jwt algs.
func WithJWTAlg(proofDescs ...proofdesc.JWTProofDescriptor) Opt {
	return func(c *ProofCheckerBase) {
		for _, proofDesc := range proofDescs {
			c.supportedJWTProofs = append(c.supportedJWTProofs, jwtCheckDescriptor{
				proofDescriptor: proofDesc,
			})
		}
	}
}

// WithCWTAlg option to set supported jwt algs.
func WithCWTAlg(proofDescs ...proofdesc.JWTProofDescriptor) Opt {
	return func(c *ProofCheckerBase) {
		for _, proofDesc := range proofDescs {
			c.supportedCWTProofs = append(c.supportedCWTProofs, cwtCheckDescriptor{
				proofDescriptor: proofDesc,
			})
		}
	}
}

// WithSignatureVerifiers option to set signature verifiers.
func WithSignatureVerifiers(verifiers ...signatureVerifier) Opt {
	return func(c *ProofCheckerBase) {
		c.signatureVerifiers = append(c.signatureVerifiers, verifiers...)
	}
}

// New creates new proof checker.
func New(verificationMethodResolver verificationMethodResolver, opts ...Opt) *ProofChecker {
	c := &ProofChecker{
		verificationMethodResolver: verificationMethodResolver,
	}

	for _, opt := range opts {
		opt(&c.ProofCheckerBase)
	}

	return c
}

// CheckLDProof check ld proof.
func (c *ProofChecker) CheckLDProof(proof *proof.Proof, expectedProofIssuer string, msg, signature []byte) error {
	publicKeyID, err := proof.PublicKeyID()
	if err != nil {
		return fmt.Errorf("proof missing public key id: %w", err)
	}

	vm, err := c.verificationMethodResolver.ResolveVerificationMethod(publicKeyID, expectedProofIssuer)
	if err != nil {
		return fmt.Errorf("proof invalid public key id: %w", err)
	}

	supportedProof, err := c.getSupportedProof(proof.Type)
	if err != nil {
		return err
	}

	pubKey, err := convertToPublicKey(supportedProof.proofDescriptor.SupportedVerificationMethods(), vm)
	if err != nil {
		return fmt.Errorf("%s proof check: %w", proof.Type, err)
	}

	if supportedProof.proofSignatureVerifierEx != nil {
		return supportedProof.proofSignatureVerifierEx.Verify(signature, msg, pubKey, proof)
	}

	verifier, err := c.getSignatureVerifier(pubKey.Type)
	if err != nil {
		return err
	}

	return verifier.Verify(signature, msg, pubKey)
}

// GetLDPCanonicalDocument will return normalized/canonical version of the document.
func (c *ProofCheckerBase) GetLDPCanonicalDocument(proof *proof.Proof,
	doc map[string]interface{}, opts ...processor.Opts) ([]byte, error) {
	supportedProof, err := c.getSupportedProof(proof.Type)
	if err != nil {
		return nil, err
	}

	return supportedProof.proofDescriptor.GetCanonicalDocument(doc, opts...)
}

// GetLDPDigest returns document digest.
func (c *ProofCheckerBase) GetLDPDigest(proof *proof.Proof, doc []byte) ([]byte, error) {
	supportedProof, err := c.getSupportedProof(proof.Type)
	if err != nil {
		return nil, err
	}

	return supportedProof.proofDescriptor.GetDigest(doc), nil
}

// CheckJWTProof check jwt proof.
func (c *ProofChecker) CheckJWTProof(headers jose.Headers, expectedProofIssuer string, msg, signature []byte) error {
	keyID, ok := headers.KeyID()
	if !ok {
		return fmt.Errorf("missed kid in jwt header")
	}

	alg, ok := headers.Algorithm()
	if !ok {
		return fmt.Errorf("missed alg in jwt header")
	}

	vm, err := c.verificationMethodResolver.ResolveVerificationMethod(keyID, expectedProofIssuer)
	if err != nil {
		return fmt.Errorf("invalid public key id: %w", err)
	}

	supportedProof, err := c.getSupportedProofByAlg(alg)
	if err != nil {
		return err
	}

	pubKey, err := convertToPublicKey(supportedProof.proofDescriptor.SupportedVerificationMethods(), vm)
	if err != nil {
		return fmt.Errorf("jwt with alg %s check: %w", alg, err)
	}

	verifier, err := c.getSignatureVerifier(pubKey.Type)
	if err != nil {
		return err
	}

	return verifier.Verify(signature, msg, pubKey)
}

func (c *ProofChecker) CheckCWTProof(
	checkCWTRequest CheckCWTProofRequest,
	msg *cose.Sign1Message,
	expectedProofIssuer string,
) error {
	if checkCWTRequest.KeyID == "" {
		return fmt.Errorf("missed kid in jwt header")
	}

	if checkCWTRequest.Algo == 0 {
		return fmt.Errorf("missed alg in cwt header")
	}

	vm, err := c.verificationMethodResolver.ResolveVerificationMethod(checkCWTRequest.KeyID, expectedProofIssuer)
	if err != nil {
		return fmt.Errorf("invalid public key id: %w", err)
	}

	supportedProof, err := c.getSupportedCWTProofByAlg(checkCWTRequest.Algo)
	if err != nil {
		return err
	}

	pubKey, err := convertToPublicKey(supportedProof.proofDescriptor.SupportedVerificationMethods(), vm)
	if err != nil {
		return fmt.Errorf("cwt with alg %s check: %w", checkCWTRequest.Algo, err)
	}

	verifier, err := cose.NewVerifier(checkCWTRequest.Algo, pubKey)
	if err != nil {
		return err
	}

	return msg.Verify(nil, verifier)
}

// FindIssuer finds issuer in payload.
func (c *ProofChecker) FindIssuer(payload []byte) string {
	parsed := gjson.ParseBytes(payload)

	for _, p := range possibleIssuerPath {
		if str := parsed.Get(p).Str; str != "" {
			return str
		}
	}

	return ""
}

func convertToPublicKey(
	supportedMethods []proofdesc.SupportedVerificationMethod,
	vm *vermethod.VerificationMethod,
) (*pubkey.PublicKey, error) {
	for _, supported := range supportedMethods {
		if supported.VerificationMethodType != vm.Type {
			continue
		}

		if vm.JWK == nil && supported.RequireJWK {
			continue
		}

		if vm.JWK != nil && (supported.JWKKeyType != vm.JWK.Kty || supported.JWKCurve != vm.JWK.Crv) {
			continue
		}

		return createPublicKey(vm, supported.KMSKeyType), nil
	}

	jwkKty := ""
	jwkCrv := ""

	if vm.JWK != nil {
		jwkKty = vm.JWK.Kty
		jwkCrv = vm.JWK.Crv
	}

	return nil, fmt.Errorf("can't verifiy with %q verification method (jwk type %q, jwk curve %q)",
		vm.Type, jwkKty, jwkCrv)
}

func createPublicKey(vm *vermethod.VerificationMethod, keyType kms.KeyType) *pubkey.PublicKey {
	if vm.JWK != nil {
		return &pubkey.PublicKey{Type: keyType, JWK: vm.JWK}
	}

	return &pubkey.PublicKey{Type: keyType, BytesKey: &pubkey.BytesKey{Bytes: vm.Value}}
}

func (c *ProofCheckerBase) getSupportedProof(proofType string) (ldCheckDescriptor, error) {
	for _, supported := range c.supportedLDProofs {
		if supported.proofDescriptor.ProofType() == proofType {
			return supported, nil
		}
	}

	return ldCheckDescriptor{}, fmt.Errorf("unsupported proof type: %s", proofType)
}

func (c *ProofCheckerBase) getSupportedProofByAlg(jwtAlg string) (jwtCheckDescriptor, error) {
	for _, supported := range c.supportedJWTProofs {
		if supported.proofDescriptor.JWTAlgorithm() == jwtAlg {
			return supported, nil
		}
	}

	return jwtCheckDescriptor{}, fmt.Errorf("unsupported jwt alg: %s", jwtAlg)
}

func (c *ProofCheckerBase) getSupportedCWTProofByAlg(cwtAlg cose.Algorithm) (cwtCheckDescriptor, error) {
	for _, supported := range c.supportedCWTProofs {
		if supported.proofDescriptor.CWTAlgorithm() == cwtAlg {
			return supported, nil
		}
	}

	return cwtCheckDescriptor{}, fmt.Errorf("unsupported cwt alg: %s", cwtAlg)
}

func (c *ProofCheckerBase) getSignatureVerifier(keyType kms.KeyType) (signatureVerifier, error) {
	for _, verifier := range c.signatureVerifiers {
		if verifier.SupportedKeyType(keyType) {
			return verifier, nil
		}
	}

	return nil, fmt.Errorf("no vefiers with supported key type %s", keyType)
}

// EmbeddedVMProofChecker is a proof  checker with embedded verification method.
type EmbeddedVMProofChecker struct {
	ProofCheckerBase
	vm *vermethod.VerificationMethod
}

// CheckJWTProof check jwt proof.
func (c *EmbeddedVMProofChecker) CheckJWTProof(headers jose.Headers, _ string, msg, signature []byte) error {
	alg, ok := headers.Algorithm()
	if !ok {
		return fmt.Errorf("missed alg in jwt header")
	}

	supportedProof, err := c.getSupportedProofByAlg(alg)
	if err != nil {
		return err
	}

	pubKey, err := convertToPublicKey(supportedProof.proofDescriptor.SupportedVerificationMethods(), c.vm)
	if err != nil {
		return fmt.Errorf("jwt with alg %s check: %w", alg, err)
	}

	verifier, err := c.getSignatureVerifier(pubKey.Type)
	if err != nil {
		return err
	}

	return verifier.Verify(signature, msg, pubKey)
}

// NewEmbeddedJWKProofChecker return new EmbeddedVMProofChecker with embedded jwk.
func NewEmbeddedJWKProofChecker(jwk *jwk.JWK, opts ...Opt) *EmbeddedVMProofChecker {
	return NewEmbeddedVMProofChecker(&vermethod.VerificationMethod{Type: "JsonWebKey2020", JWK: jwk}, opts...)
}

// NewEmbeddedVMProofChecker return new EmbeddedVMProofChecker.
func NewEmbeddedVMProofChecker(vm *vermethod.VerificationMethod, opts ...Opt) *EmbeddedVMProofChecker {
	c := &EmbeddedVMProofChecker{
		vm: vm,
	}

	for _, opt := range opts {
		opt(&c.ProofCheckerBase)
	}

	return c
}
