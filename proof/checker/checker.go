package checker

import (
	"fmt"

	"github.com/trustbloc/did-go/doc/ld/processor"
	"github.com/trustbloc/did-go/doc/ld/proof"
	"github.com/trustbloc/kms-go/doc/jose"
	"github.com/trustbloc/kms-go/doc/jose/jwk"
	"github.com/trustbloc/kms-go/spi/kms"

	"github.com/trustbloc/vc-go/crypto-ext/pubkey"
	proofdesc "github.com/trustbloc/vc-go/proof"
	"github.com/trustbloc/vc-go/vermethod"
)

type verificationMethodResolver interface {
	ResolveVerificationMethod(verificationMethod string) (*vermethod.VerificationMethod, error)
}

type signatureVerifier interface {
	SupportedKeyType(keyType kms.KeyType) bool
	Verify(sig, msg []byte, pub *pubkey.PublicKey) error
}

type signatureVerifierEx interface {
	Verify(sig, msg []byte, pub *pubkey.PublicKey, proof *proof.Proof) error
}

type ldCheckDescriptor struct {
	proofDescriptor          proofdesc.LDProofDescriptor
	proofSignatureVerifierEx signatureVerifierEx
}

type jwtCheckDescriptor struct {
	proofDescriptor proofdesc.JWTProofDescriptor
}

type ProofCheckerBase struct {
	supportedLDProofs  []ldCheckDescriptor
	supportedJWTProofs []jwtCheckDescriptor
	signatureVerifiers []signatureVerifier
}

type ProofChecker struct {
	ProofCheckerBase

	verificationMethodResolver verificationMethodResolver
}

type checkerOpt func(c *ProofCheckerBase)

func WithLDProofTypes(proofDescs ...proofdesc.LDProofDescriptor) checkerOpt {
	return func(c *ProofCheckerBase) {
		for _, proofDesc := range proofDescs {
			c.supportedLDProofs = append(c.supportedLDProofs, ldCheckDescriptor{
				proofDescriptor: proofDesc,
			})
		}
	}
}

func WithLDProofTypeEx(proofDesc proofdesc.LDProofDescriptor, proofSignatureVerifier signatureVerifierEx) checkerOpt {
	return func(c *ProofCheckerBase) {
		c.supportedLDProofs = append(c.supportedLDProofs, ldCheckDescriptor{
			proofDescriptor:          proofDesc,
			proofSignatureVerifierEx: proofSignatureVerifier,
		})
	}
}

func WithJWTAlg(proofDescs ...proofdesc.JWTProofDescriptor) checkerOpt {
	return func(c *ProofCheckerBase) {
		for _, proofDesc := range proofDescs {
			c.supportedJWTProofs = append(c.supportedJWTProofs, jwtCheckDescriptor{
				proofDescriptor: proofDesc,
			})
		}
	}
}

func WithSignatreVerifiers(verifiers ...signatureVerifier) checkerOpt {
	return func(c *ProofCheckerBase) {
		c.signatureVerifiers = append(c.signatureVerifiers, verifiers...)
	}
}

func New(verificationMethodResolver verificationMethodResolver, opts ...checkerOpt) *ProofChecker {
	c := &ProofChecker{
		verificationMethodResolver: verificationMethodResolver,
	}

	for _, opt := range opts {
		opt(&c.ProofCheckerBase)
	}
	return c
}

func (c *ProofChecker) CheckLDProof(proof *proof.Proof, msg, signature []byte) error {
	publicKeyID, err := proof.PublicKeyID()
	if err != nil {
		return fmt.Errorf("proof missing public key id: %w", err)
	}

	vm, err := c.verificationMethodResolver.ResolveVerificationMethod(publicKeyID)
	if err != nil {
		return fmt.Errorf("proof missing public key id: %w", err)
	}

	supportedProof, err := c.getSupportedProof(proof.Type)
	if err != nil {
		return err
	}

	pubKey, err := ConvertToPublicKey(supportedProof.proofDescriptor.SupportedVerificationMethods(), vm)
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

func (c *ProofCheckerBase) GetLDPCanonicalDocument(proof *proof.Proof,
	doc map[string]interface{}, opts ...processor.Opts) ([]byte, error) {
	supportedProof, err := c.getSupportedProof(proof.Type)
	if err != nil {
		return nil, err
	}

	return supportedProof.proofDescriptor.GetCanonicalDocument(doc, opts...)
}

// GetLDPDigest returns document digest
func (c *ProofCheckerBase) GetLDPDigest(proof *proof.Proof, doc []byte) ([]byte, error) {
	supportedProof, err := c.getSupportedProof(proof.Type)
	if err != nil {
		return nil, err
	}

	return supportedProof.proofDescriptor.GetDigest(doc), nil
}

func (c *ProofChecker) CheckJWTProof(headers jose.Headers, _, msg, signature []byte) error {
	keyID, ok := headers.KeyID()
	if !ok {
		return fmt.Errorf("missed kid in jwt header")
	}

	alg, ok := headers.Algorithm()
	if !ok {
		return fmt.Errorf("missed kid in alg header")
	}

	vm, err := c.verificationMethodResolver.ResolveVerificationMethod(keyID)
	if err != nil {
		return fmt.Errorf("proof missing public key id: %w", err)
	}

	supportedProof, err := c.getSupportedProofByAlg(alg)
	if err != nil {
		return err
	}

	pubKey, err := ConvertToPublicKey(supportedProof.proofDescriptor.SupportedVerificationMethods(), vm)
	if err != nil {
		return fmt.Errorf("jwt with alg %s check: %w", alg, err)
	}

	verifier, err := c.getSignatureVerifier(pubKey.Type)
	if err != nil {
		return err
	}

	return verifier.Verify(signature, msg, pubKey)
}

// TODO: take attention to this during review
func ConvertToPublicKey(
	supportedMethods []proofdesc.SupportedVerificationMethod,
	vm *vermethod.VerificationMethod) (*pubkey.PublicKey, error) {
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

	return nil, fmt.Errorf("can't verifiy %s vm %s (jwk type %q, jwk curve %q)",
		vm.Type, vm.Type, jwkKty, jwkCrv)
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

func (c *ProofCheckerBase) getSignatureVerifier(keyType kms.KeyType) (signatureVerifier, error) {
	for _, verifier := range c.signatureVerifiers {
		if verifier.SupportedKeyType(keyType) {
			return verifier, nil
		}
	}

	return nil, fmt.Errorf("no vefiers with supported key type %s", keyType)
}

type EmbeddedVMProofChecker struct {
	ProofCheckerBase
	vm *vermethod.VerificationMethod
}

func (c *EmbeddedVMProofChecker) CheckJWTProof(headers jose.Headers, _, msg, signature []byte) error {
	alg, ok := headers.Algorithm()
	if !ok {
		return fmt.Errorf("missed kid in alg header")
	}

	supportedProof, err := c.getSupportedProofByAlg(alg)
	if err != nil {
		return err
	}

	pubKey, err := ConvertToPublicKey(supportedProof.proofDescriptor.SupportedVerificationMethods(), c.vm)
	if err != nil {
		return fmt.Errorf("jwt with alg %s check: %w", alg, err)
	}

	verifier, err := c.getSignatureVerifier(pubKey.Type)
	if err != nil {
		return err
	}

	return verifier.Verify(signature, msg, pubKey)
}

func NewEmbeddedJWKProofChecker(jwk *jwk.JWK, opts ...checkerOpt) *EmbeddedVMProofChecker {
	return NewEmbeddedVMProofChecker(&vermethod.VerificationMethod{Type: "JsonWebKey2020", JWK: jwk}, opts...)
}

func NewEmbeddedVMProofChecker(vm *vermethod.VerificationMethod, opts ...checkerOpt) *EmbeddedVMProofChecker {
	c := &EmbeddedVMProofChecker{
		vm: vm,
	}

	for _, opt := range opts {
		opt(&c.ProofCheckerBase)
	}
	return c
}
