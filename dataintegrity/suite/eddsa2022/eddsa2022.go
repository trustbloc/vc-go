/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package eddsa2022

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"hash"

	"github.com/multiformats/go-multibase"
	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/did-go/doc/ld/processor"
	"github.com/trustbloc/kms-go/doc/jose/jwk"
	"github.com/trustbloc/kms-go/spi/kms"
	wrapperapi "github.com/trustbloc/kms-go/wrapper/api"

	"github.com/trustbloc/vc-go/crypto-ext/pubkey"
	"github.com/trustbloc/vc-go/crypto-ext/verifiers/ed25519"
	"github.com/trustbloc/vc-go/dataintegrity/models"
	"github.com/trustbloc/vc-go/dataintegrity/suite"
)

const (
	// SuiteType "eddsa-rdfc-2022" is the data integrity Type identifier for the suite
	// implementing eddsa signatures with RDF canonicalization as per this
	// spec:https://w3c.github.io/vc-di-eddsa/#verify-proof-eddsa-rdfc-2022
	SuiteType = "eddsa-rdfc-2022"

	// SuiteType2 "eddsa-2022" is the data integrity Type identifier for the suite. Alias (vc playground).
	SuiteType2 = "eddsa-2022"
)

// SignerGetter returns a Signer, which must sign with the private key matching
// the public key provided in models.ProofOptions.VerificationMethod.
type SignerGetter func(pub *jwk.JWK) (Signer, error)

// WithStaticSigner sets the Suite to use a fixed Signer, with externally-chosen signing key.
//
// Use when a signing Suite is initialized for a single signature, then thrown away.
func WithStaticSigner(signer Signer) SignerGetter {
	return func(*jwk.JWK) (Signer, error) {
		return signer, nil
	}
}

// WithKMSCryptoWrapper provides a SignerGetter using the kmscrypto wrapper.
//
// This SignerGetter assumes that the public key JWKs provided were received
// from the same kmscrypto.KMSCrypto implementation.
func WithKMSCryptoWrapper(kmsCrypto wrapperapi.KMSCryptoSigner) SignerGetter {
	return func(pub *jwk.JWK) (Signer, error) {
		return kmsCrypto.FixedKeySigner(pub)
	}
}

// A KMSSigner is able to sign messages.
type KMSSigner interface { // TODO note: only used by deprecated function
	// Sign will sign msg using a matching signature primitive in kh key handle of a private key
	// returns:
	// 		signature in []byte
	//		error in case of errors
	Sign(msg []byte, kh interface{}) ([]byte, error)
}

// A Signer is able to sign messages.
type Signer interface {
	// Sign will sign msg using a private key internal to the Signer.
	// returns:
	// 		signature in []byte
	//		error in case of errors
	Sign(msg []byte) ([]byte, error)
}

// A Verifier is able to verify messages.
type Verifier interface {
	// Verify will verify a signature for the given msg using a matching signature primitive in kh key handle of
	// a public key
	// returns:
	// 		error in case of errors or nil if signature verification was successful
	Verify(signature, msg []byte, pubKey *pubkey.PublicKey) error
}

// Suite implements the eddsa-2022 data integrity cryptographic suite.
type Suite struct {
	ldLoader        ld.DocumentLoader
	signerGetter    SignerGetter
	eD25519Verifier Verifier
}

// Options provides initialization options for Suite.
type Options struct {
	LDDocumentLoader ld.DocumentLoader
	ED25519Verifier  Verifier
	SignerGetter     SignerGetter
}

// SuiteInitializer is the initializer for Suite.
type SuiteInitializer func() (suite.Suite, error)

// New constructs an initializer for Suite.
func New(options *Options) SuiteInitializer {
	return func() (suite.Suite, error) {
		return &Suite{
			ldLoader:        options.LDDocumentLoader,
			eD25519Verifier: options.ED25519Verifier,
			signerGetter:    options.SignerGetter,
		}, nil
	}
}

type initializer SuiteInitializer

// Signer private, implements suite.SignerInitializer.
func (i initializer) Signer() (suite.Signer, error) {
	return i()
}

// Verifier private, implements suite.VerifierInitializer.
func (i initializer) Verifier() (suite.Verifier, error) {
	return i()
}

// Type private, implements suite.SignerInitializer and
// suite.VerifierInitializer.
func (i initializer) Type() []string {
	return []string{SuiteType, SuiteType2}
}

// SignerInitializerOptions provides options for a SignerInitializer.
type SignerInitializerOptions struct {
	LDDocumentLoader ld.DocumentLoader
	SignerGetter     SignerGetter
}

// NewSignerInitializer returns a suite.SignerInitializer that initializes an eddsa-2022
// signing Suite with the given SignerInitializerOptions.
func NewSignerInitializer(options *SignerInitializerOptions) suite.SignerInitializer {
	return initializer(New(&Options{
		LDDocumentLoader: options.LDDocumentLoader,
		SignerGetter:     options.SignerGetter,
	}))
}

// VerifierInitializerOptions provides options for a VerifierInitializer.
type VerifierInitializerOptions struct {
	LDDocumentLoader ld.DocumentLoader // required
	Ed25519Verifier  Verifier          // optional
}

// NewVerifierInitializer returns a suite.VerifierInitializer that initializes an
// eddsa-2022 verification Suite with the given VerifierInitializerOptions.
func NewVerifierInitializer(options *VerifierInitializerOptions) suite.VerifierInitializer {
	ed25519Verifier := options.Ed25519Verifier

	if ed25519Verifier == nil {
		ed25519Verifier = ed25519.New()
	}

	return initializer(New(&Options{
		LDDocumentLoader: options.LDDocumentLoader,
		ED25519Verifier:  ed25519Verifier,
	}))
}

const (
	ldCtxKey = "@context"
)

// CreateProof implements the eddsa-2022 cryptographic suite for Add Proof.
func (s *Suite) CreateProof(doc []byte, opts *models.ProofOptions) (*models.Proof, error) {
	docHash, vmKey, _, err := s.transformAndHash(doc, opts)
	if err != nil {
		return nil, err
	}

	sig, err := sign(docHash, vmKey.JWK, s.signerGetter)
	if err != nil {
		return nil, err
	}

	sigStr, err := multibase.Encode(multibase.Base58BTC, sig)
	if err != nil {
		return nil, err
	}

	var expires string
	if !opts.Expires.IsZero() {
		expires = opts.Expires.Format(models.DateTimeFormat)
	}

	p := &models.Proof{
		Type:               models.DataIntegrityProof,
		CryptoSuite:        SuiteType,
		ProofPurpose:       opts.Purpose,
		Domain:             opts.Domain,
		Challenge:          opts.Challenge,
		VerificationMethod: opts.VerificationMethod.ID,
		ProofValue:         sigStr,
		Created:            opts.Created.Format(models.DateTimeFormat),
		Expires:            expires,
	}

	return p, nil
}

// nolint:gocyclo
func (s *Suite) transformAndHash(doc []byte, opts *models.ProofOptions) ([]byte, *pubkey.PublicKey, Verifier, error) {
	docData := make(map[string]interface{})

	err := json.Unmarshal(doc, &docData)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("eddsa-2022 suite expects JSON-LD payload: %w", err)
	}

	var (
		keyType  kms.KeyType
		h        hash.Hash
		verifier Verifier
	)

	verifier = s.eD25519Verifier
	keyType = kms.ED25519Type

	finalKey := &pubkey.PublicKey{Type: keyType, JWK: opts.VerificationMethod.JSONWebKey()}
	if finalKey.JWK == nil && len(opts.VerificationMethod.Value) > 0 {
		finalKey.BytesKey = &pubkey.BytesKey{Bytes: opts.VerificationMethod.Value}
	}

	if finalKey.JWK == nil && finalKey.BytesKey == nil {
		return nil, nil, nil, errors.New("verification method needs JWK")
	}

	h = sha256.New()

	confData := proofConfig(docData[ldCtxKey], opts)

	if opts.ProofType != models.DataIntegrityProof || (opts.SuiteType != SuiteType &&
		opts.SuiteType != SuiteType2) {
		return nil, nil, nil, suite.ErrProofTransformation
	}

	canonDoc, err := canonicalize(docData, s.ldLoader)
	if err != nil {
		return nil, nil, nil, err
	}

	canonConf, err := canonicalize(confData, s.ldLoader)
	if err != nil {
		return nil, nil, nil, err
	}

	docHash := hashData(canonDoc, canonConf, h)

	return docHash, finalKey, verifier, nil
}

// VerifyProof implements the eddsa-2022 cryptographic suite for CheckJWTProof Proof.
func (s *Suite) VerifyProof(doc []byte, proof *models.Proof, opts *models.ProofOptions) error {
	message, vmKey, verifier, err := s.transformAndHash(doc, opts)
	if err != nil {
		return err
	}

	_, signature, err := multibase.Decode(proof.ProofValue)
	if err != nil {
		return fmt.Errorf("decoding proofValue: %w", err)
	}

	err = verifier.Verify(signature, message, vmKey)
	if err != nil {
		return fmt.Errorf("failed to verify eddsa-2022 DI proof: %w", err)
	}

	return nil
}

// RequiresCreated returns false, as the eddsa-2022 cryptographic suite does not
// require the use of the models.Proof.Created field.
func (s *Suite) RequiresCreated() bool {
	return false
}

func canonicalize(data map[string]interface{}, loader ld.DocumentLoader) ([]byte, error) {
	out, err := processor.Default().GetCanonicalDocument(data, processor.WithDocumentLoader(loader))
	if err != nil {
		return nil, fmt.Errorf("canonicalizing signature base data: %w", err)
	}

	return out, nil
}

func hashData(docData, proofData []byte, h hash.Hash) []byte {
	h.Write(docData)
	docHash := h.Sum(nil)

	h.Reset()
	h.Write(proofData)
	proofHash := h.Sum(nil)

	return append(proofHash, docHash...)
}

func proofConfig(docCtx interface{}, opts *models.ProofOptions) map[string]interface{} {
	suiteType := SuiteType
	if opts.SuiteType != "" {
		suiteType = opts.SuiteType
	}

	proof := map[string]interface{}{
		ldCtxKey:             docCtx,
		"type":               models.DataIntegrityProof,
		"cryptosuite":        suiteType,
		"verificationMethod": opts.VerificationMethodID,
		"proofPurpose":       opts.Purpose,
	}

	if !opts.Created.IsZero() {
		proof["created"] = opts.Created.Format(models.DateTimeFormat)
	}

	if !opts.Expires.IsZero() {
		proof["expires"] = opts.Expires.Format(models.DateTimeFormat)
	}

	if opts.Challenge != "" {
		proof["challenge"] = opts.Challenge
	}

	if opts.Domain != "" {
		proof["domain"] = opts.Domain
	}

	return proof
}

func sign(sigBase []byte, key *jwk.JWK, signerGetter SignerGetter) ([]byte, error) {
	signer, err := signerGetter(key)
	if err != nil {
		return nil, err
	}

	sig, err := signer.Sign(sigBase)
	if err != nil {
		return nil, err
	}

	return sig, nil
}
