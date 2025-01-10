/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdsa2019

import (
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"reflect"

	"github.com/multiformats/go-multibase"
	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/did-go/doc/ld/processor"
	"github.com/trustbloc/kms-go/doc/jose/jwk"
	"github.com/trustbloc/kms-go/spi/kms"
	wrapperapi "github.com/trustbloc/kms-go/wrapper/api"

	"github.com/trustbloc/vc-go/crypto-ext/pubkey"
	"github.com/trustbloc/vc-go/crypto-ext/verifiers/ecdsa"
	"github.com/trustbloc/vc-go/dataintegrity/models"
	"github.com/trustbloc/vc-go/dataintegrity/suite"
)

const (
	// SuiteType "ecdsa-2019" is the data integrity Type identifier for the suite
	// implementing ecdsa signatures with RDF canonicalization as per this
	// spec:https://www.w3.org/TR/vc-di-ecdsa/#ecdsa-2019
	SuiteType = "ecdsa-2019"

	// SuiteTypeNew "ecdsa-rdfc-2019" is the data integrity Type identifier for the suite.
	SuiteTypeNew = "ecdsa-rdfc-2019"
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

// Suite implements the ecdsa-2019 data integrity cryptographic suite.
type Suite struct {
	ldLoader     ld.DocumentLoader
	p256Verifier Verifier
	p384Verifier Verifier
	signerGetter SignerGetter
}

// Options provides initialization options for Suite.
type Options struct {
	LDDocumentLoader ld.DocumentLoader
	P256Verifier     Verifier
	P384Verifier     Verifier
	SignerGetter     SignerGetter
}

// SuiteInitializer is the initializer for Suite.
type SuiteInitializer func() (suite.Suite, error)

// New constructs an initializer for Suite.
func New(options *Options) SuiteInitializer {
	return func() (suite.Suite, error) {
		return &Suite{
			ldLoader:     options.LDDocumentLoader,
			p256Verifier: options.P256Verifier,
			p384Verifier: options.P384Verifier,
			signerGetter: options.SignerGetter,
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
	return []string{SuiteType, SuiteTypeNew}
}

// SignerInitializerOptions provides options for a SignerInitializer.
type SignerInitializerOptions struct {
	LDDocumentLoader ld.DocumentLoader
	SignerGetter     SignerGetter
}

// NewSignerInitializer returns a suite.SignerInitializer that initializes an ecdsa-2019
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
	P256Verifier     Verifier          // optional
	P384Verifier     Verifier          // optional
}

// NewVerifierInitializer returns a suite.VerifierInitializer that initializes an
// ecdsa-2019 verification Suite with the given VerifierInitializerOptions.
func NewVerifierInitializer(options *VerifierInitializerOptions) suite.VerifierInitializer {
	p256Verifier, p384Verifier := options.P256Verifier, options.P384Verifier

	if p256Verifier == nil {
		p256Verifier = ecdsa.NewES256()
	}

	if p384Verifier == nil {
		p384Verifier = ecdsa.NewES384()
	}

	return initializer(New(&Options{
		LDDocumentLoader: options.LDDocumentLoader,
		P256Verifier:     p256Verifier,
		P384Verifier:     p384Verifier,
	}))
}

const (
	ldCtxKey = "@context"
)

// CreateProof implements the ecdsa-2019 cryptographic suite for Add Proof:
// https://www.w3.org/TR/vc-di-ecdsa/#add-proof-ecdsa-2019
func (s *Suite) CreateProof(doc []byte, opts *models.ProofOptions) (*models.Proof, error) {
	if opts.SuiteType == "" {
		opts.SuiteType = SuiteType
	}

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
		CryptoSuite:        opts.SuiteType,
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

func (s *Suite) unmarshalECKey(ecCRV elliptic.Curve, pubKey []byte) ([]byte, error) {
	xBig, yBig := elliptic.UnmarshalCompressed(ecCRV, pubKey)

	if xBig != nil && yBig != nil {
		pubKey = elliptic.Marshal(ecCRV, xBig, yBig)
	} else {
		pubKey = append([]byte{4}, pubKey...)
	}

	if pubKey == nil {
		return nil, errors.New("failed to unmarshal EC key")
	}

	return pubKey, nil
}

//nolint:funlen,gocyclo // Old function
func (s *Suite) transformAndHash(doc []byte, opts *models.ProofOptions) ([]byte, *pubkey.PublicKey, Verifier, error) {
	if opts.SuiteType == "" {
		opts.SuiteType = SuiteType
	}

	docData := make(map[string]interface{})

	err := json.Unmarshal(doc, &docData)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ecdsa-2019 suite expects JSON-LD payload: %w", err)
	}

	var (
		h        hash.Hash
		verifier Verifier
		mda      ld.MessageDigestAlgorithm
	)

	finalKey := &pubkey.PublicKey{Type: "", JWK: opts.VerificationMethod.JSONWebKey()}

	if finalKey.JWK == nil && len(opts.VerificationMethod.Value) > 2 {
		header := opts.VerificationMethod.Value[0:2]

		var curve elliptic.Curve

		// ref https://www.w3.org/TR/controller-document/#Multikey
		if reflect.DeepEqual([]byte{0x80, 0x24}, header) ||
			reflect.DeepEqual([]byte{0x12, 0x00}, header) {
			verifier = s.p256Verifier
			h = sha256.New()
			curve = elliptic.P256()
			mda = ld.MessageDigestAlgorithmSHA256
			finalKey.Type = kms.ECDSAP256TypeIEEEP1363
		} else if reflect.DeepEqual([]byte{0x81, 0x24}, header) ||
			reflect.DeepEqual([]byte{0x12, 0x01}, header) {
			verifier = s.p384Verifier
			h = sha512.New384()
			curve = elliptic.P384()
			mda = ld.MessageDigestAlgorithmSHA384
			finalKey.Type = kms.ECDSAP384TypeIEEEP1363
		}

		if curve == nil {
			return nil, nil, nil, fmt.Errorf(
				"unsupported ECDSA curve. Header %x. Length %v",
				header,
				len(opts.VerificationMethod.Value),
			)
		}

		pubKey, errEc := s.unmarshalECKey(curve, opts.VerificationMethod.Value[2:])
		if errEc != nil {
			return nil, nil, nil, errors.Join(fmt.Errorf(
				"failed to unmarshal EC key. Header %x. Length %v",
				header,
				len(opts.VerificationMethod.Value),
			), errEc)
		}

		finalKey.BytesKey = &pubkey.BytesKey{Bytes: pubKey}
	}

	if finalKey.JWK == nil && finalKey.BytesKey == nil {
		return nil, nil, nil, errors.New("verification method needs JWK")
	}

	if finalKey.JWK != nil {
		switch finalKey.JWK.Crv {
		case "P-256":
			h = sha256.New()
			verifier = s.p256Verifier
			mda = ld.MessageDigestAlgorithmSHA256
			finalKey.Type = kms.ECDSAP256TypeIEEEP1363
		case "P-384":
			h = sha512.New384()
			verifier = s.p384Verifier
			mda = ld.MessageDigestAlgorithmSHA384
			finalKey.Type = kms.ECDSAP384TypeIEEEP1363
		default:
			return nil, nil, nil, fmt.Errorf("unsupported ECDSA curve. %v", finalKey.JWK.Crv)
		}
	}

	confData := proofConfig(docData[ldCtxKey], opts)

	if opts.ProofType != models.DataIntegrityProof || (opts.SuiteType != SuiteType && opts.SuiteType != SuiteTypeNew) {
		return nil, nil, nil, suite.ErrProofTransformation
	}

	canonDoc, err := canonicalize(docData, s.ldLoader, mda)
	if err != nil {
		return nil, nil, nil, err
	}

	canonConf, err := canonicalize(confData, s.ldLoader, mda)
	if err != nil {
		return nil, nil, nil, err
	}

	docHash := hashData(canonDoc, canonConf, h)

	return docHash, finalKey, verifier, nil
}

// VerifyProof implements the ecdsa-2019 cryptographic suite for CheckJWTProof Proof:
// https://www.w3.org/TR/vc-di-ecdsa/#verify-proof-ecdsa-2019
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
		return fmt.Errorf("failed to verify ecdsa-2019 DI proof: %w", err)
	}

	return nil
}

// RequiresCreated returns false, as the ecdsa-2019 cryptographic suite does not
// require the use of the models.Proof.Created field.
func (s *Suite) RequiresCreated() bool {
	return false
}

func canonicalize(data map[string]interface{}, loader ld.DocumentLoader, mda ld.MessageDigestAlgorithm,
) ([]byte, error) {
	out, err := processor.Default().GetCanonicalDocument(
		data,
		processor.WithDocumentLoader(loader),
		processor.WithMessageDigestAlgorithm(mda),
	)
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
	proof := map[string]interface{}{
		ldCtxKey:             docCtx,
		"type":               models.DataIntegrityProof,
		"cryptosuite":        opts.SuiteType,
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
