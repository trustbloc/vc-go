/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package lddocument

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/trustbloc/did-go/doc/ld/processor"
	"github.com/trustbloc/did-go/doc/ld/proof"
)

// ProofChecker implements JSON LD document proof check.
type ProofChecker interface {
	// CheckLDProof check ld proof.
	CheckLDProof(proof *proof.Proof, expectedProofIssuer string, msg, signature []byte) error

	// GetLDPCanonicalDocument will return normalized/canonical version of the document.
	GetLDPCanonicalDocument(proof *proof.Proof, doc map[string]interface{}, opts ...processor.Opts) ([]byte, error)

	// GetLDPDigest returns document digest.
	GetLDPDigest(proof *proof.Proof, doc []byte) ([]byte, error)
}

// DocumentVerifier implements JSON LD document proof verification.
type DocumentVerifier struct {
	proofChecker ProofChecker
	compactProof bool
}

// NewDocumentVerifier returns new instance of document wrapped.
func NewDocumentVerifier(proofChecker ProofChecker) *DocumentVerifier {
	return &DocumentVerifier{proofChecker: proofChecker}
}

// Verify will verify document proofs.
func (dv *DocumentVerifier) Verify(jsonLdDoc []byte, expectedProofIssuer *string, opts ...processor.Opts) error {
	var jsonLdObject map[string]interface{}

	err := json.Unmarshal(jsonLdDoc, &jsonLdObject)
	if err != nil {
		return fmt.Errorf("failed to unmarshal json ld document: %w", err)
	}

	return dv.VerifyObject(jsonLdObject, expectedProofIssuer, opts...)
}

// VerifyObject will verify document proofs for JSON LD object.
func (dv *DocumentVerifier) VerifyObject(jsonLdObject map[string]interface{},
	expectedProofIssuerPtr *string, opts ...processor.Opts) error {
	proofs, err := proof.GetProofs(jsonLdObject)
	if err != nil {
		return err
	}

	for _, p := range proofs {
		message, err := proof.CreateVerifyData(&signatureSuiteWrapper{
			wrapped:      dv.proofChecker,
			proof:        p,
			compactProof: dv.compactProof,
		}, jsonLdObject, p, opts...)
		if err != nil {
			return err
		}

		signature, err := getProofVerifyValue(p)
		if err != nil {
			return err
		}

		var expectedProofIssuer string
		if expectedProofIssuerPtr != nil {
			expectedProofIssuer = *expectedProofIssuerPtr
		} else {
			// if expectedProofIssuerPtr not set, we get issuer DID from first part of key id.
			pubKeyID, err2 := p.PublicKeyID()
			if err2 != nil {
				return errors.New("public key is missed in proof")
			}

			expectedProofIssuer = strings.Split(pubKeyID, "#")[0]
		}

		err = dv.proofChecker.CheckLDProof(p, expectedProofIssuer, message, signature)
		if err != nil {
			return err
		}
	}

	return nil
}

func getProofVerifyValue(p *proof.Proof) ([]byte, error) {
	switch p.SignatureRepresentation {
	case proof.SignatureProofValue:
		return p.ProofValue, nil
	case proof.SignatureJWS:
		return proof.GetJWTSignature(p.JWS)
	}

	return nil, fmt.Errorf("unsupported signature representation: %v", p.SignatureRepresentation)
}

type signatureSuiteCompatible interface {
	GetLDPCanonicalDocument(proof *proof.Proof, doc map[string]interface{}, opts ...processor.Opts) ([]byte, error)
	GetLDPDigest(proof *proof.Proof, doc []byte) ([]byte, error)
}

// TODO: remove this after refactoring did-go.
type signatureSuiteWrapper struct {
	wrapped      signatureSuiteCompatible
	proof        *proof.Proof
	compactProof bool
}

// GetCanonicalDocument will return normalized/canonical version of the document.
func (w *signatureSuiteWrapper) GetCanonicalDocument(doc map[string]interface{},
	opts ...processor.Opts) ([]byte, error) {
	return w.wrapped.GetLDPCanonicalDocument(w.proof, doc, opts...)
}

// GetDigest returns document digest.
func (w *signatureSuiteWrapper) GetDigest(doc []byte) []byte {
	// error will handled after did-go refactoring
	digest, _ := w.wrapped.GetLDPDigest(w.proof, doc) //nolint: errcheck
	return digest
}

// CompactProof indicates weather to compact the proof doc before canonization.
func (w *signatureSuiteWrapper) CompactProof() bool {
	return w.compactProof
}
