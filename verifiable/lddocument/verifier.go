/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package lddocument

import (
	"encoding/json"
	"fmt"

	"github.com/trustbloc/did-go/doc/ld/processor"
	"github.com/trustbloc/did-go/doc/ld/proof"
)

type ProofChecker interface {
	CheckLDProof(proof *proof.Proof, msg, signature []byte) error

	// GetLDPCanonicalDocument will return normalized/canonical version of the document
	GetLDPCanonicalDocument(proof *proof.Proof, doc map[string]interface{}, opts ...processor.Opts) ([]byte, error)

	// GetLDPDigest returns document digest
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
func (dv *DocumentVerifier) Verify(jsonLdDoc []byte, opts ...processor.Opts) error {
	var jsonLdObject map[string]interface{}

	err := json.Unmarshal(jsonLdDoc, &jsonLdObject)
	if err != nil {
		return fmt.Errorf("failed to unmarshal json ld document: %w", err)
	}

	return dv.VerifyObject(jsonLdObject, opts...)
}

// VerifyObject will verify document proofs for JSON LD object.
func (dv *DocumentVerifier) VerifyObject(jsonLdObject map[string]interface{}, opts ...processor.Opts) error {
	proofs, err := proof.GetProofs(jsonLdObject)
	if err != nil {
		return err
	}

	for _, p := range proofs {
		message, err := proof.CreateVerifyData(&signatureSuiteWrapper{
			wrapped: dv.proofChecker,
			proof:   p,
		}, jsonLdObject, p, opts...)
		if err != nil {
			return err
		}

		signature, err := getProofVerifyValue(p)
		if err != nil {
			return err
		}

		err = dv.proofChecker.CheckLDProof(p, message, signature)
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

// TODO: remove this after refactoring did-go
type signatureSuiteWrapper struct {
	wrapped      signatureSuiteCompatible
	proof        *proof.Proof
	compactProof bool
}

// GetCanonicalDocument will return normalized/canonical version of the document
func (w *signatureSuiteWrapper) GetCanonicalDocument(doc map[string]interface{},
	opts ...processor.Opts) ([]byte, error) {
	return w.wrapped.GetLDPCanonicalDocument(w.proof, doc, opts...)
}

// GetDigest returns document digest
func (w *signatureSuiteWrapper) GetDigest(doc []byte) []byte {
	// error will handled after did-go refactoring
	digest, _ := w.wrapped.GetLDPDigest(w.proof, doc)
	return digest
}

// CompactProof indicates weather to compact the proof doc before canonization
func (w *signatureSuiteWrapper) CompactProof() bool {
	return w.compactProof
}
