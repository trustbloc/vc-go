/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/trustbloc/bbs-signature-go/bbs12381g2pub"
	"github.com/trustbloc/did-go/doc/ld/proof"
	"github.com/trustbloc/kms-go/spi/kms"

	"github.com/trustbloc/vc-go/crypto-ext/pubkey"
)

// G2SignatureVerifier is a signature verifier that verifies a BBS+ Signature
// taking Bls12381G2Key2020 public key bytes as input.
// The reference implementation https://github.com/mattrglobal/bls12381-key-pair supports public key bytes only,
// JWK is not supported.
type G2SignatureVerifier struct {
}

// NewBBSG2SignatureVerifier creates a new G2SignatureVerifier.
func NewBBSG2SignatureVerifier() *G2SignatureVerifier {
	return &G2SignatureVerifier{}
}

// SupportedKeyType checks if verifier supports given key.
func (sv *G2SignatureVerifier) SupportedKeyType(keyType kms.KeyType) bool {
	return keyType == kms.BLS12381G2Type
}

// Verify verifies the signature.
func (sv *G2SignatureVerifier) Verify(signature, msg []byte, pubKeyValue *pubkey.PublicKey) error {
	if !sv.SupportedKeyType(pubKeyValue.Type) {
		return fmt.Errorf("unsupported key type %s", pubKeyValue.Type)
	}

	bbs := bbs12381g2pub.New()

	bytesKey := pubKeyValue.BytesKey
	if bytesKey == nil && pubKeyValue.JWK != nil {
		bbsKey, err := pubKeyValue.JWK.PublicKeyBytes()
		if err != nil {
			return fmt.Errorf("invalid jwk: %w", err)
		}

		bytesKey = &pubkey.BytesKey{Bytes: bbsKey}
	}

	if bytesKey == nil {
		return fmt.Errorf("incorrect pub key, should contain key bytes or jwk")
	}

	return bbs.Verify(splitMessageIntoLines(string(msg), false), signature, bytesKey.Bytes)
}

// NewBBSG2SignatureProofVerifier creates a new BBSG2SignatureProofVerifier.
func NewBBSG2SignatureProofVerifier() *G2SignatureProofVerifier {
	return &G2SignatureProofVerifier{}
}

// G2SignatureProofVerifier is a signature verifier that verifies a BBS+ Signature Proof
// taking Bls12381G2Key2020 public key bytes as input.
// The reference implementation https://github.com/mattrglobal/bls12381-key-pair supports public key bytes only,
// JWK is not supported.
type G2SignatureProofVerifier struct {
}

// Verify verifies the signature.
func (v *G2SignatureProofVerifier) Verify(signature, msg []byte, pubKeyValue *pubkey.PublicKey,
	proof *proof.Proof) error {
	bbs := bbs12381g2pub.New()

	bytesKey := pubKeyValue.BytesKey

	if bytesKey == nil && pubKeyValue.JWK != nil {
		bbsKey, err := pubKeyValue.JWK.PublicKeyBytes()
		if err != nil {
			return fmt.Errorf("invalid jwk: %w", err)
		}

		bytesKey = &pubkey.BytesKey{Bytes: bbsKey}
	}

	if bytesKey == nil {
		return fmt.Errorf("incorrect pub key, should contain key bytes or jwk")
	}

	return bbs.VerifyProof(splitMessageIntoLines(string(msg), true),
		bytes.Clone(signature), proof.Nonce, bytesKey.Bytes)
}

func splitMessageIntoLines(msg string, transformBlankNodes bool) [][]byte {
	rows := strings.Split(msg, "\n")

	msgs := make([][]byte, 0, len(rows))

	for _, row := range rows {
		if strings.TrimSpace(row) == "" {
			continue
		}

		if transformBlankNodes {
			row = transformFromBlankNode(row)
		}

		msgs = append(msgs, []byte(row))
	}

	return msgs
}

func transformFromBlankNode(row string) string {
	// transform from "urn:bnid:_:c14n0" to "_:c14n0"
	const (
		emptyNodePlaceholder = "<urn:bnid:_:c14n"
		emptyNodePrefixLen   = 10
	)

	prefixIndex := strings.Index(row, emptyNodePlaceholder)
	if prefixIndex < 0 {
		return row
	}

	sepIndex := strings.Index(row[prefixIndex:], ">")
	if sepIndex < 0 {
		return row
	}

	sepIndex += prefixIndex

	prefix := row[:prefixIndex]
	blankNode := row[prefixIndex+emptyNodePrefixLen : sepIndex]
	suffix := row[sepIndex+1:]

	return fmt.Sprintf("%s%s%s", prefix, blankNode, suffix)
}
