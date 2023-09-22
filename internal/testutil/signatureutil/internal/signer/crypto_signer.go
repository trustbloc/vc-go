/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signer

import (
	"fmt"

	"github.com/trustbloc/kms-go/doc/jose/jwk"
	kmsapi "github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/kms-go/wrapper"
)

// CryptoSigner defines signer based on crypto.
type CryptoSigner struct {
	PubJWK      *jwk.JWK
	alg         string
	fixedCrypto wrapper.FixedKeyCrypto
}

// Sign will sign document and return signature.
func (s *CryptoSigner) Sign(msg []byte) ([]byte, error) {
	return s.fixedCrypto.Sign(msg)
}

// PublicJWK returns a JWK containing the public key.
func (s *CryptoSigner) PublicJWK() *jwk.JWK {
	return s.PubJWK
}

// Alg returns alg.
func (s *CryptoSigner) Alg() string {
	return s.alg
}

// NewCryptoSigner creates a new CryptoSigner.
func NewCryptoSigner(kmsCrypto wrapper.KMSCrypto, keyType kmsapi.KeyType, alg string) (*CryptoSigner, error) {
	pubJWK, err := kmsCrypto.Create(keyType)
	if err != nil {
		return nil, fmt.Errorf("create key: %w", err)
	}

	fkc, err := kmsCrypto.FixedKeyCrypto(pubJWK)
	if err != nil {
		return nil, err
	}

	return &CryptoSigner{
		fixedCrypto: fkc,
		PubJWK:      pubJWK,
		alg:         alg,
	}, nil
}
