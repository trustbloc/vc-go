/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ed25519

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/trustbloc/kms-go/spi/kms"

	"github.com/trustbloc/vc-go/crypto-ext/pubkey"
)

// Verifier verifies a Ed25519 signature taking Ed25519 public key bytes as input.
type Verifier struct {
}

// New creates a new ed25519 Verifier.
func New() *Verifier {
	return &Verifier{}
}

// SupportedKeyType checks if verifier supports given key.
func (sv *Verifier) SupportedKeyType(keyType kms.KeyType) bool {
	return keyType == kms.ED25519Type
}

// Verify verifies the signature.
func (sv *Verifier) Verify(signature, msg []byte, pubKey *pubkey.PublicKey) error {
	if !sv.SupportedKeyType(pubKey.Type) {
		return fmt.Errorf("unsupported key type %s", pubKey.Type)
	}

	var value []byte
	if pubKey.BytesKey != nil {
		value = pubKey.BytesKey.Bytes
	}

	if pubKey.JWK != nil {
		var ok bool
		value, ok = pubKey.JWK.Public().Key.(ed25519.PublicKey)

		if !ok {
			return fmt.Errorf("public key not ed25519.VerificationMethod")
		}
	}
	// ed25519 panics if key size is wrong
	if len(value) != ed25519.PublicKeySize {
		return errors.New("ed25519: invalid key")
	}

	verified := ed25519.Verify(value, msg, signature)
	if !verified {
		return errors.New("ed25519: invalid signature")
	}

	return nil
}
