/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rsa

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/trustbloc/kms-go/spi/kms"

	"github.com/trustbloc/vc-go/crypto-ext/pubkey"
)

// PS256Verifier verifies a rsa signature taking RSA public key bytes as input.
type PS256Verifier struct{}

// NewPS256 creates a new PS256Verifier.
func NewPS256() *PS256Verifier {
	return &PS256Verifier{}
}

// SupportedKeyType checks if verifier supports given key.
func (sv *PS256Verifier) SupportedKeyType(keyType kms.KeyType) bool {
	return keyType == kms.RSAPS256Type
}

// Verify verifies the signature.
func (sv *PS256Verifier) Verify(signature, msg []byte, key *pubkey.PublicKey) error {
	if !sv.SupportedKeyType(key.Type) {
		return fmt.Errorf("unsupported key type %s", key.Type)
	}

	var (
		pubKeyRsa *rsa.PublicKey
		err       error
	)

	if key.JWK != nil {
		var ok bool
		pubKeyRsa, ok = key.JWK.Public().Key.(*rsa.PublicKey)

		if !ok {
			return fmt.Errorf("jwk public key not rsa.PublicKey")
		}
	}

	if key.BytesKey != nil {
		pubKeyRsa, err = x509.ParsePKCS1PublicKey(key.BytesKey.Bytes)
		if err != nil {
			return errors.New("rsa: invalid public key")
		}
	}

	if pubKeyRsa == nil {
		return errors.New("rsa: invalid public key")
	}

	hash := crypto.SHA256
	hasher := hash.New()

	_, err = hasher.Write(msg)
	if err != nil {
		return errors.New("rsa: hash error")
	}

	hashed := hasher.Sum(nil)

	err = rsa.VerifyPSS(pubKeyRsa, hash, hashed, signature, nil)
	if err != nil {
		return errors.New("crypto/rsa: verification error")
	}

	return nil
}

// RS256Verifier verifies a rsa signature taking RSA public key bytes as input.
type RS256Verifier struct {
}

// NewRS256 creates a new RS256Verifier.
func NewRS256() *RS256Verifier {
	return &RS256Verifier{}
}

// SupportedKeyType checks if verifier supports given key.
func (sv *RS256Verifier) SupportedKeyType(keyType kms.KeyType) bool {
	return keyType == kms.RSARS256Type
}

// Verify verifies the signature.
func (sv *RS256Verifier) Verify(signature, msg []byte, key *pubkey.PublicKey) error {
	if !sv.SupportedKeyType(key.Type) {
		return fmt.Errorf("unsupported key type %s", key.Type)
	}

	var (
		pubKeyRsa *rsa.PublicKey
		err       error
	)

	if key.JWK != nil {
		var ok bool
		pubKeyRsa, ok = key.JWK.Public().Key.(*rsa.PublicKey)

		if !ok {
			return fmt.Errorf("jwk public key not rsa.PublicKey")
		}
	}

	if key.BytesKey != nil {
		pubKeyRsa, err = x509.ParsePKCS1PublicKey(key.BytesKey.Bytes)
		if err != nil {
			return errors.New("rsa: invalid public key")
		}
	}

	if pubKeyRsa == nil {
		return errors.New("rsa: invalid public key")
	}

	hash := crypto.SHA256.New()

	_, err = hash.Write(msg)
	if err != nil {
		return err
	}

	hashed := hash.Sum(nil)

	return rsa.VerifyPKCS1v15(pubKeyRsa, crypto.SHA256, hashed, signature)
}
