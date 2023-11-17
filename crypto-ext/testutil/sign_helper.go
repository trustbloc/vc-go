/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/trustbloc/kms-go/doc/jose/jwk/jwksupport"
	"github.com/trustbloc/kms-go/spi/kms"
	wrapperapi "github.com/trustbloc/kms-go/wrapper/api"

	"github.com/trustbloc/vc-go/crypto-ext/pubkey"
	"github.com/trustbloc/vc-go/internal/testutil/kmscryptoutil"
)

// CreateRSARS256 created signer and corresponding public key.
func CreateRSARS256() (*RS256Signer, *pubkey.PublicKey, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	pubKey := &privKey.PublicKey
	signer := NewRS256Signer(privKey)

	pub := &pubkey.PublicKey{
		Type:     kms.RSARS256Type,
		BytesKey: &pubkey.BytesKey{Bytes: x509.MarshalPKCS1PublicKey(pubKey)},
	}

	return signer, pub, nil
}

// CreateRSAPS256 created signer and corresponding public key.
func CreateRSAPS256() (*PS256Signer, *pubkey.PublicKey, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	pubKey := &privKey.PublicKey
	signer := NewPS256Signer(privKey)

	pub := &pubkey.PublicKey{
		Type:     kms.RSAPS256Type,
		BytesKey: &pubkey.BytesKey{Bytes: x509.MarshalPKCS1PublicKey(pubKey)},
	}

	return signer, pub, nil
}

// CreateEDSASecp256k1 created signer and corresponding public key.
func CreateEDSASecp256k1(jwkVM bool) (*ECDSASigner, *pubkey.PublicKey, error) {
	privKey, err := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	pubKey := &privKey.PublicKey
	signer := NewECDSASecp256k1Signer(privKey)

	pub := &pubkey.PublicKey{
		Type:     kms.ECDSASecp256k1TypeIEEEP1363,
		BytesKey: &pubkey.BytesKey{Bytes: elliptic.Marshal(pubKey.Curve, pubKey.X, pubKey.Y)},
	}

	if jwkVM {
		pubJWK, err := jwksupport.JWKFromKey(pubKey)
		if err != nil {
			return nil, nil, err
		}

		pub = &pubkey.PublicKey{
			Type: kms.ECDSASecp256k1TypeIEEEP1363,
			JWK:  pubJWK,
		}
	}

	return signer, pub, nil
}

// CreateKMSSigner created signer and corresponding public key.
func CreateKMSSigner(keyType kms.KeyType, jwkVM bool) (wrapperapi.FixedKeyCrypto, *pubkey.PublicKey, error) {
	kmsCrypto, err := kmscryptoutil.LocalKMSCryptoErr()
	if err != nil {
		return nil, nil, err
	}

	pubJWK, err := kmsCrypto.Create(keyType)
	if err != nil {
		return nil, nil, err
	}

	fkc, err := kmsCrypto.FixedKeyCrypto(pubJWK)
	if err != nil {
		return nil, nil, err
	}

	vm := &pubkey.PublicKey{
		Type: keyType,
		JWK:  pubJWK,
	}

	if !jwkVM {
		pubKeyBytes, err := pubJWK.PublicKeyBytes()
		vm = &pubkey.PublicKey{
			Type:     keyType,
			BytesKey: &pubkey.BytesKey{Bytes: pubKeyBytes},
		}

		if err != nil {
			return nil, nil, err
		}
	}

	return fkc, vm, nil
}
