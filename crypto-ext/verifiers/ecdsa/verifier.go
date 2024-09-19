/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdsa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"slices"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/trustbloc/kms-go/spi/kms"

	"github.com/trustbloc/vc-go/crypto-ext/pubkey"
)

const (
	p256KeySize      = 32
	p384KeySize      = 48
	p521KeySize      = 66
	secp256k1KeySize = 32
	ed25519KeySize   = 32
)

type ellipticCurve struct {
	curve   elliptic.Curve
	keySize int
	hash    crypto.Hash
}

// Verifier verifies elliptic curve signatures.
type Verifier struct {
	ec         ellipticCurve
	kmsKeyType []kms.KeyType
}

// SupportedKeyType checks if verifier supports given key.
func (sv *Verifier) SupportedKeyType(keyType kms.KeyType) bool {
	return slices.Contains(sv.kmsKeyType, keyType)
}

func (sv *Verifier) parseKey(pubKey *pubkey.PublicKey) (*ecdsa.PublicKey, error) {
	if !sv.SupportedKeyType(pubKey.Type) {
		return nil, fmt.Errorf("unsupported key type %s", pubKey.Type)
	}

	var ecdsaPubKey *ecdsa.PublicKey

	if pubKey.JWK == nil {
		var err error

		ecdsaPubKey, err = sv.createECDSAPublicKey(pubKey.BytesKey.Bytes)
		if err != nil {
			return nil, fmt.Errorf("ecdsa: create JWK from public key bytes: %w", err)
		}
	} else {
		var ok bool
		ecdsaPubKey, ok = pubKey.JWK.Key.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("ecdsa: invalid public key type")
		}
	}

	return ecdsaPubKey, nil
}

// Verify verifies the signature.
func (sv *Verifier) Verify(signature, msg []byte, pubKey *pubkey.PublicKey) error {
	ecdsaPubKey, err := sv.parseKey(pubKey)
	if err != nil {
		return err
	}

	ec := sv.ec

	if len(signature) < 2*ec.keySize {
		return errors.New("ecdsa: invalid signature size")
	}

	hasher := ec.hash.New()

	_, err = hasher.Write(msg)
	if err != nil {
		return errors.New("ecdsa: hash error")
	}

	hash := hasher.Sum(nil)

	r := big.NewInt(0).SetBytes(signature[:ec.keySize])
	s := big.NewInt(0).SetBytes(signature[ec.keySize:])

	// TODO: Asn.1 DER signatures can on occasion be the same length as a P1363 signature
	//  I'm uncertain whether a P1363 signature can be generated which has bytes in
	//  the right places to appear as if it's an ASN.1 signature, but we could always
	//  try verification both ways. Whether there exists a P1363 signature that can
	//  be parsed as Asn.1 DER and validated against a different key is uncertain.
	//  Ideally, we enforce the use of either one or the other somehow, perhaps when
	//  initialising the application.
	if len(signature) > 2*ec.keySize {
		var esig struct {
			R, S *big.Int
		}

		if _, err := asn1.Unmarshal(signature, &esig); err != nil {
			return err
		}

		r = esig.R
		s = esig.S
	}

	verified := ecdsa.Verify(ecdsaPubKey, hash, r, s)
	if !verified {
		return errors.New("ecdsa: invalid signature")
	}

	return nil
}

func (sv *Verifier) createECDSAPublicKey(pubKeyBytes []byte) (*ecdsa.PublicKey, error) {
	curve := sv.ec.curve

	x, y := elliptic.Unmarshal(curve, pubKeyBytes)
	if x == nil {
		return nil, errors.New("invalid public key bytes")
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

// NewSecp256k1 creates a new signature verifier that verifies a ECDSA secp256k1 signature
// taking public key bytes and JSON Web Key as input.
func NewSecp256k1() *Verifier {
	return &Verifier{
		ec: ellipticCurve{
			curve:   btcec.S256(),
			keySize: secp256k1KeySize,
			hash:    crypto.SHA256,
		},
		kmsKeyType: []kms.KeyType{kms.ECDSASecp256k1TypeIEEEP1363, kms.ECDSASecp256k1TypeDER},
	}
}

// NewES256 creates a new signature verifier that verifies a ECDSA P-256 signature
// taking public key bytes and JSON Web Key as input.
func NewES256() *Verifier {
	return &Verifier{
		ec: ellipticCurve{
			curve:   elliptic.P256(),
			keySize: p256KeySize,
			hash:    crypto.SHA256,
		},
		kmsKeyType: []kms.KeyType{kms.ECDSAP256TypeIEEEP1363, kms.ECDSAP256TypeDER},
	}
}

// NewES384 creates a new signature verifier that verifies a ECDSA P-384 signature
// taking public key bytes and JSON Web Key as input.
func NewES384() *Verifier {
	return &Verifier{
		ec: ellipticCurve{
			curve:   elliptic.P384(),
			keySize: p384KeySize,
			hash:    crypto.SHA384,
		},
		kmsKeyType: []kms.KeyType{kms.ECDSAP384TypeIEEEP1363, kms.ECDSAP384TypeDER},
	}
}

// NewES521 creates a new signature verifier that verifies a ECDSA P-521 signature
// taking public key bytes and JSON Web Key as input.
func NewES521() *Verifier {
	return &Verifier{
		ec: ellipticCurve{
			curve:   elliptic.P521(),
			keySize: p521KeySize,
			hash:    crypto.SHA512,
		},
		kmsKeyType: []kms.KeyType{kms.ECDSAP521TypeIEEEP1363, kms.ECDSAP521TypeDER},
	}
}
