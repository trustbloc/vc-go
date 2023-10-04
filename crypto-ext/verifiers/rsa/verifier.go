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

func (sv *PS256Verifier) SupportedKeyType(keyType kms.KeyType) bool {
	return keyType == kms.RSAPS256Type
}

// Verify verifies the signature.
func (sv *PS256Verifier) Verify(signature, msg []byte, key *pubkey.PublicKey) error {
	if !sv.SupportedKeyType(key.Type) {
		return fmt.Errorf("unsupported key type %s", key.Type)
	}

	var (
		pubKey *rsa.PublicKey
		err    error
	)

	if key.JWK != nil {
		pubKey = key.JWK.Key.(*rsa.PublicKey) // nolint: errcheck
	} else {
		pubKey, err = x509.ParsePKCS1PublicKey(key.BytesKey.Bytes)
		if err != nil {
			return errors.New("rsa: invalid public key")
		}
	}

	hash := crypto.SHA256
	hasher := hash.New()

	_, err = hasher.Write(msg)
	if err != nil {
		return errors.New("rsa: hash error")
	}

	hashed := hasher.Sum(nil)

	err = rsa.VerifyPSS(pubKey, hash, hashed, signature, nil)
	if err != nil {
		return errors.New("rsa: invalid signature")
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
		pubKeyRsa = key.JWK.Public().Key.(*rsa.PublicKey) // nolint: errcheck
	} else {
		pubKeyRsa, err = x509.ParsePKCS1PublicKey(key.BytesKey.Bytes)
		if err != nil {
			return errors.New("rsa: invalid public key")
		}
	}

	hash := crypto.SHA256.New()

	_, err = hash.Write(msg)
	if err != nil {
		return err
	}

	hashed := hash.Sum(nil)

	return rsa.VerifyPKCS1v15(pubKeyRsa, crypto.SHA256, hashed, signature)
}
