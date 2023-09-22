/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package suite

import (
	"github.com/trustbloc/kms-go/spi/crypto"
	"github.com/trustbloc/kms-go/wrapper"

	"github.com/trustbloc/vc-go/signature/api"
	"github.com/trustbloc/vc-go/signature/kmscrypto"
)

// CryptoSigner defines signer based on crypto.
type CryptoSigner struct {
	cr  crypto.Crypto
	kh  interface{}
	fks wrapper.FixedKeySigner
}

// NewCryptoWrapperSigner creates a new CryptoSigner using a kmscrypto wrapper.
func NewCryptoWrapperSigner(keySigner wrapper.FixedKeySigner) *CryptoSigner {
	return &CryptoSigner{fks: keySigner}
}

// NewCryptoSigner creates a new CryptoSigner.
//
// Deprecated: use NewCryptoWrapperSigner instead.
func NewCryptoSigner(cr crypto.Crypto, kh interface{}) *CryptoSigner {
	return &CryptoSigner{
		cr: cr,
		kh: kh,
	}
}

// Sign will sign document and return signature.
func (s *CryptoSigner) Sign(msg []byte) ([]byte, error) {
	if s.fks != nil {
		return s.fks.Sign(msg)
	}

	return s.cr.Sign(msg, s.kh)
}

// Alg return alg.
func (s *CryptoSigner) Alg() string {
	return ""
}

// CryptoVerifier defines signature verifier based on crypto.
type CryptoVerifier struct {
	kc wrapper.KMSCryptoVerifier
}

// NewCryptoVerifier creates a new CryptoVerifier.
func NewCryptoVerifier(kmsCrypto wrapper.KMSCryptoVerifier) kmscrypto.PublicKeyVerifier {
	return &CryptoVerifier{
		kc: kmsCrypto,
	}
}

// Verify will verify a signature.
func (v *CryptoVerifier) Verify(kh *api.PublicKey, msg, signature []byte) error {
	return v.kc.Verify(signature, msg, kh.JWK)
}
