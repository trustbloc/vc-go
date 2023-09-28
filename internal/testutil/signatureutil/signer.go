/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signatureutil

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	kmsapi "github.com/trustbloc/kms-go/spi/kms"
	wrapperapi "github.com/trustbloc/kms-go/wrapper/api"

	"github.com/trustbloc/vc-go/internal/testutil/kmscryptoutil"
	"github.com/trustbloc/vc-go/internal/testutil/signatureutil/internal/signer"
)

// TODO: neither NewCryptoSigner or NewSigner is used by wallet-sdk or vcs. This
//  API seems to be used only by vc-go tests? maybe we can substitute it for a
//  signer that *is* used elsewhere.

// CryptoSigner creates a Signer for use in tests.
func CryptoSigner(t *testing.T, keyType kmsapi.KeyType) Signer {
	cs, err := NewCryptoSigner(kmscryptoutil.LocalKMSCrypto(t), keyType)
	require.NoError(t, err)

	return cs
}

// NewCryptoSigner creates a new signer based on crypto if possible.
func NewCryptoSigner(kmsCrypto wrapperapi.KMSCrypto, keyType kmsapi.KeyType) (Signer, error) {
	var alg string

	// Note: signer.CryptoSigner doesn't support secp256k1 or rsa, as kms-go
	// jwk.PubKeyBytesToJWK doesn't support those key types.
	switch keyType {
	case kmsapi.ECDSAP256TypeDER, kmsapi.ECDSAP256TypeIEEEP1363:
		alg = signer.P256Alg
	case kmsapi.ECDSAP384TypeDER, kmsapi.ECDSAP384TypeIEEEP1363:
		alg = signer.P384Alg
	case kmsapi.ECDSAP521TypeDER, kmsapi.ECDSAP521TypeIEEEP1363:
		alg = signer.P521Alg
	case kmsapi.ED25519Type:
		alg = signer.Ed25519alg
	case kmsapi.ECDSASecp256k1DER, kmsapi.ECDSASecp256k1TypeIEEEP1363:
		// TODO use crypto signer when available (https://github.com/hyperledger/aries-framework-go/issues/1285)
		return signer.NewECDSASecp256k1Signer()

	case kmsapi.RSARS256Type:
		return signer.NewRS256Signer()

	case kmsapi.RSAPS256Type:
		return signer.NewPS256Signer()

	default:
		return nil, errors.New("unsupported key type")
	}

	return signer.NewCryptoSigner(kmsCrypto, keyType, alg)
}

// TODO: GetEd25519Signer is used in vc-go tests, and it's quite convenient. Move to internal/testutil

// GetEd25519Signer returns Ed25519 Signer with predefined private and public keys.
func GetEd25519Signer(privKey ed25519.PrivateKey, pubKey ed25519.PublicKey) Signer {
	return signer.GetEd25519Signer(privKey, pubKey)
}
