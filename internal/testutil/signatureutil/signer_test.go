/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signatureutil

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
	kmsapi "github.com/trustbloc/kms-go/spi/kms"

	"github.com/trustbloc/vc-go/internal/testutil/kmscryptoutil"
	"github.com/trustbloc/vc-go/internal/testutil/signatureutil/internal/signer"
)

func TestNewCryptoSigner(t *testing.T) {
	for _, keyType := range [...]kmsapi.KeyType{
		kmsapi.ECDSAP256TypeDER, kmsapi.ECDSAP384TypeDER, kmsapi.ECDSAP521TypeDER,
		kmsapi.ECDSAP256TypeIEEEP1363, kmsapi.ECDSAP521TypeIEEEP1363, kmsapi.ED25519Type,
		kmsapi.ECDSAP384TypeIEEEP1363, kmsapi.ECDSASecp256k1TypeIEEEP1363, kmsapi.RSARS256Type, kmsapi.RSAPS256Type,
	} {
		newSigner := CryptoSigner(t, keyType)

		msgSig, signerErr := newSigner.Sign([]byte("test message"))
		require.NoError(t, signerErr)
		require.NotEmpty(t, msgSig)
	}

	newSigner, err := NewCryptoSigner(kmscryptoutil.LocalKMSCrypto(t), kmsapi.ChaCha20Poly1305Type)
	require.Error(t, err)
	require.EqualError(t, err, "unsupported key type")
	require.Nil(t, newSigner)
}

func TestGetEd25519Signer(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	ed25519Signer := GetEd25519Signer(privKey, pubKey)
	require.NotNil(t, ed25519Signer)
	require.IsType(t, &signer.Ed25519Signer{}, ed25519Signer)
}
