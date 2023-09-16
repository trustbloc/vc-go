/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jsonwebsignature2020

import (
	"crypto"
	"crypto/elliptic"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/stretchr/testify/require"
	kmsapi "github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/vc-go/internal/testutil/signatureutil"
	sigverifier "github.com/trustbloc/vc-go/signature/verifier"
)

func TestPublicKeyVerifier_Verify_EC(t *testing.T) {
	msg := []byte("test message")

	t.Run("happy path", func(t *testing.T) {
		tests := []struct {
			curve     elliptic.Curve
			curveName string
			algorithm string
			hash      crypto.Hash
		}{
			{
				curve:     elliptic.P256(),
				curveName: "P-256",
				algorithm: "ES256",
				hash:      crypto.SHA256,
			},
			{
				curve:     elliptic.P384(),
				curveName: "P-384",
				algorithm: "ES384",
				hash:      crypto.SHA384,
			},
			{
				curve:     elliptic.P521(),
				curveName: "P-521",
				algorithm: "ES521",
				hash:      crypto.SHA512,
			},
			{
				curve:     btcec.S256(),
				curveName: "secp256k1",
				algorithm: "ES256K",
				hash:      crypto.SHA256,
			},
		}

		t.Parallel()

		for _, test := range tests {
			tc := test
			t.Run(tc.curveName, func(t *testing.T) {
				keyType, err := signatureutil.MapECCurveToKeyType(tc.curve)
				require.NoError(t, err)

				signer := signatureutil.CryptoSigner(t, keyType)

				pubKey := &sigverifier.PublicKey{
					Type: "JsonWebKey2020",
					JWK:  signer.PublicJWK(),
				}

				msgSig, err := signer.Sign(msg)
				require.NoError(t, err)

				v := NewPublicKeyVerifier()
				err = v.Verify(pubKey, msg, msgSig)
				require.NoError(t, err)
			})
		}
	})
}

func TestPublicKeyVerifier_Verify_Ed25519(t *testing.T) {
	signer := signatureutil.CryptoSigner(t, kmsapi.ED25519Type)

	msg := []byte("test message")
	msgSig, err := signer.Sign(msg)
	require.NoError(t, err)

	pubKey := &sigverifier.PublicKey{
		Type: "JsonWebKey2020",
		JWK:  signer.PublicJWK(),
	}
	v := NewPublicKeyVerifier()

	err = v.Verify(pubKey, msg, msgSig)
	require.NoError(t, err)
}

func TestPublicKeyVerifier_Verify_RSA(t *testing.T) {
	signer := signatureutil.CryptoSigner(t, kmsapi.RSAPS256Type)

	msg := []byte("test message")

	msgSig, err := signer.Sign(msg)
	require.NoError(t, err)

	pubKey := &sigverifier.PublicKey{
		Type: "JsonWebKey2020",
		JWK:  signer.PublicJWK(),
	}

	v := NewPublicKeyVerifier()

	err = v.Verify(pubKey, msg, msgSig)
	require.NoError(t, err)
}
