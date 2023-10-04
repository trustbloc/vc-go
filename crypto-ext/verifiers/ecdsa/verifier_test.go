/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdsa_test

import (
	"testing"

	gojose "github.com/go-jose/go-jose/v3"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/kms-go/doc/jose/jwk"
	kmsapi "github.com/trustbloc/kms-go/spi/kms"

	"github.com/trustbloc/vc-go/crypto-ext/pubkey"
	"github.com/trustbloc/vc-go/crypto-ext/testutil"
	"github.com/trustbloc/vc-go/crypto-ext/verifiers/ecdsa"
)

func TestNewECDSAES256SignatureVerifier(t *testing.T) {
	msg := []byte("test message")

	t.Run("happy path", func(t *testing.T) {
		tests := []struct {
			sVerifier *ecdsa.Verifier
			algorithm string
			keyType   kmsapi.KeyType
		}{
			{
				sVerifier: ecdsa.NewES256(),
				keyType:   kmsapi.ECDSAP256TypeIEEEP1363,
				algorithm: "ES256",
			},
			{
				sVerifier: ecdsa.NewES384(),
				keyType:   kmsapi.ECDSAP384TypeIEEEP1363,
				algorithm: "ES384",
			},
			{
				sVerifier: ecdsa.NewES521(),
				keyType:   kmsapi.ECDSAP521TypeIEEEP1363,
				algorithm: "ES521",
			},
		}

		t.Parallel()

		for _, test := range tests {
			tc := test
			t.Run(tc.algorithm, func(t *testing.T) {
				signer, pubKey, err := testutil.CreateKMSSigner(test.keyType, true)
				require.NoError(t, err)

				msgSig, err := signer.Sign(msg)
				require.NoError(t, err)

				err = tc.sVerifier.Verify(msgSig, msg, pubKey)
				require.NoError(t, err)
			})
		}

		t.Run("ES256K", func(t *testing.T) {
			signer, pubKey, err := testutil.CreateEDSASecp256k1(true)
			require.NoError(t, err)

			msgSig, err := signer.Sign(msg)
			require.NoError(t, err)

			err = ecdsa.NewSecp256k1().Verify(msgSig, msg, pubKey)
			require.NoError(t, err)
		})
	})

	v := ecdsa.NewES256()
	require.NotNil(t, v)

	signer, pubKey, err := testutil.CreateKMSSigner(kmsapi.ECDSAP256TypeIEEEP1363, false)
	require.NoError(t, err)

	msgSig, err := signer.Sign(msg)
	require.NoError(t, err)

	t.Run("verify with public key bytes", func(t *testing.T) {
		verifyError := v.Verify(msgSig, msg, pubKey)

		require.NoError(t, verifyError)
	})

	t.Run("invalid public key", func(t *testing.T) {
		err = v.Verify(msgSig, msg, &pubkey.PublicKey{
			Type:     kmsapi.AES256GCM,
			BytesKey: &pubkey.BytesKey{Bytes: []byte("invalid-key")},
		})
		require.Error(t, err)
		require.EqualError(t, err, "unsupported key type AES256GCM")
	})

	t.Run("invalid public key bytes", func(t *testing.T) {
		err = v.Verify(msgSig, msg, &pubkey.PublicKey{
			Type:     kmsapi.ECDSAP256TypeIEEEP1363,
			BytesKey: &pubkey.BytesKey{Bytes: []byte("invalid-key")},
		})
		require.Error(t, err)
		require.ErrorContains(t, err, "invalid public key bytes")
	})

	t.Run("invalid public key type", func(t *testing.T) {
		err = v.Verify(msgSig, msg, &pubkey.PublicKey{
			Type: kmsapi.ECDSAP256TypeIEEEP1363,
			JWK: &jwk.JWK{
				JSONWebKey: gojose.JSONWebKey{
					Key: "foo",
				},
				Kty: "RSA",
			},
		})
		require.Error(t, err)
		require.EqualError(t, err, "ecdsa: invalid public key type")
	})

	t.Run("invalid signature", func(t *testing.T) {
		verifyError := v.Verify([]byte("signature of invalid size"), msg, pubKey)
		require.Error(t, verifyError)
		require.EqualError(t, verifyError, "ecdsa: invalid signature size")

		emptySig := make([]byte, 64)
		verifyError = v.Verify(emptySig, msg, pubKey)
		require.Error(t, verifyError)
		require.EqualError(t, verifyError, "ecdsa: invalid signature")
	})
}
