/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rsa_test

import (
	"testing"

	gojose "github.com/go-jose/go-jose/v3"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/kms-go/doc/jose/jwk"
	kmsapi "github.com/trustbloc/kms-go/spi/kms"

	"github.com/trustbloc/vc-go/crypto-ext/pubkey"
	"github.com/trustbloc/vc-go/crypto-ext/testutil"
	"github.com/trustbloc/vc-go/crypto-ext/verifiers/rsa"
)

func TestNewRSARS256SignatureVerifier(t *testing.T) {
	v := rsa.NewRS256()
	require.NotNil(t, v)

	signer, pubKey, err := testutil.CreateRSARS256()
	require.NoError(t, err)

	msg := []byte("test message")
	msgSig, err := signer.Sign(msg)
	require.NoError(t, err)

	err = v.Verify(msgSig, msg, pubKey)
	require.NoError(t, err)

	// invalid public key type
	err = v.Verify(msgSig, msg, &pubkey.PublicKey{
		Type:     kmsapi.RSARS256,
		BytesKey: &pubkey.BytesKey{Bytes: []byte("invalid-key")},
	})
	require.Error(t, err)
	require.EqualError(t, err, "rsa: invalid public key")

	// invalid public key type2
	err = v.Verify(msgSig, msg, &pubkey.PublicKey{
		Type: kmsapi.RSARS256,
	})
	require.Error(t, err)
	require.EqualError(t, err, "rsa: invalid public key")

	// unsupported key type
	err = v.Verify(msgSig, msg, &pubkey.PublicKey{
		Type:     kmsapi.AES256GCM,
		BytesKey: &pubkey.BytesKey{Bytes: []byte("invalid-key")},
	})
	require.Error(t, err)
	require.EqualError(t, err, "unsupported key type AES256GCM")

	// invalid JWK value
	err = v.Verify(msgSig, msg, &pubkey.PublicKey{
		Type: kmsapi.RSARS256,
		JWK: &jwk.JWK{
			JSONWebKey: gojose.JSONWebKey{
				Key: "foo",
			},
			Kty: "RSA",
		},
	})
	require.Error(t, err)
	require.EqualError(t, err, "jwk public key not rsa.PublicKey")

	// invalid signature
	err = v.Verify([]byte("invalid signature"), msg, pubKey)
	require.Error(t, err)
	require.EqualError(t, err, "crypto/rsa: verification error")
}

func TestNewRSAPS256SignatureVerifier(t *testing.T) {
	v := rsa.NewPS256()
	require.NotNil(t, v)

	signer, pubKey, err := testutil.CreateRSAPS256()
	require.NoError(t, err)

	msg := []byte("test message")
	msgSig, err := signer.Sign(msg)
	require.NoError(t, err)

	err = v.Verify(msgSig, msg, pubKey)
	require.NoError(t, err)

	// invalid public key type
	err = v.Verify(msgSig, msg, &pubkey.PublicKey{
		Type:     kmsapi.RSAPS256,
		BytesKey: &pubkey.BytesKey{Bytes: []byte("invalid-key")},
	})
	require.Error(t, err)
	require.EqualError(t, err, "rsa: invalid public key")

	// invalid public key type2
	err = v.Verify(msgSig, msg, &pubkey.PublicKey{
		Type: kmsapi.RSAPS256,
	})
	require.Error(t, err)
	require.EqualError(t, err, "rsa: invalid public key")

	// unsupported key type
	err = v.Verify(msgSig, msg, &pubkey.PublicKey{
		Type:     kmsapi.AES256GCM,
		BytesKey: &pubkey.BytesKey{Bytes: []byte("invalid-key")},
	})
	require.Error(t, err)
	require.EqualError(t, err, "unsupported key type AES256GCM")

	// invalid JWK value
	err = v.Verify(msgSig, msg, &pubkey.PublicKey{
		Type: kmsapi.RSAPS256,
		JWK: &jwk.JWK{
			JSONWebKey: gojose.JSONWebKey{
				Key: "foo",
			},
			Kty: "RSA",
		},
	})
	require.Error(t, err)
	require.EqualError(t, err, "jwk public key not rsa.PublicKey")

	// invalid signature
	err = v.Verify([]byte("invalid signature"), msg, pubKey)
	require.Error(t, err)
	require.EqualError(t, err, "crypto/rsa: verification error")
}
