/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ed25519_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/kms-go/doc/jose/jwk"
	kmsapi "github.com/trustbloc/kms-go/spi/kms"

	gojose "github.com/go-jose/go-jose/v3"

	"github.com/trustbloc/vc-go/crypto-ext/pubkey"
	"github.com/trustbloc/vc-go/crypto-ext/testutil"
	"github.com/trustbloc/vc-go/crypto-ext/verifiers/ed25519"
)

func TestNewEd25519SignatureVerifier(t *testing.T) {
	v := ed25519.New()
	require.NotNil(t, v)

	signer, pubKey, err := testutil.CreateKMSSigner(kmsapi.ED25519Type, true)
	require.NoError(t, err)

	msg := []byte("test message")
	msgSig, err := signer.Sign(msg)
	require.NoError(t, err)

	err = v.Verify(msgSig, msg, pubKey)
	require.NoError(t, err)

	// invalid public key type
	err = v.Verify(msgSig, msg, &pubkey.PublicKey{
		Type:     kmsapi.ED25519,
		BytesKey: &pubkey.BytesKey{Bytes: []byte("invalid-key")},
	})
	require.Error(t, err)
	require.EqualError(t, err, "ed25519: invalid key")

	// invalid public key type2
	err = v.Verify(msgSig, msg, &pubkey.PublicKey{
		Type: kmsapi.ED25519,
	})
	require.Error(t, err)
	require.EqualError(t, err, "ed25519: invalid key")

	// unsupported key type
	err = v.Verify(msgSig, msg, &pubkey.PublicKey{
		Type:     kmsapi.RSAPS256Type,
		BytesKey: &pubkey.BytesKey{Bytes: []byte("invalid-key")},
	})
	require.Error(t, err)
	require.EqualError(t, err, "unsupported key type RSAPS256")

	// invalid JWK value
	err = v.Verify(msgSig, msg, &pubkey.PublicKey{
		Type: kmsapi.ED25519,
		JWK: &jwk.JWK{
			JSONWebKey: gojose.JSONWebKey{
				Key: "foo",
			},
			Kty: "OKP",
			Crv: "Ed25519",
		},
	})
	require.Error(t, err)
	require.EqualError(t, err, "public key not ed25519.VerificationMethod")

	// invalid signature
	err = v.Verify([]byte("invalid signature"), msg, pubKey)
	require.Error(t, err)
	require.EqualError(t, err, "ed25519: invalid signature")
}
