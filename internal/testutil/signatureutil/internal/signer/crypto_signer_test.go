/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signer_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	kmsapi "github.com/trustbloc/kms-go/spi/kms"
	mockkmscrypto "github.com/trustbloc/vc-go/internal/mock/kmscrypto"
	"github.com/trustbloc/vc-go/internal/testutil/kmscryptoutil"
	. "github.com/trustbloc/vc-go/internal/testutil/signatureutil/internal/signer"
)

func TestNewCryptoSigner(t *testing.T) {
	kmsCrypto := kmscryptoutil.LocalKMSCrypto(t)
	// TODO note: kms-go jwk implementation encodes all ecdsa keys as P1363 -
	//  there's no way to indicate DER vs P1363 in a JWK so we need to pick a
	//  default, and our implementation defaults to P1363. This means, even if the
	//  KMS keypair is DER, and the tink signer encodes the signature in Asn.1 DER
	//  format, the tink verifier will be given a pub keyhandle in P1363 format, try
	//  to decode the signature in P1363 format, and fail to verify.
	//
	//  Note, this failure only happens when the kmsCrypto instance used for
	//  verification doesn't have access to the same keys as the kmsCrypto instance
	//  used for signing. If they share storage (or, eg, if it's the same instance).
	//  it can fetch the original public key, in Asn.1 DER format, and the tink
	//  verifier will correctly parse the Asn.1 DER signature.
	//
	//  Note, the ecdsa verifier in vc-go/signature/verifier will still successfully
	//  verify all signatures, since it handles both P1363 and Asn.1 DER signatures.

	tests := []struct {
		keyType      kmsapi.KeyType
		expectedType interface{}
		expectedAlg  string
	}{
		{kmsapi.ED25519Type, ed25519.PublicKey{}, Ed25519alg},
		{kmsapi.ECDSAP256TypeDER, &ecdsa.PublicKey{}, P256Alg},
		{kmsapi.ECDSAP384TypeDER, &ecdsa.PublicKey{}, P384Alg},
		{kmsapi.ECDSAP521TypeDER, &ecdsa.PublicKey{}, P521Alg},
		{kmsapi.ECDSAP256TypeIEEEP1363, &ecdsa.PublicKey{}, P256Alg},
		{kmsapi.ECDSAP384TypeIEEEP1363, &ecdsa.PublicKey{}, P384Alg},
		{kmsapi.ECDSAP521TypeIEEEP1363, &ecdsa.PublicKey{}, P521Alg},
	}

	for _, test := range tests {
		signer, err := NewCryptoSigner(kmsCrypto, test.keyType, test.expectedAlg)
		require.NoError(t, err)

		msg := []byte("test message")
		sigMsg, err := signer.Sign(msg)
		require.NoError(t, err)

		err = kmsCrypto.Verify(sigMsg, msg, signer.PubJWK)
		require.NoError(t, err)

		signerAlg := signer.Alg()
		require.Equal(t, test.expectedAlg, signerAlg)
	}

	t.Run("error corner cases", func(t *testing.T) {
		mockKC := &mockkmscrypto.MockKMSCrypto{
			CreateErr: errors.New("key creation error"),
		}
		signer, err := NewCryptoSigner(mockKC, kmsapi.ED25519Type, "")
		require.Error(t, err)
		require.ErrorIs(t, err, mockKC.CreateErr)
		require.Nil(t, signer)
	})
}
