/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdsasecp256k1signature2019

import (
	"testing"

	"github.com/stretchr/testify/require"
	kmsapi "github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/vc-go/internal/testutil/signatureutil"

	"github.com/trustbloc/vc-go/signature/verifier"
)

func TestPublicKeyVerifier_Verify(t *testing.T) {
	signer := signatureutil.CryptoSigner(t, kmsapi.ECDSASecp256k1TypeIEEEP1363)

	msg := []byte("test message")

	msgSig, err := signer.Sign(msg)
	require.NoError(t, err)

	pubKey := &verifier.PublicKey{
		Type: "EcdsaSecp256k1VerificationKey2019",
		JWK:  signer.PublicJWK(),
	}

	v := NewPublicKeyVerifier()

	err = v.Verify(pubKey, msg, msgSig)
	require.NoError(t, err)

	pubKey = &verifier.PublicKey{
		Type: "EcdsaSecp256k1VerificationKey2019",
		JWK:  signer.PublicJWK(),
	}

	err = v.Verify(pubKey, msg, msgSig)
	require.NoError(t, err)
}
