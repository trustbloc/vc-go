/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ed25519signature2020

import (
	"testing"

	"github.com/stretchr/testify/require"
	kmsapi "github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/vc-go/internal/testutil/signatureutil"

	"github.com/trustbloc/vc-go/signature/verifier"
)

func TestPublicKeyVerifier_Verify(t *testing.T) {
	signer := signatureutil.CryptoSigner(t, kmsapi.ED25519Type)

	msg := []byte("test message")

	msgSig, err := signer.Sign(msg)
	require.NoError(t, err)

	pubKey := &verifier.PublicKey{
		Type: kmsapi.ED25519,
		JWK:  signer.PublicJWK(),
		// Value: signer.PublicKeyBytes(),
	}
	v := NewPublicKeyVerifier()

	err = v.Verify(pubKey, msg, msgSig)
	require.NoError(t, err)
}
