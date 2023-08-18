/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ed25519signature2018

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/kms-crypto-go/crypto/tinkcrypto"
	"github.com/trustbloc/kms-crypto-go/kms/localkms"
	mockkms "github.com/trustbloc/kms-crypto-go/mock/kms"
	"github.com/trustbloc/kms-crypto-go/secretlock/noop"
	kmsapi "github.com/trustbloc/kms-crypto-go/spi/kms"

	"github.com/trustbloc/vc-go/legacy/mock/storage"
	signature "github.com/trustbloc/vc-go/signature/util"
	"github.com/trustbloc/vc-go/signature/verifier"
)

func TestPublicKeyVerifier_Verify(t *testing.T) {
	signer, err := newCryptoSigner(kmsapi.ED25519Type)
	require.NoError(t, err)

	msg := []byte("test message")

	msgSig, err := signer.Sign(msg)
	require.NoError(t, err)

	pubKey := &verifier.PublicKey{
		Type:  kmsapi.ED25519,
		Value: signer.PublicKeyBytes(),
	}
	v := NewPublicKeyVerifier()

	err = v.Verify(pubKey, msg, msgSig)
	require.NoError(t, err)
}

func newCryptoSigner(keyType kmsapi.KeyType) (signature.Signer, error) {
	p, err := mockkms.NewProviderForKMS(storage.NewMockStoreProvider(), &noop.NoLock{})
	if err != nil {
		return nil, err
	}

	localKMS, err := localkms.New("local-lock://custom/master/key/", p)
	if err != nil {
		return nil, err
	}

	tinkCrypto, err := tinkcrypto.New()
	if err != nil {
		return nil, err
	}

	return signature.NewCryptoSigner(tinkCrypto, localKMS, keyType)
}
