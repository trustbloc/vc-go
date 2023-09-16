/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package ed25519signature2018

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/vc-go/internal/testutil/kmscryptoutil"
	"github.com/trustbloc/vc-go/signature/kmscrypto"

	kmsapi "github.com/trustbloc/kms-go/spi/kms"

	"github.com/trustbloc/vc-go/signature/suite"
	sigverifier "github.com/trustbloc/vc-go/signature/verifier"
)

func TestNewCryptoSignerAndVerifier(t *testing.T) {
	kc := kmscryptoutil.LocalKMSCrypto(t)

	pk, err := kc.Create(kmsapi.ED25519Type)
	require.NoError(t, err)

	fks, err := kc.FixedKeySigner(pk)
	require.NoError(t, err)

	doc := []byte("test doc")

	suiteSigner := suite.NewCryptoWrapperSigner(fks)

	ss := New(suite.WithSigner(suiteSigner), suite.WithVerifier(kmscrypto.NewPublicKeyVerifier(kc)))

	docSig, err := ss.Sign(doc)
	if err != nil {
		panic("failed to create a signature")
	}

	pubKey := &sigverifier.PublicKey{
		Type: "JsonWebKey2020",
		JWK:  pk,
	}

	err = ss.Verify(pubKey, doc, docSig)
	if err != nil {
		panic("failed to verify signature")
	}
}
