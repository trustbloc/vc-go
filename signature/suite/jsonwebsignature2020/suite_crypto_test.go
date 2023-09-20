/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package jsonwebsignature2020

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/vc-go/internal/testutil/kmscryptoutil"
	"github.com/trustbloc/vc-go/signature/kmscrypto"

	kmsapi "github.com/trustbloc/kms-go/spi/kms"

	sigverifier "github.com/trustbloc/vc-go/signature/verifier"

	"github.com/trustbloc/vc-go/signature/suite"
)

func TestNewCryptoSignerAndVerifier(t *testing.T) {
	kc := kmscryptoutil.LocalKMSCrypto(t)

	pk, err := kc.Create(kmsapi.ECDSAP256TypeIEEEP1363)
	require.NoError(t, err)

	fks, err := kc.FixedKeySigner(pk)
	require.NoError(t, err)

	doc := []byte("test doc")

	suiteSigner := suite.NewCryptoWrapperSigner(fks)
	suiteVerifier := kmscrypto.NewPublicKeyVerifier(kc)

	ss := New(suite.WithSigner(suiteSigner), suite.WithVerifier(suiteVerifier))

	docSig, err := ss.Sign(doc)
	require.NoError(t, err)

	pubKey := &sigverifier.PublicKey{
		Type: kmsapi.ECDSAP256IEEEP1363,
		JWK:  pk,
	}

	err = ss.Verify(pubKey, doc, docSig)
	require.NoError(t, err)
}
