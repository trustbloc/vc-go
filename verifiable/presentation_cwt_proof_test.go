/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/kms-go/spi/kms"
	"github.com/veraison/go-cose"

	"github.com/trustbloc/vc-go/proof/testsupport"
)

func TestParsePresentationFromCWS_EdDSA(t *testing.T) {
	vpBytes := []byte(validPresentation)

	vp, err := newTestPresentation(t, vpBytes, WithPresDisabledProofCheck())
	require.NoError(t, err)

	holderKeyID := vp.Holder + "#keys-" + keyID

	proofCreator, proofChecher := testsupport.NewKMSSigVerPair(t, kms.ED25519Type,
		holderKeyID)

	// marshal presentation into JWS using EdDSA (Ed25519 signature algorithm).
	cwtClaims, err := vp.CWTClaims([]string{}, false)
	require.NoError(t, err)

	cwtBytes, msg, err := cwtClaims.MarshalCWT(cose.AlgorithmEdDSA, proofCreator, holderKeyID)
	require.NoError(t, err)
	assert.NotNil(t, msg)

	hexStr := hex.EncodeToString(cwtBytes)
	fmt.Println(hexStr)
	// unmarshal presentation from JWS
	vpFromJWS, err := newTestPresentation(t,
		cwtBytes,
		WithPresProofChecker(proofChecher))
	require.NoError(t, err)

	require.Equal(t, cwtBytes, vpFromJWS.CWT.Raw)

	marshaled, err := vpFromJWS.MarshalCBOR()
	require.NoError(t, err)

	vpFromJWS2, err2 := newTestPresentation(t,
		marshaled,
		WithPresProofChecker(proofChecher))
	require.NoError(t, err2)

	// unmarshalled presentation must be the same as original one
	require.Equal(t, vpFromJWS, vpFromJWS2)
}
