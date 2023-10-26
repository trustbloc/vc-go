/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwt

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/kms-go/doc/jose"
)

func TestJoseVerifier(t *testing.T) {
	testIssuer := "did:test:testIssuer"

	t.Run("expectedProofIssuer is defined", func(t *testing.T) {
		mock := &mockProofChecker{}
		verifier := &joseVerifier{proofChecker: mock, expectedProofIssuer: &testIssuer}

		err := verifier.Verify(jose.Headers{"kid": "did:test:keyIssuer#key-1"}, nil, nil, nil)
		require.NoError(t, err)
		require.Equal(t, testIssuer, mock.resultedExpectedProofIssuer)
	})

	t.Run("expectedProofIssuer should be derived from key id", func(t *testing.T) {
		mock := &mockProofChecker{}
		verifier := &joseVerifier{proofChecker: mock}

		err := verifier.Verify(jose.Headers{"kid": "did:test:keyIssuer#key-1"}, nil, nil, nil)
		require.NoError(t, err)
		require.Equal(t, "did:test:keyIssuer", mock.resultedExpectedProofIssuer)
	})

	t.Run("test missed key id", func(t *testing.T) {
		mock := &mockProofChecker{}
		verifier := &joseVerifier{proofChecker: mock}

		err := verifier.Verify(jose.Headers{}, nil, nil, nil)
		require.ErrorContains(t, err, "missed kid in jwt header")
	})
}

type mockProofChecker struct {
	resultedExpectedProofIssuer string
}

func (m *mockProofChecker) CheckJWTProof(headers jose.Headers,
	expectedProofIssuer string, msg, signature []byte) error {
	m.resultedExpectedProofIssuer = expectedProofIssuer
	return nil
}
