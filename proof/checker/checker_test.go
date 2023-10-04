/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package checker_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/did-go/doc/ld/proof"
	"github.com/trustbloc/kms-go/doc/jose"

	"github.com/trustbloc/vc-go/proof/checker"
	"github.com/trustbloc/vc-go/proof/jwtproofs/eddsa"
	"github.com/trustbloc/vc-go/proof/ldproofs/ed25519signature2018"
	"github.com/trustbloc/vc-go/proof/testsupport"
	"github.com/trustbloc/vc-go/proof/testsupport/commontest"
	"github.com/trustbloc/vc-go/vermethod"
)

func TestProofChecker_AllLD(t *testing.T) {
	t.Run("Test With all LD proofs", func(t *testing.T) {
		commontest.TestAllLDSignersVerifiers(t)
	})

	t.Run("Test With all jwt proofs", func(t *testing.T) {
		commontest.TestAllJWTSignersVerifiers(t)
	})

	t.Run("Test With all jwt proofs", func(t *testing.T) {
		commontest.TestEmbeddedProofChecker(t)
	})
}

func TestProofChecker_CheckLDProof(t *testing.T) {
	testable := checker.New(
		testsupport.NewSingleKeyResolver("lookupId", []byte{}, "test"),
		checker.WithLDProofTypes(ed25519signature2018.New()))

	err := testable.CheckLDProof(&proof.Proof{}, nil, nil)
	require.ErrorContains(t, err, "roof missing public key id")

	err = testable.CheckLDProof(&proof.Proof{
		VerificationMethod: "invlaid",
	}, nil, nil)
	require.ErrorContains(t, err, "proof invalid public key id")

	err = testable.CheckLDProof(&proof.Proof{
		VerificationMethod: "lookupId",
	}, nil, nil)
	require.ErrorContains(t, err, "unsupported proof type")

	err = testable.CheckLDProof(&proof.Proof{
		VerificationMethod: "lookupId",
		Type:               "Ed25519Signature2018",
	}, nil, nil)
	require.ErrorContains(t, err, "can't verifiy with \"test\" verification method")
}

func TestProofChecker_CheckJWTProof(t *testing.T) {
	testable := checker.New(
		testsupport.NewSingleKeyResolver("lookupId", []byte{}, "test"),
		checker.WithJWTAlg(eddsa.New()))

	err := testable.CheckJWTProof(jose.Headers{jose.HeaderAlgorithm: "talg"}, nil, nil, nil)
	require.ErrorContains(t, err, "missed kid in jwt header")

	err = testable.CheckJWTProof(jose.Headers{jose.HeaderKeyID: "tid"}, nil, nil, nil)
	require.ErrorContains(t, err, "missed alg in jwt header")

	err = testable.CheckJWTProof(jose.Headers{
		jose.HeaderKeyID: "tid", jose.HeaderAlgorithm: "talg"}, nil, nil, nil)
	require.ErrorContains(t, err, "invalid public key id")

	err = testable.CheckJWTProof(jose.Headers{
		jose.HeaderKeyID: "lookupId", jose.HeaderAlgorithm: "talg"}, nil, nil, nil)
	require.ErrorContains(t, err, "unsupported jwt alg")

	err = testable.CheckJWTProof(jose.Headers{
		jose.HeaderKeyID: "lookupId", jose.HeaderAlgorithm: "EdDSA"}, nil, nil, nil)
	require.ErrorContains(t, err, "can't verifiy with \"test\" verification method")
}

func TestEmbeddedVMProofChecker_CheckJWTProof(t *testing.T) {
	testable := checker.NewEmbeddedVMProofChecker(
		&vermethod.VerificationMethod{Type: "test"},
		checker.WithJWTAlg(eddsa.New()))

	err := testable.CheckJWTProof(jose.Headers{}, nil, nil, nil)
	require.ErrorContains(t, err, "missed alg in jwt header")

	err = testable.CheckJWTProof(jose.Headers{jose.HeaderAlgorithm: "talg"}, nil, nil, nil)
	require.ErrorContains(t, err, "unsupported jwt alg")

	err = testable.CheckJWTProof(jose.Headers{jose.HeaderAlgorithm: "EdDSA"}, nil, nil, nil)
	require.ErrorContains(t, err, "can't verifiy with \"test\" verification method")
}
