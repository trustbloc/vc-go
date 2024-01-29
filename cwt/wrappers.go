/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cwt

import (
	"strings"

	"github.com/veraison/go-cose"

	"github.com/trustbloc/vc-go/proof/checker"
)

type Verifier struct {
	ProofChecker        ProofChecker
	expectedProofIssuer *string
}

func (v *Verifier) Verify(
	proof *cose.Sign1Message,
	keyID string,
	algo cose.Algorithm,
) error {
	var expectedProofIssuer string

	if v.expectedProofIssuer != nil {
		expectedProofIssuer = *v.expectedProofIssuer
	} else {
		// if expectedProofIssuer not set, we get issuer DID from first part of key id.
		expectedProofIssuer = strings.Split(keyID, "#")[0]
	}

	return v.ProofChecker.CheckCWTProof(checker.CheckCWTProofRequest{
		KeyID: keyID,
		Algo:  algo,
	}, proof, expectedProofIssuer)
}
