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

// Verifier verifies CWT proof.
type Verifier struct {
	ProofChecker        ProofChecker
	expectedProofIssuer *string
}

// Verify verifies CWT proof.
func (v *Verifier) Verify(
	keyID string,
	algo cose.Algorithm,
	msg []byte,
	sign []byte,
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
	}, expectedProofIssuer, msg, sign)
}
