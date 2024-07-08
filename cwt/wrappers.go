/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cwt

import (
	"github.com/veraison/go-cose"

	"github.com/trustbloc/vc-go/proof/checker"
)

// Verifier verifies CWT proof.
type Verifier struct {
	ProofChecker ProofChecker
}

// Verify verifies CWT proof.
func (v *Verifier) Verify(
	keyMaterial string,
	algo cose.Algorithm,
	msg []byte,
	sign []byte,
) error {
	return v.ProofChecker.CheckCWTProof(checker.CheckCWTProofRequest{
		KeyMaterial: keyMaterial,
		Algo:        algo,
	}, "", msg, sign)
}
