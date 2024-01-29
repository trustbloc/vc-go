/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cwt

//go:generate mockgen -destination interfaces_mocks_test.go -package cwt_test -source=interfaces.go
import (
	"github.com/veraison/go-cose"

	"github.com/trustbloc/vc-go/proof/checker"
)

// ProofChecker used to check proof of jwt vc.
type ProofChecker interface {
	CheckCWTProof(
		checkCWTRequest checker.CheckCWTProofRequest,
		msg *cose.Sign1Message,
		expectedProofIssuer string,
	) error
}
