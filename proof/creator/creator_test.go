/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package creator_test

import (
	"testing"

	"github.com/trustbloc/vc-go/proof/testsupport/commontest"
)

func TestProofCreator_Common(t *testing.T) {
	t.Run("Test With all LD proofs", func(t *testing.T) {
		commontest.TestAllLDSignersVerifiers(t)
	})

	t.Run("Test With all jwt proofs", func(t *testing.T) {
		commontest.TestAllJWTSignersVerifiers(t)
	})

	t.Run("Test With all cwt proofs", func(t *testing.T) {
		commontest.TestAllCWTSignersVerifiers(t)
	})
}
