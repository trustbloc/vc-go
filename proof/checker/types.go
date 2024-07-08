/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package checker

import "github.com/veraison/go-cose"

// CheckCWTProofRequest is the request for checking a CWT proof.
type CheckCWTProofRequest struct {
	KeyID       string
	KeyMaterial string // hex encoded key material
	Algo        cose.Algorithm
}
