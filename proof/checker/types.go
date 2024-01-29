/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package checker

import "github.com/veraison/go-cose"

type CheckCWTProofRequest struct {
	KeyID string
	Algo  cose.Algorithm
}
