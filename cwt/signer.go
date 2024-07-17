/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cwt

// ProofCreator defines signer interface which is used to sign VC JWT.
type ProofCreator interface {
	SignCWT(params SignParameters, cborData []byte) ([]byte, error)
}
