/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"github.com/trustbloc/did-go/doc/ld/processor"
)

// AddLinkedDataProof appends proof to the Verifiable Credential.
func (vc *Credential) AddLinkedDataProof(context *LinkedDataProofContext, jsonldOpts ...processor.Opts) error {
	proofs, err := addLinkedDataProof(context, vc.credentialJSON, jsonldOpts...)
	if err != nil {
		return err
	}

	vc.ldProofs = proofs

	return nil
}

// ResetProofs sets new proofs for vc.
func (vc *Credential) ResetProofs(newProofs []Proof) {
	vc.credentialJSON[jsonFldLDProof] = proofsToRaw(newProofs)
	vc.ldProofs = newProofs
}
