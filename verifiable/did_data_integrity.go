/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"fmt"

	"github.com/trustbloc/did-go/doc/did"

	"github.com/trustbloc/vc-go/dataintegrity"
)

// AddDIDDataIntegrityProof adds a Data Integrity Proof to the did.Doc.
func AddDIDDataIntegrityProof(
	didDoc *did.Doc,
	context *DataIntegrityProofContext,
	diSigner *dataintegrity.Signer,
) (*did.Doc, error) {
	didBytes, err := didDoc.JSONBytes()
	if err != nil {
		return nil, fmt.Errorf("decode did doc: %w", err)
	}

	var jsonLdObject map[string]interface{}

	err = json.Unmarshal(didBytes, &jsonLdObject)
	if err != nil {
		return nil, fmt.Errorf("unmarshal did doc: %w", err)
	}

	// TODO: rewrite to use json object instead bytes presentation
	diProof, err := addDataIntegrityProof(context, didBytes, diSigner)
	if err != nil {
		return nil, fmt.Errorf("create data integrity proof: %w", err)
	}

	jsonLdObject[jsonFldLDProof] = proofsToRaw(diProof)

	signedDoc, err := json.Marshal(jsonLdObject)
	if err != nil {
		return nil, fmt.Errorf("encode signed did doc: %w", err)
	}

	didDocSignedLDP, err := did.ParseDocument(signedDoc)
	if err != nil {
		return nil, fmt.Errorf("parse signed did doc: %w", err)
	}

	return didDocSignedLDP, nil
}
