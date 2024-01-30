/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cwt

import (
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

// GetProofValue returns the proof value for the given COSE_Sign1 message.
func GetProofValue(message *cose.Sign1Message) ([]byte, error) {
	var protected cbor.RawMessage
	protected, err := message.Headers.MarshalProtected()

	if err != nil {
		return nil, err
	}

	cborProtectedData, err := deterministicBinaryString(protected)
	if err != nil {
		return nil, err
	}

	sigStructure := []interface{}{
		"Signature1",      // context
		cborProtectedData, // body_protected
		[]byte{},          // external_aad
		message.Payload,   // payload
	}

	cborData, err := cbor.Marshal(sigStructure)
	if err != nil {
		return nil, err
	}

	return cborData, nil
}
