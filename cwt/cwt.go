/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cwt

import (
	"errors"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

const (
	issuerPayloadIndex = 1
	keyIDHeaderIndex   = int64(4)
)

type CWT struct {
	ProtectedHeader map[int]interface{}
	Payload         []byte
	Signature       []byte
}

// ParseAndCheckProof parses input JWT in serialized form into JSON Web Token and check signature proof.
// if checkIssuer set to true, will check if issuer set by "iss" own key set by "kid" header.
func ParseAndCheckProof(
	cwtSerialized []byte,
	proofChecker ProofChecker,
	checkIssuer bool,
) (*cose.Sign1Message, []byte, error) {
	cwtParsed, err := Parse(cwtSerialized)
	if err != nil {
		return nil, nil, err
	}

	var expectedProofIssuer *string

	if checkIssuer {
		payload := map[int]interface{}{}
		if err = cbor.Unmarshal(cwtParsed.Payload, &payload); err != nil {
			return nil, nil, err
		}

		iss, ok := payload[issuerPayloadIndex]
		if !ok {
			return nil, nil, errors.New("check cwt failure: iss claim is required")
		}

		issStr, ok := iss.(string)
		if !ok {
			return nil, nil, errors.New("check cwt failure: iss claim is not a string")
		}

		expectedProofIssuer = &issStr
	}

	err = CheckProof(cwtParsed, proofChecker, expectedProofIssuer)
	if err != nil {
		return nil, nil, err
	}

	return cwtParsed, cwtParsed.Payload, nil
}

// Parse parses input CWT in serialized form into JSON Web Token.
func Parse(cwtSerialized []byte) (*cose.Sign1Message, error) {
	var message cose.Sign1Message
	if err := message.UnmarshalCBOR(cwtSerialized); err != nil {
		return nil, err
	}

	return &message, nil
}

// CheckProof checks that jwt have correct signature.
func CheckProof(
	message *cose.Sign1Message,
	proofChecker ProofChecker,
	expectedProofIssuer *string,
) error {
	alg, err := message.Headers.Protected.Algorithm()
	if err != nil {
		return err
	}
	keyIDBytes, ok := message.Headers.Unprotected[keyIDHeaderIndex].([]byte)
	if !ok {
		return errors.New("check cwt failure: kid header is required")
	}

	checker := cwtVerifier{
		proofChecker:        proofChecker,
		expectedProofIssuer: expectedProofIssuer,
	}

	return checker.Verify(message, string(keyIDBytes), alg)
}
