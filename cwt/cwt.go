/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cwt

import (
	"errors"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"

	"github.com/trustbloc/vc-go/proof"
	"github.com/trustbloc/vc-go/util/binary"
	"github.com/trustbloc/vc-go/verifiable/cwt"
)

const (
	issuerPayloadIndex = 1
)

// SignParameters contains parameters of signing for cwt vc.
type SignParameters struct {
	KeyID  string
	CWTAlg cose.Algorithm
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

	_, ok := cwtParsed.Headers.Protected[proof.COSEKeyHeader].(string)
	if !ok {
		return nil, nil, errors.New("check cwt failure: COSE_Key header is required")
	}

	proofValue, err := cwt.GetProofValue(cwtParsed)
	if err != nil {
		return nil, nil, err
	}

	err = CheckProof(cwtParsed, proofChecker, expectedProofIssuer, proofValue, cwtParsed.Signature)
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
	msg []byte,
	signature []byte,
) error {
	var err error

	alg, err := message.Headers.Protected.Algorithm()
	if err != nil {
		return err
	}

	// currently supported only COSE_Key, x5chain is not supported by go opensource implementation yet
	keyMaterial, _ := message.Headers.Protected[proof.COSEKeyHeader].(string)   // nolint
	keyIDBinary, _ := message.Headers.Protected[cose.HeaderLabelKeyID].(string) // nolint

	var rawKeyID string
	if keyIDBinary != "" {
		rawKeyID, err = binary.DecodeBinaryStringToString(keyIDBinary)
		if err != nil {
			return err
		}
	}

	checker := Verifier{
		ProofChecker:        proofChecker,
		expectedProofIssuer: expectedProofIssuer,
	}

	return checker.Verify(keyMaterial, rawKeyID, alg, msg, signature)
}
