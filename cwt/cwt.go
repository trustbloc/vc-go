/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cwt

import (
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/trustbloc/kms-go/doc/jose"
	"github.com/veraison/go-cose"
)

// jwtParseOpts holds options for the JWT parsing.
type parseOpts struct {
}

type CWT struct {
	ProtectedHeader map[int]interface{}
	Payload         []byte
	Signature       []byte
}

// ParseOpt is the JWT Parser option.
type ParseOpt func(opts *parseOpts)

// ParseAndCheckProof parses input JWT in serialized form into JSON Web Token and check signature proof.
// if checkIssuer set to true, will check if issuer set by "iss" own key set by "kid" header.
func ParseAndCheckProof(
	cwtSerialized string,
	proofChecker ProofChecker,
	checkIssuer bool,
	opts ...ParseOpt,
) (*cose.Sign1Message, []byte, error) {
	cwtParsed, err := Parse(cwtSerialized, opts...)
	if err != nil {
		return nil, nil, err
	}

	var expectedProofIssuer *string

	if checkIssuer {
		payload := map[string]interface{}{}
		if err = cbor.Unmarshal(cwtParsed.Payload, &payload); err != nil {
			return nil, nil, err
		}

		iss, ok := payload["iss"]
		if !ok {
			return nil, nil, errors.New("check cwt failure: iss claim is required")
		}

		issStr, ok := iss.(string)
		if !ok {
			return nil, nil, errors.New("check cwt failure: iss claim is not a string")
		}

		expectedProofIssuer = &issStr
	}

	pOpts := &parseOpts{}

	for _, opt := range opts {
		opt(pOpts)
	}

	err = CheckProof(cwtSerialized, proofChecker, expectedProofIssuer)
	if err != nil {
		return nil, nil, err
	}

	return cwtParsed, cwtParsed.Payload, nil
}

// Parse parses input CWT in serialized form into JSON Web Token.
func Parse(cwtSerialized string, opts ...ParseOpt) (*cose.Sign1Message, error) {
	var message cose.Sign1Message
	if err := message.UnmarshalCBOR([]byte(cwtSerialized)); err != nil {
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
	keyID, ok := message.Headers.Unprotected["kid"].(string)
	if !ok {
		return errors.New("check cwt failure: kid header is required")
	}

	vm, err := c.verificationMethodResolver.ResolveVerificationMethod(keyID, expectedProofIssuer)
	if err != nil {
		return fmt.Errorf("invalid public key id: %w", err)
	}

	message.Verify(nil, proofChecker)
	_, err := jose.ParseJWS(jwtSerialized,
		&joseVerifier{expectedProofIssuer: expectedProofIssuer, proofChecker: proofChecker}, jwsOpts...)

	return err
}
