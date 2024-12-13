/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/samber/lo"
	"github.com/trustbloc/kms-go/doc/jose"
	"github.com/veraison/go-cose"

	"github.com/trustbloc/vc-go/sdjwt/common"
)

// CredentialParser is a parser for credentials.
type CredentialParser interface {
	Parse(vcData []byte, vcOpts *credentialOpts) (*Credential, error)
}

// CredentialJSONParser is a parser for JSON credentials.
type CredentialJSONParser struct {
}

// Parse parses a JSON credential.
func (p *CredentialJSONParser) Parse( //nolint:funlen,gocyclo // Old function
	vcData []byte,
	vcOpts *credentialOpts,
) (*Credential, error) {
	vcStr := unwrapStringVC(vcData)

	var (
		externalJWT string
		jwtHeader   jose.Headers
		err         error

		vcDataDecoded []byte
	)

	jwtParseRes := tryParseAsJWSVC(vcStr)
	if jwtParseRes.isJWS {
		jwtHeader, vcDataDecoded, err = decodeJWTVC(jwtParseRes.onlyJWT)
		if err != nil {
			return nil, fmt.Errorf("decode new JWT credential: %w", err)
		}

		if err = validateDisclosures(vcDataDecoded, jwtParseRes.sdDisclosures); err != nil {
			return nil, err
		}

		externalJWT = jwtParseRes.onlyJWT
	} else {
		// Decode json-ld credential, from unsecured JWT or raw JSON
		vcDataDecoded, err = decodeLDVC(vcData, vcStr)
		if err != nil {
			return nil, fmt.Errorf("decode new credential: %w", err)
		}
	}

	vcJSON, err := parseCredentialJSON(vcDataDecoded)
	if err != nil {
		return nil, errors.Join(errUnsupportedCredentialFormat, err)
	}

	contents, err := parseCredentialContents(vcJSON, jwtParseRes.isSDJWT)
	if err != nil {
		return nil, err
	}

	ldProofs, err := parseLDProof(vcJSON[jsonFldLDProof])
	if err != nil {
		return nil, fmt.Errorf("fill credential proof from raw: %w", err)
	}

	if externalJWT == "" && !vcOpts.disableValidation {
		// TODO: consider new validation options for, eg, jsonschema only, for JWT VC
		err = validateCredential(contents, vcJSON, vcOpts)
		if err != nil {
			return nil, err
		}
	}

	vc := &Credential{
		credentialJSON:     vcJSON,
		credentialContents: *contents,
		ldProofs:           ldProofs,
	}

	parsedDisclosures, err := parseDisclosures(jwtParseRes.sdDisclosures, contents.SDJWTHashAlg)
	if err != nil {
		return nil, fmt.Errorf("fill credential sdjwt disclosures from raw: %w", err)
	}

	if jwtParseRes.isJWS {
		vc.JWTEnvelope = &JWTEnvelope{
			JWT:              externalJWT,
			JWTHeaders:       jwtHeader,
			SDJWTVersion:     common.SDJWTVersionDefault,
			SDJWTDisclosures: parsedDisclosures,
			SDHolderBinding:  jwtParseRes.sdHolderBinding,
		}
	}

	return vc, nil
}

// CredentialCBORParser is a parser for CBOR credentials.
type CredentialCBORParser struct{}

func convertToStringMap(
	input map[interface{}]interface{},
) map[string]interface{} {
	out := map[string]interface{}{}

	for k, v := range input {
		key := fmt.Sprintf("%v", k)

		out[key] = convertElement(v)
	}

	return out
}

func convertElement(element interface{}) interface{} {
	switch elem := element.(type) {
	case map[interface{}]interface{}:
		return convertToStringMap(elem)
	case []interface{}:
		for i, v := range elem {
			elem[i] = convertElement(v)
		}

		return elem
	default:
		return elem
	}
}

func (p *CredentialCBORParser) parseCred(data []byte) (*cose.Sign1Message, error) {
	var message cose.Sign1Message

	if err := cbor.Unmarshal(data, &message); err != nil {
		return nil, fmt.Errorf("unmarshal cbor credential: %w", err)
	}

	return &message, nil
}

// Parse parses a CBOR credential.
func (p *CredentialCBORParser) Parse( //nolint:funlen,gocyclo // Old function
	vcData []byte,
	vcOpts *credentialOpts,
) (*Credential, error) {
	var rawErr, hexRawErr, hexErr error

	message, rawErr := p.parseCred(vcData)

	if rawErr != nil {
		vcData = unQuote(vcData)

		vcData, hexErr = hex.DecodeString(string(vcData))
		if hexErr != nil {
			return nil, errors.Join(errUnsupportedCredentialFormat, hexErr)
		}

		message, hexRawErr = p.parseCred(vcData)
		if hexRawErr != nil {
			return nil, errors.Join(errors.New("unmarshal cbor cred after hex failed"), hexRawErr)
		}
	}

	if message == nil {
		return nil, errors.Join(errors.New("parsed cbor message is nil"), rawErr, hexRawErr,
			hexErr)
	}

	var vcJSON map[string]interface{}
	if err := cbor.Unmarshal(message.Payload, &vcJSON); err != nil {
		return nil, fmt.Errorf("unmarshal cbor credential payload: %w", err)
	}

	vcDataMap, ok := vcJSON["vc"].(map[interface{}]interface{})
	if !ok {
		return nil, errors.New("vc field not found in cbor credential")
	}

	convertedMap := convertToStringMap(vcDataMap)

	contents, err := parseCredentialContents(convertedMap, false)
	if err != nil {
		return nil, err
	}

	if !vcOpts.disableValidation {
		err = validateCredential(contents, convertedMap, vcOpts)
		if err != nil {
			return nil, err
		}
	}

	finalCred := &Credential{
		credentialJSON:     convertedMap,
		credentialContents: *contents,
		CWTEnvelope: &CWTEnvelope{
			Sign1MessageRaw:    vcData,
			Sign1MessageParsed: message,
		},
	}

	return finalCred, nil
}

// EnvelopedCredentialParser is a parser for enveloped credentials.
// See https://www.w3.org/TR/vc-data-model-2.0/#enveloped-verifiable-credentials.
type EnvelopedCredentialParser struct {
}

// Parse parses an enveloped credential.
func (p *EnvelopedCredentialParser) Parse(vcData []byte, opts *credentialOpts) (*Credential, error) {
	vcJSON, err := parseCredentialJSON(vcData)
	if err != nil {
		return nil, errUnsupportedCredentialFormat
	}

	types, err := decodeType(vcJSON[jsonFldType])
	if err != nil {
		return nil, errUnsupportedCredentialFormat
	}

	if !lo.Contains(types, VCEnvelopedType) {
		return nil, errUnsupportedCredentialFormat
	}

	id, ok := vcJSON[jsonFldID].(string)
	if !ok {
		return nil, errors.New("id is required for enveloped credential")
	}

	vc, err := parseCredentialDataURL(id, opts)
	if err != nil {
		return nil, fmt.Errorf("parse credential data URL: %w", err)
	}

	return vc, nil
}

var errUnsupportedCredentialFormat = errors.New("unsupported credential format")
