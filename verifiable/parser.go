package verifiable

import (
	"encoding/hex"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/trustbloc/kms-go/doc/jose"
	"github.com/veraison/go-cose"

	"github.com/trustbloc/vc-go/sdjwt/common"
)

type CredentialParser interface {
	Parse(vcData []byte, vcOpts *credentialOpts) (*Credential, error)
}

type CredentialJSONParser struct {
}

func (p *CredentialJSONParser) Parse(
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
		return nil, err
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

type CredentialCBORParser struct{}

func (p *CredentialCBORParser) convertToStringMap(
	input map[interface{}]interface{},
) map[string]interface{} {
	out := map[string]interface{}{}

	for k, v := range input {
		key := fmt.Sprintf("%v", k)

		if m, ok := v.(map[interface{}]interface{}); ok {
			out[key] = p.convertToStringMap(m)
		} else {
			out[key] = v
		}
	}

	return out
}

func (p *CredentialCBORParser) Parse(
	vcData []byte,
	vcOpts *credentialOpts,
) (*Credential, error) {
	vcData, _ = hex.DecodeString(string(vcData)) // we are not sure, if its hex or not, so ignore err

	var message cose.Sign1Message
	if err := cbor.Unmarshal(vcData, &message); err != nil {
		return nil, fmt.Errorf("unmarshal cbor credential: %w", err)
	}

	var vcJSON map[string]interface{}
	if err := cbor.Unmarshal(message.Payload, &vcJSON); err != nil {
		return nil, fmt.Errorf("unmarshal cbor credential payload: %w", err)
	}

	vcDataMap, ok := vcJSON["vc"].(map[interface{}]interface{})
	if !ok {
		return nil, fmt.Errorf("vc field not found in cbor credential")
	}

	convertedMap := p.convertToStringMap(vcDataMap)
	contents, err := parseCredentialContents(convertedMap, false)
	if err != nil {
		return nil, err
	}

	finalCred := &Credential{
		credentialContents: *contents,
		CWTEnvelope: &CWTEnvelope{
			Sign1MessageRaw:    vcData,
			Sign1MessageParsed: &message,
		},
	}

	return finalCred, nil
}
