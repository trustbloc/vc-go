package verifiable

import (
	"fmt"

	"github.com/trustbloc/kms-go/doc/jose"

	"github.com/trustbloc/vc-go/sdjwt/common"
)

type CredentialJSONParser struct {
}

func (p *CredentialJSONParser) Parse() (*Credential, error) {
	vcOpts := getCredentialOpts(opts)

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
}
