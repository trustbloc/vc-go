package verifiable

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"

	"github.com/trustbloc/vc-go/jwt"
)

type parsePresentationResponse struct {
	VPDataDecoded []byte
	VPRaw         rawPresentation
	VPJwt         string
	VPCwt         []byte
}

// PresentationParser is an interface for parsing presentations.
type PresentationParser interface {
	parse(vpData []byte, vpOpts *presentationOpts) (*parsePresentationResponse, error)
}

// PresentationJSONParser is a parser for JSON presentations.
type PresentationJSONParser struct {
}

func (p *PresentationJSONParser) parse(vpData []byte, vpOpts *presentationOpts) (*parsePresentationResponse, error) {
	vpStr := string(unQuote(vpData))

	if jwt.IsJWS(vpStr) {
		if !vpOpts.disabledProofCheck && vpOpts.proofChecker == nil {
			return nil, errors.New("proof checker is not defined")
		}

		proofChecker := vpOpts.proofChecker
		if vpOpts.disabledProofCheck {
			proofChecker = nil
		}

		vcDataFromJwt, rawCred, err := decodeVPFromJWS(vpStr, proofChecker)
		if err != nil {
			return nil, fmt.Errorf("decoding of Verifiable Presentation from JWS: %w", err)
		}

		return &parsePresentationResponse{
			VPDataDecoded: vcDataFromJwt,
			VPRaw:         rawCred,
			VPJwt:         vpStr,
		}, nil
	}

	embeddedProofCheckOpts := &embeddedProofCheckOpts{
		dataIntegrityOpts:    vpOpts.verifyDataIntegrity,
		proofChecker:         vpOpts.proofChecker,
		disabledProofCheck:   vpOpts.disabledProofCheck,
		jsonldCredentialOpts: vpOpts.jsonldCredentialOpts,
	}

	if jwt.IsJWTUnsecured(vpStr) {
		rawBytes, rawPres, err := decodeVPFromUnsecuredJWT(vpStr)
		if err != nil {
			return nil, fmt.Errorf("decoding of Verifiable Presentation from unsecured JWT: %w", err)
		}

		if err := checkEmbeddedProofBytes(rawBytes, nil, embeddedProofCheckOpts); err != nil {
			return nil, err
		}

		return &parsePresentationResponse{
			VPDataDecoded: rawBytes,
			VPRaw:         rawPres,
			VPJwt:         vpStr,
		}, nil
	}

	vpRaw, err := decodeVPFromJSON(vpData)
	if err != nil {
		return nil, err
	}

	err = checkEmbeddedProofBytes(vpData, nil, embeddedProofCheckOpts)
	if err != nil {
		return nil, err
	}

	// check that embedded proof is present, if not, it's not a verifiable presentation
	if vpOpts.requireProof && vpRaw[vpFldProof] == nil {
		return nil, errors.New("embedded proof is missing")
	}

	return &parsePresentationResponse{
		VPDataDecoded: vpData,
		VPRaw:         vpRaw,
		VPJwt:         "",
	}, nil
}

// PresentationCWTParser is a parser for CWT presentations.
type PresentationCWTParser struct {
}

func (p *PresentationCWTParser) parse(vpData []byte, _ *presentationOpts) (*parsePresentationResponse, error) {
	var rawErr error
	var hexRawErr error
	var hexErr error

	// todo proof checker !!
	message, rawErr := p.parsePres(vpData)

	if rawErr != nil {
		vpData = unQuote(vpData)

		vpData, hexErr = hex.DecodeString(string(vpData))
		if hexErr != nil {
			return nil, errors.Join(errors.New("vpData is not a valid hex string"), hexErr)
		}

		message, hexRawErr = p.parsePres(vpData)
		if hexRawErr != nil {
			return nil, errors.Join(errors.New("unmarshal cbor vp after hex failed"), hexRawErr)
		}
	}

	if message == nil {
		return nil, errors.Join(errors.New("parsed vp cbor message is nil"), rawErr, hexRawErr, hexErr)
	}

	var vpJSON map[interface{}]interface{}
	if err := cbor.Unmarshal(message.Payload, &vpJSON); err != nil {
		return nil, fmt.Errorf("unmarshal cbor vp payload: %w", err)
	}

	convertedMap := convertToStringMap(vpJSON)
	vpContent, _ := convertedMap["vp"].(map[string]interface{})

	return &parsePresentationResponse{
		VPDataDecoded: vpData,
		VPRaw:         vpContent,
		VPJwt:         "",
		VPCwt:         vpData,
	}, nil
}

func (p *PresentationCWTParser) parsePres(data []byte) (*cose.Sign1Message, error) {
	var message cose.Sign1Message

	if err := cbor.Unmarshal(data, &message); err != nil {
		return nil, fmt.Errorf("unmarshal cbor credential: %w", err)
	}

	return &message, nil
}
