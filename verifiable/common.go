/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package verifiable implements Verifiable Credential and Presentation data model
// (https://www.w3.org/TR/vc-data-model).
// It provides the data structures and functions which allow to process the Verifiable documents on different
// sides and levels. For example, an Issuer can create verifiable.Credential structure and issue it to a
// Holder in JWS form. The Holder can decode received Credential and make sure the signature is valid.
// The Holder can present the Credential to the Verifier or combine one or more Credentials into a Verifiable
// Presentation. The Verifier can decode and verify the received Credentials and Presentations.
package verifiable

import (
	"errors"
	"fmt"

	"github.com/piprate/json-gold/ld"
	util "github.com/trustbloc/did-go/doc/util/time"
	"github.com/veraison/go-cose"
	"github.com/xeipuuv/gojsonschema"

	kmsapi "github.com/trustbloc/kms-go/spi/kms"

	jsonutil "github.com/trustbloc/vc-go/util/json"
)

// JWSAlgorithm defines JWT signature algorithms of Verifiable Credential.
type JWSAlgorithm int

const (
	// RS256 JWT Algorithm.
	RS256 JWSAlgorithm = iota

	// PS256 JWT Algorithm.
	PS256

	// EdDSA JWT Algorithm.
	EdDSA

	// ECDSASecp256k1 JWT Algorithm.
	ECDSASecp256k1

	// ECDSASecp256r1 JWT Algorithm.
	ECDSASecp256r1

	// ECDSASecp384r1 JWT Algorithm.
	ECDSASecp384r1

	// ECDSASecp521r1 JWT Algorithm.
	ECDSASecp521r1
)

// KeyTypeToJWSAlgo returns the JWSAlgorithm based on keyType.
func KeyTypeToJWSAlgo(keyType kmsapi.KeyType) (JWSAlgorithm, error) {
	switch keyType {
	case kmsapi.ECDSAP256TypeDER, kmsapi.ECDSAP256TypeIEEEP1363:
		return ECDSASecp256r1, nil
	case kmsapi.ECDSAP384TypeDER, kmsapi.ECDSAP384TypeIEEEP1363:
		return ECDSASecp384r1, nil
	case kmsapi.ECDSAP521TypeDER, kmsapi.ECDSAP521TypeIEEEP1363:
		return ECDSASecp521r1, nil
	case kmsapi.ED25519Type:
		return EdDSA, nil
	case kmsapi.ECDSASecp256k1TypeIEEEP1363, kmsapi.ECDSASecp256k1DER:
		return ECDSASecp256k1, nil
	case kmsapi.RSARS256Type:
		return RS256, nil
	case kmsapi.RSAPS256Type:
		return PS256, nil
	default:
		return 0, errors.New("unsupported key type")
	}
}

// KeyTypeToCWSAlgo returns the cose.Algorithm based on keyType.
func KeyTypeToCWSAlgo(keyType kmsapi.KeyType) (cose.Algorithm, error) {
	switch keyType {
	case kmsapi.ECDSAP256TypeDER, kmsapi.ECDSAP256TypeIEEEP1363:
		return cose.AlgorithmES256, nil
	case kmsapi.ECDSAP384TypeDER, kmsapi.ECDSAP384TypeIEEEP1363:
		return cose.AlgorithmES384, nil
	case kmsapi.ED25519Type:
		return cose.AlgorithmEdDSA, nil
	case kmsapi.RSARS256Type:
		return cose.AlgorithmRS256, nil
	case kmsapi.RSAPS256Type:
		return cose.AlgorithmPS256, nil
	default:
		return 0, errors.New("unsupported key type")
	}
}

// Name return the name of the signature algorithm.
func (ja JWSAlgorithm) Name() (string, error) {
	switch ja {
	case RS256:
		return "RS256", nil
	case PS256:
		return "PS256", nil
	case EdDSA:
		return "EdDSA", nil
	case ECDSASecp256k1:
		return "ES256K", nil
	case ECDSASecp256r1:
		return "ES256", nil
	case ECDSASecp384r1:
		return "ES384", nil
	case ECDSASecp521r1:
		return "ES521", nil
	default:
		return "", fmt.Errorf("unsupported algorithm: %v", ja)
	}
}

type jsonldCredentialOpts struct {
	jsonldDocumentLoader                      ld.DocumentLoader
	externalContext                           []string
	jsonldOnlyValidRDF                        bool
	jsonldIncludeDetailedStructureDiffOnError bool
}

// Proof defines embedded proof of Verifiable Credential.
type Proof map[string]interface{}

// CustomFields is a map of extra fields of struct build when unmarshalling JSON which are not
// mapped to the struct fields.
type CustomFields map[string]interface{}

const (
	jsonFldTypedIDID    = "id"
	jsonFldTypedIDType  = "type"
	jsonFldTypedURLType = "url"
)

// TypedID defines a flexible structure with id and name fields and arbitrary extra fields
// kept in CustomFields.
type TypedID struct {
	ID   string
	Type string

	CustomFields
}

func parseTypedIDObj(typedIDObj JSONObject) (TypedID, error) {
	flds, rest := jsonutil.SplitJSONObj(typedIDObj, jsonFldTypedIDID, jsonFldTypedIDType)

	id, err := parseStringFld(flds, jsonFldTypedIDID)
	if err != nil {
		return TypedID{}, fmt.Errorf("parse TypedID: %w", err)
	}

	typeName, err := parseStringFld(flds, jsonFldTypedIDType)
	if err != nil {
		return TypedID{}, fmt.Errorf("parse TypedID: %w", err)
	}

	return TypedID{
		ID:           id,
		Type:         typeName,
		CustomFields: rest,
	}, nil
}

func serializeTypedIDObj(typedID TypedID) JSONObject {
	json := jsonutil.ShallowCopyObj(typedID.CustomFields)

	json[jsonFldTypedIDID] = typedID.ID
	json[jsonFldTypedIDType] = typedID.Type

	return json
}

func newNilableTypedID(v interface{}) (*TypedID, error) {
	if v == nil {
		return nil, nil
	}

	typedIDObj, ok := v.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("should be json object but got %v", v)
	}

	tid, err := parseTypedIDObj(typedIDObj)
	if err != nil {
		return nil, err
	}

	return &tid, err
}

func describeSchemaValidationError(result *gojsonschema.Result, what string) string {
	errMsg := what + " is not valid:\n"
	for _, desc := range result.Errors() {
		errMsg += fmt.Sprintf("- %s\n", desc)
	}

	return errMsg
}

func stringSlice(values []interface{}) ([]string, error) {
	s := make([]string, len(values))

	for i := range values {
		t, valid := values[i].(string)
		if !valid {
			return nil, errors.New("array element is not a string")
		}

		s[i] = t
	}

	return s, nil
}

// decodeType decodes raw type(s).
//
// type can be defined as a single string value or array of strings.
func decodeType(t interface{}) ([]string, error) {
	switch rType := t.(type) {
	case string:
		return []string{rType}, nil
	case []interface{}:
		types, err := stringSlice(rType)
		if err != nil {
			return nil, fmt.Errorf("vc types: %w", err)
		}

		return types, nil
	case []string:
		return rType, nil
	default:
		return nil, errors.New("credential type of unknown structure")
	}
}

// decodeContext decodes raw context(s).
//
// context can be defined as a single string value or array;
// at the second case, the array can be a mix of string and object types
// (objects can express context information); object context are
// defined at the tail of the array.
func decodeContext(c interface{}) ([]string, []interface{}, error) {
	switch rContext := c.(type) {
	case string:
		return []string{rContext}, nil, nil
	case []interface{}:
		s := make([]string, 0)

		for i := range rContext {
			c, valid := rContext[i].(string)
			if !valid {
				// the remaining contexts are of custom type
				return s, rContext[i:], nil
			}

			s = append(s, c)
		}
		// no contexts of custom type, just string contexts found
		return s, nil, nil
	case []string:
		return rContext, nil, nil
	default:
		return nil, nil, errors.New("credential context of unknown type")
	}
}

func safeStringValue(v interface{}) string {
	if v == nil {
		return ""
	}

	return v.(string)
}

func proofsToRaw(proofs []Proof) interface{} {
	switch len(proofs) {
	case 0:
		return nil
	case 1:
		return map[string]interface{}(proofs[0])
	default:
		return mapSlice(proofs, func(p Proof) interface{} {
			return map[string]interface{}(p)
		})
	}
}

func parseLDProof(proofJSON interface{}) ([]Proof, error) {
	if proofJSON == nil {
		return nil, nil
	}

	switch proof := proofJSON.(type) {
	case map[string]interface{}:
		return []Proof{proof}, nil
	case []interface{}:
		return mapSlice2(proof, func(raw interface{}) (Proof, error) {
			p, ok := raw.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("unsupported proof value '%v'", proofJSON)
			}

			return p, nil
		})
	default:
		return nil, fmt.Errorf("unsupported proof value '%v'", proofJSON)
	}
}

func parseStringFld(obj JSONObject, fldName string) (string, error) {
	jsonStr := obj[fldName]

	if jsonStr == nil {
		return "", nil
	}

	switch str := jsonStr.(type) {
	case string:
		return str, nil

	default:
		return "", fmt.Errorf("field %q should be string, instead got '%v'", fldName, jsonStr)
	}
}

func parseTimeFld(obj JSONObject, fldName string) (*util.TimeWrapper, error) {
	jsonTime := obj[fldName]

	if jsonTime == nil {
		return nil, nil
	}

	switch timeStr := jsonTime.(type) {
	case string:
		time, err := util.ParseTimeWrapper(timeStr)
		if err != nil {
			return nil, fmt.Errorf("field %q contains invalid time value '%v':%w", fldName, jsonTime, err)
		}

		return time, nil

	default:
		return nil, fmt.Errorf("time field %q should be json string, instead got '%v'", fldName, jsonTime)
	}
}

func mapSlice[T any, U any](slice []T, mapFN func(T) U) []U {
	var result []U
	for _, v := range slice {
		result = append(result, mapFN(v))
	}

	return result
}

func mapSlice2[T any, U any](slice []T, mapFN func(T) (U, error)) ([]U, error) {
	var result []U

	for _, v := range slice {
		newVal, err := mapFN(v)
		if err != nil {
			return nil, err
		}

		result = append(result, newVal)
	}

	return result, nil
}
