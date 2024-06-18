/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"crypto"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	jsonld "github.com/trustbloc/did-go/doc/ld/processor"
	afgotime "github.com/trustbloc/did-go/doc/util/time"
	"github.com/trustbloc/kms-go/spi/kms"
	"github.com/veraison/go-cose"
	"github.com/xeipuuv/gojsonschema"
	"golang.org/x/exp/slices"

	"github.com/trustbloc/vc-go/proof/testsupport"

	jsonutil "github.com/trustbloc/vc-go/util/json"
)

const singleCredentialSubject = `
{
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "degree": {
      "type": "BachelorDegree",
      "name": "Bachelor of Science and Arts"
    }
}
`

const multipleCredentialSubjects = `
[{
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "name": "Jayden Doe",
    "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
  }, {
    "id": "did:example:c276e12ec21ebfeb1f712ebc6f1",
    "name": "Morgan Doe",
    "spouse": "did:example:ebfeb1f712ebc6f1c276e12ec21"
  }]
`

const issuerAsObject = `
{
    "id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
    "name": "Example University"
}
`

//nolint:gochecknoglobals
var subjectProto = Subject{
	ID: "did:example:ebfeb1f712ebc6f1c276e12ec21",
	CustomFields: map[string]interface{}{
		"name":   "Jayden Doe",
		"spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1",
	},
}

//nolint:gochecknoglobals
var vccProto = CredentialContents{
	Context: []string{
		"https://www.w3.org/2018/credentials/v1",
		"https://www.w3.org/2018/credentials/examples/v1",
	},
	ID: "http://example.edu/credentials/1872",
	Types: []string{
		"VerifiableCredential",
		"UniversityDegreeCredential",
	},
	Subject: []Subject{subjectProto},
	Issuer: &Issuer{
		ID:           "did:example:76e12ec712ebc6f1c221ebfeb1f",
		CustomFields: CustomFields{"name": "Example University"},
	},
	Issued:  afgotime.NewTime(time.Now()),
	Expired: afgotime.NewTime(time.Now().Add(time.Hour)),
	Schemas: []TypedID{},
}

func TestParseCredential(t *testing.T) {
	t.Run("test creation of new Verifiable Credential from JSON with valid structure", func(t *testing.T) {
		vc, err := parseTestCredential(t, []byte(validCredential), WithStrictValidation(), WithDisabledProofCheck())
		require.NoError(t, err)
		require.NotNil(t, vc)

		vcc := vc.Contents()

		// validate @context
		require.Equal(t, []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://www.w3.org/2018/credentials/examples/v1",
			"https://w3id.org/security/jws/v1",
			"https://trustbloc.github.io/context/vc/examples-v1.jsonld",
			"https://w3id.org/security/suites/ed25519-2020/v1",
		}, vcc.Context)

		// validate id
		require.Equal(t, "http://example.edu/credentials/1872", vcc.ID)

		// validate type
		require.Equal(t, []string{"VerifiableCredential"}, vcc.Types)

		// validate not null credential subject
		require.NotNil(t, vcc.Subject)

		// validate not null credential subject
		require.NotNil(t, vcc.Issuer)
		require.Equal(t, "did:example:76e12ec712ebc6f1c221ebfeb1f", vcc.Issuer.ID)
		require.Equal(t, "Example University", vcc.Issuer.CustomFields["name"])
		require.Equal(t, "data:image/png;base64,iVBOR", vcc.Issuer.CustomFields["image"])

		// check issued date
		expectedIssued := time.Date(2010, time.January, 1, 19, 23, 24, 0, time.UTC)
		require.Equal(t, expectedIssued, vcc.Issued.Time)

		// check issued date
		expectedExpired := time.Date(2020, time.January, 1, 19, 23, 24, 0, time.UTC)
		require.Equal(t, expectedExpired, vcc.Expired.Time)

		// check credential status
		require.NotNil(t, vcc.Status)
		require.Equal(t, "https://example.edu/status/24", vcc.Status.ID)
		require.Equal(t, "CredentialStatusList2017", vcc.Status.Type)

		// check refresh service
		require.NotNil(t, vcc.RefreshService)
		require.Equal(t, "https://example.edu/refresh/3732", vcc.RefreshService[0].ID)
		require.Equal(t, "ManualRefreshService2018", vcc.RefreshService[0].Type)

		require.NotNil(t, vcc.Evidence)

		require.NotNil(t, vcc.TermsOfUse)
		require.Len(t, vcc.TermsOfUse, 1)
	})

	t.Run("test a try to create a new Verifiable Credential from JSON with invalid structure", func(t *testing.T) {
		emptyJSONDoc := "{}"
		vc, err := parseTestCredential(t, []byte(emptyJSONDoc))
		require.Error(t, err)
		require.Contains(t, err.Error(), "credential type of unknown structure")
		require.Nil(t, vc)
	})

	t.Run("test a try to create a new Verifiable Credential from non-JSON doc", func(t *testing.T) {
		vc, err := parseTestCredential(t, []byte("non json"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "new credential")
		require.Nil(t, vc)
	})
}

func TestParseCredentialWithoutIssuanceDate(t *testing.T) {
	t.Run("test creation of new Verifiable Credential with disabled issuance date check", func(t *testing.T) {
		schema := JSONSchemaLoader(WithDisableRequiredField("issuanceDate"))

		vc, err := parseTestCredential(t, []byte(credentialWithoutIssuanceDate), WithDisabledProofCheck(),
			WithStrictValidation(),
			WithSchema(schema))
		require.NoError(t, err)
		require.NotNil(t, vc)
	})

	t.Run("'issuanceDate is required' error", func(t *testing.T) {
		_, err := parseTestCredential(t, []byte(credentialWithoutIssuanceDate), WithDisabledProofCheck(),
			WithStrictValidation())
		require.Error(t, err)
	})
}

func TestValidateVerCredContext(t *testing.T) {
	t.Run("test verifiable credential with a single context", func(t *testing.T) {
		var raw JSONObject

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw[jsonFldContext] = []string{"https://www.w3.org/2018/credentials/v1"}

		err := validateCredentialUsingJSONSchema(raw, nil, &credentialOpts{})
		require.NoError(t, err)
	})

	t.Run("test verifiable credential with a single invalid context", func(t *testing.T) {
		var raw JSONObject

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw[jsonFldContext] = []string{"https://www.w3.org/2018/credentials/v2"}

		err := validateCredentialUsingJSONSchema(raw, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "does not match: \"https://www.w3.org/2018/credentials/v1\"")
	})

	t.Run("test verifiable credential with empty context", func(t *testing.T) {
		var raw JSONObject

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		delete(raw, jsonFldContext)

		err := validateCredentialUsingJSONSchema(raw, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "@context is required")
	})

	t.Run("test verifiable credential with multiple contexts", func(t *testing.T) {
		var raw JSONObject

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw[jsonFldContext] = []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://www.w3.org/2018/credentials/examples/v1",
		}

		err := validateCredentialUsingJSONSchema(raw, nil, &credentialOpts{})
		require.NoError(t, err)
	})

	t.Run("test verifiable credential with multiple invalid contexts", func(t *testing.T) {
		var raw JSONObject

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw[jsonFldContext] = []string{
			"https://www.w3.org/2018/credentials/v2",
			"https://www.w3.org/2018/credentials/examples/v1",
		}

		err := validateCredentialUsingJSONSchema(raw, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "@context.0: @context.0 does not match: \"https://www.w3.org/2018/credentials/v1\"")
	})

	t.Run("test verifiable credential with object context", func(t *testing.T) {
		var raw JSONObject

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))

		raw[jsonFldContext] = []interface{}{"https://www.w3.org/2018/credentials/examples/v1", map[string]interface{}{
			"image": map[string]string{
				"@id": "schema:image", "@type": "@id",
			},
		}}

		err := validateCredentialUsingJSONSchema(raw, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "@context.0: @context.0 does not match: \"https://www.w3.org/2018/credentials/v1\"")
	})
}

// func TestValidateVerCredID(t *testing.T) {
// 	raw := JSONObject{}
//
// 	require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
//
// 	raw.ID = "not valid credential ID URL"
// 	bytes, err := json.Marshal(raw)
// 	require.NoError(t, err)
// 	err = validateCredentialUsingJSONSchema(bytes, nil, &credentialOpts{})
// 	require.Error(t, err)
// 	require.Contains(t, err.Error(), "id: Does not match format 'uri'")
// }

func TestValidateVerCredType(t *testing.T) {
	t.Run("test verifiable credential with no type", func(t *testing.T) {
		var raw JSONObject

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw[jsonFldType] = []string{}

		err := validateCredentialUsingJSONSchema(raw, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "Array must have at least 1 items")
	})

	t.Run("test verifiable credential with not first VerifiableCredential type", func(t *testing.T) {
		var raw JSONObject

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw[jsonFldType] = []string{"NotVerifiableCredential"}

		err := validateCredentialUsingJSONSchema(raw, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "Does not match pattern '^VerifiableCredential$")
	})

	t.Run("test verifiable credential with VerifiableCredential type only as string", func(t *testing.T) {
		var raw JSONObject

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw[jsonFldType] = "VerifiableCredential"

		err := validateCredentialUsingJSONSchema(raw, nil, &credentialOpts{})
		require.NoError(t, err)
	})

	t.Run("test verifiable credential with several types where VerifiableCredential is not a first type",
		func(t *testing.T) {
			var raw JSONObject

			require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
			raw[jsonFldType] = []string{"UniversityDegreeCredentail", "VerifiableCredential"}

			err := validateCredentialUsingJSONSchema(raw, nil, &credentialOpts{})
			require.NoError(t, err)
		})
}

func TestValidateVerCredCredentialSubject(t *testing.T) {
	t.Run("test verifiable credential with no credential subject", func(t *testing.T) {
		var raw JSONObject

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		delete(raw, jsonFldSubject)

		err := validateCredentialUsingJSONSchema(raw, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "credentialSubject is required")
	})

	t.Run("test verifiable credential with single credential subject", func(t *testing.T) {
		var raw JSONObject
		var subject interface{}

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		require.NoError(t, json.Unmarshal([]byte(singleCredentialSubject), &subject))
		raw[jsonFldSubject] = subject

		err := validateCredentialUsingJSONSchema(raw, nil, &credentialOpts{})
		require.NoError(t, err)
	})

	t.Run("test verifiable credential with single string credential subject", func(t *testing.T) {
		var raw JSONObject
		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))

		raw[jsonFldSubject] = "did:example:ebfeb1f712ebc6f1c276e12ec21"

		err := validateCredentialUsingJSONSchema(raw, nil, &credentialOpts{})
		require.NoError(t, err)
	})

	t.Run("test verifiable credential with several credential subjects", func(t *testing.T) {
		var raw JSONObject
		var subject interface{}

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		require.NoError(t, json.Unmarshal([]byte(multipleCredentialSubjects), &subject))
		raw[jsonFldSubject] = subject

		_, err := ParseCredentialJSON(raw, WithJSONLDDocumentLoader(createTestDocumentLoader(t)))
		require.NoError(t, err)
	})

	t.Run("test verifiable credential with invalid type of credential subject", func(t *testing.T) {
		var raw JSONObject

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))

		raw[jsonFldSubject] = 55

		err := validateCredentialUsingJSONSchema(raw, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "credentialSubject: Invalid type.")
	})
}

func TestValidateVerCredIssuer(t *testing.T) {
	t.Run("test verifiable credential with no issuer", func(t *testing.T) {
		var raw JSONObject

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		delete(raw, jsonFldIssuer)

		err := validateCredentialUsingJSONSchema(raw, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "issuer is required")
	})

	t.Run("test verifiable credential with plain id issuer", func(t *testing.T) {
		var raw JSONObject

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))

		raw[jsonFldIssuer] = "https://example.edu/issuers/14"

		err := validateCredentialUsingJSONSchema(raw, nil, &credentialOpts{})
		require.NoError(t, err)
	})

	t.Run("test verifiable credential with issuer as an object", func(t *testing.T) {
		var raw JSONObject
		var issuer interface{}

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		require.NoError(t, json.Unmarshal([]byte(issuerAsObject), &issuer))
		raw[jsonFldIssuer] = issuer

		err := validateCredentialUsingJSONSchema(raw, nil, &credentialOpts{})
		require.NoError(t, err)
	})

	t.Run("test verifiable credential with invalid type of issuer", func(t *testing.T) {
		var raw JSONObject

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))

		raw[jsonFldIssuer] = 55

		err := validateCredentialUsingJSONSchema(raw, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "issuer: Invalid type")
	})

	t.Run("test verifiable credential with string issuer", func(t *testing.T) {
		var raw JSONObject

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))

		issuerRaw, err := json.Marshal("not-a-uri-issuer")
		require.NoError(t, err)

		raw[jsonFldIssuer] = issuerRaw

		err = validateCredentialUsingJSONSchema(raw, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "issuer: Does not match format 'uri'")
	})

	t.Run("test verifiable credential with object issuer", func(t *testing.T) {
		var raw JSONObject

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))

		issuerRaw := map[string]interface{}{
			"id":   "not-a-uri-issuer-id",
			"name": "University",
		}

		raw[jsonFldIssuer] = issuerRaw

		err := validateCredentialUsingJSONSchema(raw, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "issuer.id: Does not match format 'uri'")
	})
}

func TestValidateVerCredIssuanceDate(t *testing.T) {
	t.Run("test verifiable credential with empty issuance date", func(t *testing.T) {
		var raw JSONObject

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		delete(raw, jsonFldIssued)

		err := validateCredentialUsingJSONSchema(raw, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "issuanceDate is required")
	})

	t.Run("test verifiable credential with wrong format of issuance date", func(t *testing.T) {
		var vcMap map[string]interface{}

		require.NoError(t, json.Unmarshal([]byte(validCredential), &vcMap))
		vcMap["issuanceDate"] = "not a valid date time"

		err := validateCredentialUsingJSONSchema(vcMap, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "issuanceDate: Does not match format 'date-time'")
	})

	for _, timeStr := range []string{"2010-01-01T19:23:24Z", "2010-01-01T19:23:24.385Z"} {
		var vcMap map[string]interface{}

		require.NoError(t, json.Unmarshal([]byte(validCredential), &vcMap))
		vcMap["issuanceDate"] = timeStr

		err := validateCredentialUsingJSONSchema(vcMap, nil, &credentialOpts{})
		require.NoError(t, err)
	}
}

func TestValidateVerCredProof(t *testing.T) {
	t.Run("test verifiable credential with embedded proof", func(t *testing.T) {
		var raw JSONObject

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))

		proof := []Proof{{
			"type":               "Ed25519Signature2018",
			"created":            "2018-06-18T21:19:10Z",
			"proofPurpose":       "assertionMethod",
			"verificationMethod": "https://example.com/jdoe/keys/1",
			"jws":                "eyJhbGciOiJQUzI1N..Dw_mmMCjs9qxg0zcZzqEJw",
		}}

		raw[jsonFldLDProof] = proof

		err := validateCredentialUsingJSONSchema(raw, nil, &credentialOpts{})
		require.NoError(t, err)
	})
	t.Run("test verifiable credential with empty proof", func(t *testing.T) {
		var raw JSONObject

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw[jsonFldLDProof] = nil

		err := validateCredentialUsingJSONSchema(raw, nil, &credentialOpts{})
		require.NoError(t, err)
	})
}

func TestValidateVerCredExpirationDate(t *testing.T) {
	t.Run("test verifiable credential with empty expiration date", func(t *testing.T) {
		var raw JSONObject

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw[jsonFldExpired] = nil

		err := validateCredentialUsingJSONSchema(raw, nil, &credentialOpts{})
		require.NoError(t, err)
	})

	t.Run("test verifiable credential with wrong format of expiration date", func(t *testing.T) {
		var vcMap map[string]interface{}

		require.NoError(t, json.Unmarshal([]byte(validCredential), &vcMap))
		vcMap["expirationDate"] = "not a valid date time"

		err := validateCredentialUsingJSONSchema(vcMap, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "expirationDate: Does not match format 'date-time'")
	})

	for _, timeStr := range []string{"2010-01-01T19:23:24Z", "2010-01-01T19:23:24.385Z"} {
		var vcMap map[string]interface{}

		require.NoError(t, json.Unmarshal([]byte(validCredential), &vcMap))
		vcMap["expirationDate"] = timeStr

		err := validateCredentialUsingJSONSchema(vcMap, nil, &credentialOpts{})
		require.NoError(t, err)
	}
}

func TestValidateVerCredStatus(t *testing.T) {
	t.Run("test verifiable credential with empty credential status", func(t *testing.T) {
		var raw JSONObject

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw[jsonFldStatus] = nil

		err := validateCredentialUsingJSONSchema(raw, nil, &credentialOpts{})
		require.NoError(t, err)
	})

	t.Run("test verifiable credential with undefined id of credential status", func(t *testing.T) {
		var raw JSONObject

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw[jsonFldStatus] = &TypedID{Type: "CredentialStatusList2017"}

		err := validateCredentialUsingJSONSchema(raw, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "credentialStatus: id is required")
	})

	t.Run("test verifiable credential with undefined type of credential status", func(t *testing.T) {
		var raw JSONObject

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw[jsonFldStatus] = &TypedID{ID: "https://example.edu/status/24"}

		err := validateCredentialUsingJSONSchema(raw, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "credentialStatus: type is required")
	})

	t.Run("test verifiable credential with invalid URL of id of credential status", func(t *testing.T) {
		var raw JSONObject

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw[jsonFldStatus] = map[string]interface{}{"id": "invalid URL", "type": "CredentialStatusList2017"}

		err := validateCredentialUsingJSONSchema(raw, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "credentialStatus.id: Does not match format 'uri'")
	})
}

func TestValidateVerCredSchema(t *testing.T) {
	t.Run("test verifiable credential with empty credential schema", func(t *testing.T) {
		var raw JSONObject

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))

		err := validateCredentialUsingJSONSchema(raw, nil, &credentialOpts{})
		require.NoError(t, err)
	})

	t.Run("test verifiable credential with undefined id of credential schema", func(t *testing.T) {
		var raw JSONObject

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw[jsonFldSchema] = &TypedID{Type: "JsonSchemaValidator2018"}

		err := validateCredentialUsingJSONSchema(raw, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "credentialSchema: id is required")
	})

	t.Run("test verifiable credential with undefined type of credential schema", func(t *testing.T) {
		var raw JSONObject

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw[jsonFldSchema] = &TypedID{ID: "https://example.org/examples/degree.json"}

		err := validateCredentialUsingJSONSchema(raw, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "credentialSchema: type is required")
	})

	t.Run("test verifiable credential with invalid URL of id of credential schema", func(t *testing.T) {
		var raw JSONObject

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw[jsonFldSchema] = map[string]interface{}{"id": "invalid URL", "type": "JsonSchemaValidator2018"}

		err := validateCredentialUsingJSONSchema(raw, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "credentialSchema.id: Does not match format 'uri'")
	})
}

func TestValidateVerCredRefreshService(t *testing.T) {
	t.Run("test verifiable credential with empty refresh service", func(t *testing.T) {
		var raw JSONObject

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw[jsonFldRefreshService] = nil

		err := validateCredentialUsingJSONSchema(raw, nil, &credentialOpts{})
		require.NoError(t, err)
	})

	t.Run("test verifiable credential with undefined id of refresh service", func(t *testing.T) {
		vc, err := parseTestCredential(t, []byte(validCredential), WithDisabledProofCheck())
		require.NoError(t, err)

		raw := vc.ToRawJSON()

		raw[jsonFldRefreshService] = map[string]interface{}{"type": "ManualRefreshService2018"}

		err = validateCredentialUsingJSONSchema(raw, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "refreshService: id is required")
	})

	t.Run("test verifiable credential with undefined type of refresh service", func(t *testing.T) {
		vc, err := parseTestCredential(t, []byte(validCredential), WithDisabledProofCheck())
		require.NoError(t, err)

		raw := vc.ToRawJSON()

		raw[jsonFldRefreshService] = map[string]interface{}{"id": "https://example.edu/refresh/3732"}

		err = validateCredentialUsingJSONSchema(raw, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "refreshService: type is required")
	})

	t.Run("test verifiable credential with invalid URL of id of credential schema", func(t *testing.T) {
		vc, err := parseTestCredential(t, []byte(validCredential), WithDisabledProofCheck())
		require.NoError(t, err)

		raw := vc.ToRawJSON()

		raw[jsonFldRefreshService] = map[string]interface{}{"id": "invalid URL", "type": "ManualRefreshService2018"}

		err = validateCredentialUsingJSONSchema(raw, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "refreshService.id: Does not match format 'uri'")
	})
}

func TestCredential_MarshalJSON(t *testing.T) {
	t.Run("round trip conversion of credential with plain issuer", func(t *testing.T) {
		// setup -> create verifiable credential from json byte data
		vc, err := parseTestCredential(t, []byte(validCredential), WithDisabledProofCheck())
		require.NoError(t, err)
		require.NotEmpty(t, vc)

		// convert verifiable credential to json byte data
		byteCred, err := vc.MarshalJSON()
		require.NoError(t, err)
		require.NotEmpty(t, byteCred)

		// convert json byte data to verifiable credential
		cred2, err := parseTestCredential(t, byteCred, WithDisabledProofCheck())
		require.NoError(t, err)
		require.NotEmpty(t, cred2)

		// verify verifiable credentials created by ParseCredential and JSON function matches
		require.Equal(t, vc.stringJSON(t), cred2.stringJSON(t))
	})

	t.Run("round trip conversion of SD-JWT credential", func(t *testing.T) {
		// setup -> create verifiable credential from SD-JWT

		sdJWTString, proofChecker := createTestSDJWTCred(t)

		vc, err := ParseCredential([]byte(sdJWTString), WithProofChecker(proofChecker))
		require.NoError(t, err)
		require.NotEmpty(t, vc)

		// convert verifiable credential to SD-JWT json string
		byteCred, err := vc.MarshalJSON()
		require.NoError(t, err)
		require.NotEmpty(t, byteCred)

		// original sd-jwt is in 'issuance' format, without a trailing tilde, while MarshalJSON will marshal
		// in 'presentation' format, including a trailing tilde if the sd-jwt has disclosures but no holder binding.

		sdJWTSegments := strings.Split(string(unQuote([]byte(sdJWTString)))+"~", "~")
		byteCredSegments := strings.Split(string(unQuote(byteCred)), "~")

		slices.Sort(sdJWTSegments)
		slices.Sort(byteCredSegments)
		require.Equal(t, sdJWTSegments, byteCredSegments)

		// convert SD-JWT json string to verifiable credential
		cred2, err := ParseCredential(byteCred, WithJWTProofChecker(proofChecker))
		require.NoError(t, err)
		require.NotEmpty(t, cred2)

		// verify verifiable credentials created by ParseCredential and JSON function matches
		expect := strings.Split(vc.stringJSON(t), "~")
		actual := strings.Split(cred2.stringJSON(t), "~")

		require.Len(t, actual, len(expect))

		// jwt is same
		require.Equal(t, expect[0], actual[0])
		// holder signature is same (empty)
		require.Equal(t, expect[len(expect)-1], actual[len(actual)-1])

		expectedDisclosures := map[string]struct{}{}

		for i := 1; i < len(expect)-1; i++ {
			expectedDisclosures[expect[i]] = struct{}{}
		}

		for i := 1; i < len(actual)-1; i++ {
			require.Contains(t, expectedDisclosures, actual[i])
		}
	})

	t.Run("round trip conversion of credential with composite issuer", func(t *testing.T) {
		// setup -> create verifiable credential from json byte data
		vc, err := parseTestCredential(t, []byte(validCredential), WithDisabledProofCheck())
		require.NoError(t, err)
		require.NotEmpty(t, vc)

		vcc := vc.Contents()

		// clean issuer name - this means that we have only issuer id and thus it should be serialized
		// as plain issuer id
		delete(vcc.Issuer.CustomFields, "name")

		// convert verifiable credential to json byte data
		byteCred, err := vc.MarshalJSON()
		require.NoError(t, err)
		require.NotEmpty(t, byteCred)

		// convert json byte data to verifiable credential
		cred2, err := parseTestCredential(t, byteCred, WithDisabledProofCheck())
		require.NoError(t, err)
		require.NotEmpty(t, cred2)

		// verify verifiable credentials created by ParseCredential and JSON function matches
		require.Equal(t, vc.stringJSON(t), cred2.stringJSON(t))
	})

	t.Run("Failure in cf marshalling", func(t *testing.T) {
		vc, err := CreateCredential(CredentialContents{}, map[string]interface{}{
			"invalid field": make(chan int),
		})
		require.NoError(t, err)

		bytes, err := vc.MarshalJSON()
		require.Error(t, err)
		require.Nil(t, bytes)
	})

	t.Run("Failure in TermsOfUse marshalling", func(t *testing.T) {
		vc, err := CreateCredential(CredentialContents{
			TermsOfUse: []TypedID{{CustomFields: map[string]interface{}{
				"invalidField": make(chan int),
			}}},
		}, nil)
		require.NoError(t, err)

		bytes, err := vc.MarshalJSON()
		require.Error(t, err)
		require.Nil(t, bytes)
	})
}

func TestCredential_CreateSignedCOSEVC(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		vcc := vccProto
		vc, err := CreateCredential(vcc, nil)
		require.NoError(t, err)

		pubKeyID := "did:123#issuer-key"
		issuerSigner, _ := testsupport.NewKMSSigVerPair(t, kms.RSARS256Type, keyID)

		jwtVC, err := vc.CreateSignedCOSEVC(true, cose.AlgorithmRS256, issuerSigner, pubKeyID)
		require.NoError(t, err)
		require.NotNil(t, jwtVC)

		cwtCred, err := jwtVC.MarshalAsCWTLD()

		require.NoError(t, err)
		require.NotNil(t, cwtCred)
		str := hex.EncodeToString(cwtCred)
		assert.NotEmpty(t, str)

		parsed, err := ParseCredential([]byte(str))
		require.NoError(t, err)
		require.NotNil(t, parsed)
	})
}

func TestCredential_CreateSignedJWTVC(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		vcc := vccProto
		vc, err := CreateCredential(vcc, nil)
		require.NoError(t, err)

		pubKeyID := "did:123#issuer-key"
		issuerSigner, _ := testsupport.NewKMSSigVerPair(t, kms.RSARS256Type, keyID)

		jwtVC, err := vc.CreateSignedJWTVC(true, RS256, issuerSigner, pubKeyID)
		require.NoError(t, err)
		require.NotNil(t, jwtVC)

		unsecureJWT, err := vc.CreateUnsecuredJWTVC(true)
		require.NoError(t, err)
		require.NotNil(t, unsecureJWT)
	})

	t.Run("Invalid subject", func(t *testing.T) {
		vcc := vccProto
		vcc.Subject = nil

		vc, err := CreateCredential(vcc, nil)
		require.NoError(t, err)

		pubKeyID := "did:123#issuer-key"
		issuerSigner, _ := testsupport.NewKMSSigVerPair(t, kms.RSARS256Type, keyID)

		_, err = vc.CreateSignedJWTVC(true, RS256, issuerSigner, pubKeyID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no subject is defined")

		_, err = vc.CreateUnsecuredJWTVC(true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no subject is defined")
	})
}

func TestCreateCredential(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		vcc := vccProto

		vc, err := CreateCredential(vcc, nil)
		require.NoError(t, err)
		require.NotNil(t, vc)
	})

	t.Run("SDJWTHashAlgs", func(t *testing.T) {
		vcc := vccProto
		sdAlg := crypto.SHA256
		vcc.SDJWTHashAlg = &sdAlg

		vc, err := CreateCredential(vcc, nil)
		require.NoError(t, err)
		require.NotNil(t, vc)

		sdAlg = crypto.SHA384
		vcc.SDJWTHashAlg = &sdAlg

		vc, err = CreateCredential(vcc, nil)
		require.NoError(t, err)
		require.NotNil(t, vc)

		sdAlg = crypto.SHA512
		vcc.SDJWTHashAlg = &sdAlg

		vc, err = CreateCredential(vcc, nil)
		require.NoError(t, err)
		require.NotNil(t, vc)

		sdAlg = crypto.MD5
		vcc.SDJWTHashAlg = &sdAlg

		_, err = CreateCredential(vcc, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not supported")
	})

	t.Run("With proofs", func(t *testing.T) {
		vcc := vccProto

		vc, err := CreateCredentialWithProofs(
			vcc, nil, []Proof{{"type": "JsonWebSignature2020"}})
		require.NoError(t, err)
		require.NotNil(t, vc)
	})

	t.Run("With proofs, failure", func(t *testing.T) {
		vcc := vccProto
		sdAlg := crypto.MD5
		vcc.SDJWTHashAlg = &sdAlg

		_, err := CreateCredentialWithProofs(
			vcc, nil, []Proof{{"type": "JsonWebSignature2020"}})
		require.Error(t, err)

		_, err = CreateCredential(vcc, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not supported")
	})
}

func TestCredential_parseCredentialContents(t *testing.T) {
	vcProto, errC := CreateCredential(vccProto, nil)
	require.NoError(t, errC)
	require.NotNil(t, vcProto)

	t.Run("invalid subject", func(t *testing.T) {
		raw := vcProto.ToRawJSON()

		raw["credentialSubject"] = []string{}
		_, err := parseCredentialContents(raw, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "subject from raw")
	})

	t.Run("invalid id", func(t *testing.T) {
		raw := vcProto.ToRawJSON()

		raw["id"] = []string{}
		_, err := parseCredentialContents(raw, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "credential id")
	})

	t.Run("invalid expirationDate", func(t *testing.T) {
		raw := vcProto.ToRawJSON()

		raw["expirationDate"] = "dd"
		_, err := parseCredentialContents(raw, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "credential expired")
	})

	t.Run("invalid issuanceDate", func(t *testing.T) {
		raw := vcProto.ToRawJSON()

		raw["issuanceDate"] = []string{}
		_, err := parseCredentialContents(raw, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "credential issued")
	})

	t.Run("invalid credentialStatus", func(t *testing.T) {
		raw := vcProto.ToRawJSON()

		raw["credentialStatus"] = []string{}
		_, err := parseCredentialContents(raw, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "credential status")
	})

	t.Run("missed _sd_alg", func(t *testing.T) {
		raw := vcProto.ToRawJSON()

		_, err := parseCredentialContents(raw, true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "_sd_alg must be present in SD-JWT")
	})

	t.Run("invalid _sd_alg", func(t *testing.T) {
		raw := vcProto.ToRawJSON()

		raw["_sd_alg"] = []string{}
		_, err := parseCredentialContents(raw, true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "should be string")
	})
}

func TestWithDisabledExternalSchemaCheck(t *testing.T) {
	credentialOpt := WithNoCustomSchemaCheck()
	require.NotNil(t, credentialOpt)

	opts := &credentialOpts{}
	credentialOpt(opts)
	require.True(t, opts.disabledCustomSchema)
}

func TestWithDisabledProofCheck(t *testing.T) {
	credentialOpt := WithDisabledProofCheck()
	require.NotNil(t, credentialOpt)

	opts := &credentialOpts{}
	credentialOpt(opts)
	require.True(t, opts.disabledProofCheck)
}

func TestWithCredDisableValidation(t *testing.T) {
	credentialOpt := WithCredDisableValidation()
	require.NotNil(t, credentialOpt)

	opts := &credentialOpts{}
	credentialOpt(opts)
	require.True(t, opts.disableValidation)
}

func TestWithCredentialSchemaLoader(t *testing.T) {
	httpClient := &http.Client{}
	jsonSchemaLoader := gojsonschema.NewStringLoader(JSONSchemaLoader())
	cache := NewExpirableSchemaCache(100, 10*time.Minute)

	credentialOpt := WithCredentialSchemaLoader(
		NewCredentialSchemaLoaderBuilder().
			SetSchemaDownloadClient(httpClient).
			SetCache(cache).
			SetJSONLoader(jsonSchemaLoader).
			Build())
	require.NotNil(t, credentialOpt)

	opts := &credentialOpts{}
	credentialOpt(opts)
	require.NotNil(t, opts.schemaLoader)
	require.Equal(t, httpClient, opts.schemaLoader.schemaDownloadClient)
	require.Equal(t, jsonSchemaLoader, opts.schemaLoader.jsonLoader)
	require.Equal(t, cache, opts.schemaLoader.cache)

	// check that defaults are applied

	credentialOpt = WithCredentialSchemaLoader(
		NewCredentialSchemaLoaderBuilder().Build())
	require.NotNil(t, credentialOpt)

	opts = &credentialOpts{}
	credentialOpt(opts)
	require.NotNil(t, opts.schemaLoader)
	require.NotNil(t, opts.schemaLoader.schemaDownloadClient)
	require.NotNil(t, opts.schemaLoader.jsonLoader)
	require.Nil(t, opts.schemaLoader.cache)
}

func TestWithJSONLDValidation(t *testing.T) {
	credentialOpt := WithJSONLDValidation()
	require.NotNil(t, credentialOpt)

	opts := &credentialOpts{}
	credentialOpt(opts)
	require.Equal(t, jsonldValidation, opts.modelValidationMode)
	require.Empty(t, opts.allowedCustomContexts)
	require.Empty(t, opts.allowedCustomTypes)
}

func TestWithBaseContextValidation(t *testing.T) {
	credentialOpt := WithBaseContextValidation()
	require.NotNil(t, credentialOpt)

	opts := &credentialOpts{}
	credentialOpt(opts)
	require.Equal(t, baseContextValidation, opts.modelValidationMode)
	require.Empty(t, opts.allowedCustomContexts)
	require.Empty(t, opts.allowedCustomTypes)
}

func TestWithBaseContextExtendedValidation(t *testing.T) {
	credentialOpt := WithBaseContextExtendedValidation(
		[]string{"https://www.w3.org/2018/credentials/examples/v1"},
		[]string{"UniversityDegreeCredential", "AlumniCredential"})
	require.NotNil(t, credentialOpt)

	opts := &credentialOpts{}
	credentialOpt(opts)
	require.Equal(t, baseContextExtendedValidation, opts.modelValidationMode)

	require.Equal(t, map[string]bool{
		"https://www.w3.org/2018/credentials/v1":          true,
		"https://www.w3.org/2018/credentials/examples/v1": true,
	},
		opts.allowedCustomContexts)

	require.Equal(t, map[string]bool{
		"VerifiableCredential":       true,
		"UniversityDegreeCredential": true,
		"AlumniCredential":           true,
	},
		opts.allowedCustomTypes)
}

func TestWithJSONLDDocumentLoader(t *testing.T) {
	documentLoader := ld.NewDefaultDocumentLoader(nil)
	credentialOpt := WithJSONLDDocumentLoader(documentLoader)
	require.NotNil(t, credentialOpt)

	opts := &credentialOpts{}
	credentialOpt(opts)
	require.Equal(t, documentLoader, opts.jsonldDocumentLoader)
}

func TestWithStrictValidation(t *testing.T) {
	credentialOpt := WithStrictValidation()
	require.NotNil(t, credentialOpt)

	opts := &credentialOpts{}
	credentialOpt(opts)
	require.True(t, opts.strictValidation)
}

func TestCustomCredentialJsonSchemaValidator2018(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		rawMap := make(map[string]interface{})
		require.NoError(t, json.Unmarshal([]byte(JSONSchemaLoader()), &rawMap))

		// extend default schema to require new referenceNumber field to be mandatory
		required, success := rawMap["required"].([]interface{})
		require.True(t, success)
		required = append(required, "referenceNumber")
		rawMap["required"] = required

		bytes, err := json.Marshal(rawMap)
		require.NoError(t, err)

		res.WriteHeader(http.StatusOK)
		_, err = res.Write(bytes)
		require.NoError(t, err)
	}))

	defer func() { testServer.Close() }()

	var raw JSONObject
	err := json.Unmarshal([]byte(validCredential), &raw)
	require.NoError(t, err)

	// define credential schema
	raw[jsonFldSchema] = map[string]interface{}{"id": testServer.URL, "type": "JsonSchemaValidator2018"}
	// but new required field referenceNumber is not defined...

	missingReqFieldSchema, mErr := json.Marshal(raw)
	require.NoError(t, mErr)

	t.Run("Applies custom JSON Schema and detects data inconsistency due to missing new required field", func(t *testing.T) { //nolint:lll
		vc, err := parseTestCredential(t, missingReqFieldSchema)
		require.Error(t, err)
		require.Contains(t, err.Error(), "referenceNumber is required")
		require.Nil(t, vc)
	})

	t.Run("Applies custom credentialSchema and passes new data inconsistency check", func(t *testing.T) {
		raw := make(map[string]interface{})
		require.NoError(t, json.Unmarshal(missingReqFieldSchema, &raw))

		// define required field "referenceNumber"
		raw["referenceNumber"] = 83294847

		customValidSchema, err := json.Marshal(raw)
		require.NoError(t, err)

		vc, err := parseTestCredential(t, customValidSchema, WithDisabledProofCheck(),
			WithBaseContextExtendedValidation([]string{
				"https://www.w3.org/2018/credentials/v1",
				"https://www.w3.org/2018/credentials/examples/v1",
				"https://w3id.org/security/jws/v1",
				"https://trustbloc.github.io/context/vc/examples-v1.jsonld",
				"https://w3id.org/security/suites/ed25519-2020/v1",
			}, []string{
				"VerifiableCredential",
				"UniversityDegreeCredential",
			}))
		require.NoError(t, err)

		vcc := vc.Contents()

		// check credential schema
		require.NotNil(t, vcc.Schemas)
		require.Equal(t, vcc.Schemas[0].ID, testServer.URL)
		require.Equal(t, vcc.Schemas[0].Type, "JsonSchemaValidator2018")
	})

	t.Run("Error when failed to download custom credentialSchema", func(t *testing.T) {
		var raw JSONObject

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))

		// define credential schema with invalid port
		raw[jsonFldSchema] = map[string]interface{}{"id": "http://localhost:0001", "type": "JsonSchemaValidator2018"}
		// but new required field referenceNumber is not defined...

		schemaWithInvalidURLToCredentialSchema, err := json.Marshal(raw)
		require.NoError(t, err)

		vc, err := parseTestCredential(t, schemaWithInvalidURLToCredentialSchema)
		require.Error(t, err)
		require.Contains(t, err.Error(), "load of custom credential schema")
		require.Nil(t, vc)
	})

	t.Run("Uses default schema if custom credentialSchema is not of 'JsonSchemaValidator2018' type", func(t *testing.T) { //nolint:lll
		var raw JSONObject

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))

		// define credential schema with not supported type
		raw[jsonFldSchema] = map[string]interface{}{"id": testServer.URL, "type": "ZkpExampleSchema2018"}

		unsupportedCredentialTypeOfSchema, err := json.Marshal(raw)
		require.NoError(t, err)

		vc, err := parseTestCredential(t, unsupportedCredentialTypeOfSchema, WithDisabledProofCheck())
		require.NoError(t, err)

		vcc := vc.Contents()

		// check credential schema
		require.NotNil(t, vcc.Schemas)
		require.Equal(t, vcc.Schemas[0].ID, testServer.URL)
		require.Equal(t, vcc.Schemas[0].Type, "ZkpExampleSchema2018")
	})

	t.Run("Fallback to default schema validation when custom schemas usage is disabled", func(t *testing.T) {
		_, err := parseTestCredential(t, missingReqFieldSchema, WithDisabledProofCheck(), WithNoCustomSchemaCheck())

		// without disabling external schema check we would get an error here
		require.NoError(t, err)
	})
}

func TestDownloadCustomSchema(t *testing.T) {
	t.Parallel()

	httpClient := &http.Client{}

	noCacheOpts := &credentialOpts{schemaLoader: newDefaultSchemaLoader()}
	withCacheOpts := &credentialOpts{schemaLoader: &CredentialSchemaLoader{
		schemaDownloadClient: httpClient,
		jsonLoader:           gojsonschema.NewStringLoader(JSONSchemaLoader()),
		cache:                NewExpirableSchemaCache(32*1024*1024, time.Hour),
	}}

	t.Run("HTTP GET request to download custom credentialSchema successes", func(t *testing.T) {
		testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
			res.WriteHeader(http.StatusOK)
			_, err := res.Write([]byte("custom schema"))
			require.NoError(t, err)
		}))

		defer func() { testServer.Close() }()

		customSchema, err := getJSONSchema(testServer.URL, noCacheOpts)
		require.NoError(t, err)
		require.Equal(t, []byte("custom schema"), customSchema)
	})

	t.Run("Check custom schema caching", func(t *testing.T) {
		loadsCount := 0
		testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
			res.WriteHeader(http.StatusOK)
			_, err := res.Write([]byte("custom schema"))
			require.NoError(t, err)
			loadsCount++
		}))

		defer func() { testServer.Close() }()

		customSchema, err := getJSONSchema(testServer.URL, withCacheOpts)
		require.NoError(t, err)
		require.Equal(t, []byte("custom schema"), customSchema)

		// Check that schema was downloaded only once - i.e. the cache was used second time
		customSchema2, err := getJSONSchema(testServer.URL, withCacheOpts)
		require.NoError(t, err)
		require.Equal(t, []byte("custom schema"), customSchema2)
		require.Equal(t, 1, loadsCount)

		// Check for cache expiration.
		withCacheOpts = &credentialOpts{schemaLoader: &CredentialSchemaLoader{
			schemaDownloadClient: httpClient,
			jsonLoader:           gojsonschema.NewStringLoader(JSONSchemaLoader()),
			cache:                NewExpirableSchemaCache(32*1024*1024, time.Second),
		}}
		loadsCount = 0
		customSchema4, err := getJSONSchema(testServer.URL, withCacheOpts)
		require.NoError(t, err)
		require.Equal(t, []byte("custom schema"), customSchema4)

		time.Sleep(2 * time.Second)
		customSchema5, err := getJSONSchema(testServer.URL, withCacheOpts)
		require.NoError(t, err)
		require.Equal(t, []byte("custom schema"), customSchema5)
		require.Equal(t, 2, loadsCount)
	})

	t.Run("HTTP GET request to download custom credentialSchema fails", func(t *testing.T) {
		testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
			res.WriteHeader(http.StatusSeeOther)
		}))

		defer func() { testServer.Close() }()

		customSchema, err := getJSONSchema(testServer.URL, noCacheOpts)
		require.Error(t, err)
		require.Contains(t, err.Error(), "credential schema endpoint HTTP failure")
		require.Nil(t, customSchema)
	})

	t.Run("HTTP GET request to download custom credentialSchema returns not OK", func(t *testing.T) {
		// HTTP GET failed
		testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
			res.WriteHeader(http.StatusNotFound)
		}))

		defer func() { testServer.Close() }()

		customSchema, err := getJSONSchema(testServer.URL, withCacheOpts)
		require.Error(t, err)
		require.Contains(t, err.Error(), "credential schema endpoint HTTP failure")
		require.Nil(t, customSchema)
	})
}

func Test_SubjectID(t *testing.T) {
	t.Run("With single Subject", func(t *testing.T) {
		vcWithSingleSubject := &CredentialContents{Subject: []Subject{{
			ID: "did:example:ebfeb1f712ebc6f1c276e12ecaa",
			CustomFields: map[string]interface{}{
				"degree": map[string]interface{}{
					"type": "BachelorDegree",
					"name": "Bachelor of Science and Arts",
				}},
		}}}
		subjectID, err := SubjectID(vcWithSingleSubject.Subject)
		require.NoError(t, err)
		require.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ecaa", subjectID)
	})

	t.Run("With multiple Subjects", func(t *testing.T) {
		vcWithMultipleSubjects := &CredentialContents{
			Subject: []Subject{
				{
					ID: "did:example:ebfeb1f712ebc6f1c276e12ec21",
					CustomFields: map[string]interface{}{
						"name":   "Jayden Doe",
						"spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1",
					},
				},
				{
					ID: "did:example:c276e12ec21ebfeb1f712ebc6f1",
					CustomFields: map[string]interface{}{"name": "Morgan Doe",
						"spouse": "did:example:ebfeb1f712ebc6f1c276e12ec21",
					},
				},
			},
		}
		subjectID, err := SubjectID(vcWithMultipleSubjects.Subject)
		require.Error(t, err)
		require.EqualError(t, err, "more than one subject is defined")
		require.Empty(t, subjectID)
	})

	t.Run("With no Subject", func(t *testing.T) {
		vcWithNoSubject := &CredentialContents{
			Subject: nil,
		}
		subjectID, err := SubjectID(vcWithNoSubject.Subject)
		require.Error(t, err)
		require.EqualError(t, err, "no subject is defined")
		require.Empty(t, subjectID)
	})

	t.Run("With empty Subject", func(t *testing.T) {
		vcWithNoSubject := &CredentialContents{
			Subject: []Subject{},
		}
		subjectID, err := SubjectID(vcWithNoSubject.Subject)
		require.Error(t, err)
		require.EqualError(t, err, "no subject is defined")
		require.Empty(t, subjectID)
	})

	t.Run("Subject without ID defined", func(t *testing.T) {
		vcWithSubjectWithoutID := &CredentialContents{
			Subject: []Subject{{
				CustomFields: CustomFields{
					"givenName":  "Jane",
					"familyName": "Doe",
					"degree": map[string]interface{}{
						"type":    "BachelorDegree",
						"name":    "Bachelor of Science in Mechanical Engineering",
						"college": "College of Engineering",
					}},
			}},
		}
		subjectID, err := SubjectID(vcWithSubjectWithoutID.Subject)
		require.Error(t, err)
		require.EqualError(t, err, "subject id is not defined")
		require.Empty(t, subjectID)
	})
}

func TestRawCredentialSerialization(t *testing.T) {
	cBytes := []byte(validCredential)

	rc := new(JSONObject)
	err := json.Unmarshal(cBytes, rc)
	require.NoError(t, err)
	rcBytes, err := json.Marshal(rc)
	require.NoError(t, err)

	var cMap map[string]interface{}
	err = json.Unmarshal(cBytes, &cMap)
	require.NoError(t, err)

	var rcMap map[string]interface{}
	err = json.Unmarshal(rcBytes, &rcMap)
	require.NoError(t, err)

	require.Equal(t, cMap, rcMap)
}

func TestParseIssuer(t *testing.T) {
	t.Run("Parse Issuer defined by ID only", func(t *testing.T) {
		issuer, err := parseIssuer("did:example:76e12ec712ebc6f1c221ebfeb1f")
		require.NoError(t, err)
		require.Equal(t, "did:example:76e12ec712ebc6f1c221ebfeb1f", issuer.ID)
		require.Empty(t, issuer.CustomFields)
	})

	t.Run("Parse Issuer identified by ID and name", func(t *testing.T) {
		issueRaw := map[string]interface{}{
			"id":   "did:example:76e12ec712ebc6f1c221ebfeb1f",
			"name": "Example University",
		}

		issuer, err := parseIssuer(issueRaw)
		require.NoError(t, err)
		require.Equal(t, "did:example:76e12ec712ebc6f1c221ebfeb1f", issuer.ID)
		require.Equal(t, "Example University", issuer.CustomFields["name"])
	})

	t.Run("Parse Issuer identified by ID and name and image", func(t *testing.T) {
		issueRaw := map[string]interface{}{
			"id":    "did:example:76e12ec712ebc6f1c221ebfeb1f",
			"name":  "Example University",
			"image": "data:image/png;base64,iVBOR",
		}

		issuer, err := parseIssuer(issueRaw)
		require.NoError(t, err)
		require.Equal(t, "did:example:76e12ec712ebc6f1c221ebfeb1f", issuer.ID)
		require.Equal(t, "Example University", issuer.CustomFields["name"])
		require.Equal(t, "data:image/png;base64,iVBOR", issuer.CustomFields["image"])
	})

	t.Run("Parse Issuer identified by ID and empty name", func(t *testing.T) {
		issueRaw := map[string]interface{}{
			"id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
		}

		issuer, err := parseIssuer(issueRaw)
		require.NoError(t, err)
		require.Equal(t, "did:example:76e12ec712ebc6f1c221ebfeb1f", issuer.ID)
		require.Empty(t, issuer.CustomFields)
	})

	t.Run("Parse Issuer identified by empty ID and name", func(t *testing.T) {
		issueRaw := map[string]interface{}{
			"name": "Example University",
		}

		issuer, err := parseIssuer(issueRaw)
		require.Error(t, err)
		require.EqualError(t, err, "issuer ID is not defined")
		require.Empty(t, issuer)
	})

	t.Run("Parse Issuer with invalid type of ID", func(t *testing.T) {
		issueRaw := map[string]interface{}{
			"id": 55,
		}

		issuer, err := parseIssuer(issueRaw)
		require.Error(t, err)
		require.Contains(t, err.Error(), "should be string")
		require.Empty(t, issuer)
	})

	t.Run("Parse Issuer of invalid type", func(t *testing.T) {
		issueRaw := 77

		issuer, err := parseIssuer(issueRaw)

		require.Error(t, err)
		require.Contains(t, err.Error(), "should be json object or string")
		require.Empty(t, issuer)
	})

	t.Run("Parse undefined Issuer", func(t *testing.T) {
		issuer, err := parseIssuer(nil)
		require.NoError(t, err)
		require.Nil(t, issuer)
	})
}

func TestParseSubject(t *testing.T) {
	t.Run("Parse Subject defined by ID only", func(t *testing.T) {
		subjectRaw := "did:example:ebfeb1f712ebc6f1c276e12ec21"

		subject, err := parseSubject(subjectRaw)
		require.NoError(t, err)
		require.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ec21", subject[0].ID)
	})

	t.Run("Parse empty subject", func(t *testing.T) {
		subject, err := parseSubject(nil)
		require.NoError(t, err)
		require.Nil(t, subject)
	})

	t.Run("Parse single Subject object", func(t *testing.T) {
		subjectRaw := map[string]interface{}{
			"id":     "did:example:ebfeb1f712ebc6f1c276e12ec21",
			"name":   "Jayden Doe",
			"spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1",
		}

		subject, err := parseSubject(subjectRaw)
		require.NoError(t, err)
		require.Len(t, subject, 1)
		require.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ec21", subject[0].ID)
		require.NotEmpty(t, subject[0].CustomFields)
		require.Equal(t, "Jayden Doe", subject[0].CustomFields["name"])
		require.Equal(t, "did:example:c276e12ec21ebfeb1f712ebc6f1", subject[0].CustomFields["spouse"])
	})

	t.Run("Parse several Subject objects", func(t *testing.T) {
		subjectRaw := []interface{}{
			map[string]interface{}{
				"id":     "did:example:ebfeb1f712ebc6f1c276e12ec21",
				"name":   "Jayden Doe",
				"spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1",
			},
			map[string]interface{}{
				"id":     "did:example:c276e12ec21ebfeb1f712ebc6f1",
				"name":   "Morgan Doe",
				"spouse": "did:example:ebfeb1f712ebc6f1c276e12ec21",
			},
		}

		subject, err := parseSubject(subjectRaw)
		require.NoError(t, err)
		require.Len(t, subject, 2)
		require.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ec21", subject[0].ID)
		require.NotEmpty(t, subject[0].CustomFields)
		require.Equal(t, "Jayden Doe", subject[0].CustomFields["name"])
		require.Equal(t, "did:example:c276e12ec21ebfeb1f712ebc6f1", subject[0].CustomFields["spouse"])
		require.Equal(t, "did:example:c276e12ec21ebfeb1f712ebc6f1", subject[1].ID)
		require.NotEmpty(t, subject[1].CustomFields)
		require.Equal(t, "Morgan Doe", subject[1].CustomFields["name"])
		require.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ec21", subject[1].CustomFields["spouse"])
	})
}

func TestSerializeIssuer(t *testing.T) {
	t.Run("Marshal Issuer with ID defined only", func(t *testing.T) {
		issuer := Issuer{ID: "did:example:76e12ec712ebc6f1c221ebfeb1f"}

		expectedIssuerBytes, err := json.Marshal("did:example:76e12ec712ebc6f1c221ebfeb1f")
		require.NoError(t, err)

		issuerBytes, err := json.Marshal(serializeIssuer(issuer))
		require.NoError(t, err)
		require.Equal(t, expectedIssuerBytes, issuerBytes)
	})

	t.Run("Marshal Issuer with ID, name, image defined", func(t *testing.T) {
		issuer := Issuer{
			ID: "did:example:76e12ec712ebc6f1c221ebfeb1f",
			CustomFields: CustomFields{
				"name":  "Example University",
				"image": "data:image/png;base64,iVBOR",
			},
		}

		expectedIssuerBytes, err := json.Marshal(map[string]interface{}{
			"id":    "did:example:76e12ec712ebc6f1c221ebfeb1f",
			"name":  "Example University",
			"image": "data:image/png;base64,iVBOR",
		})
		require.NoError(t, err)

		issuerBytes, err := json.Marshal(serializeIssuer(issuer))
		require.NoError(t, err)
		require.Equal(t, expectedIssuerBytes, issuerBytes)
	})

	t.Run("corner case: marshal issuer with invalid custom fields", func(t *testing.T) {
		issuer := Issuer{
			ID:           "did:example:76e12ec712ebc6f1c221ebfeb1f",
			CustomFields: map[string]interface{}{"image": map[chan int]interface{}{make(chan int): 777}},
		}

		issuerBytes, err := json.Marshal(serializeIssuer(issuer))
		require.Error(t, err)
		require.Empty(t, issuerBytes)
	})
}

func TestMarshalSubject(t *testing.T) {
	t.Run("Marshal Subject with ID defined only", func(t *testing.T) {
		subjectRaw := []Subject{{ID: "did:example:76e12ec712ebc6f1c221ebfeb1f"}}

		subject := SerializeSubject(subjectRaw)
		require.Equal(t, map[string]interface{}{"id": "did:example:76e12ec712ebc6f1c221ebfeb1f"}, subject)
	})

	t.Run("Marshal Subject with ID, name, spouse defined", func(t *testing.T) {
		subjectRaw := []Subject{{
			ID: "did:example:76e12ec712ebc6f1c221ebfeb1f",
			CustomFields: CustomFields{
				"name":   "Morgan Doe",
				"spouse": "did:example:ebfeb1f712ebc6f1c276e12ec21",
			},
		}}

		expectedSubject := map[string]interface{}{
			"id":     "did:example:76e12ec712ebc6f1c221ebfeb1f",
			"name":   "Morgan Doe",
			"spouse": "did:example:ebfeb1f712ebc6f1c276e12ec21",
		}

		subject := SerializeSubject(subjectRaw)
		require.Equal(t, expectedSubject, subject)
	})
}

func TestTypesToSerialize(t *testing.T) {
	// single type
	require.Equal(t, "VerifiableCredential", serializeTypes([]string{"VerifiableCredential"}))

	// several types
	require.Equal(t,
		[]interface{}{"VerifiableCredential", "UniversityDegreeCredential"},
		serializeTypes([]string{"VerifiableCredential", "UniversityDegreeCredential"}))
}

func TestContextToSerialize(t *testing.T) {
	// single context without custom objects
	require.Equal(t,
		[]interface{}{"https://www.w3.org/2018/credentials/v1"},
		contextToRaw([]string{"https://www.w3.org/2018/credentials/v1"}, []interface{}{}))

	// several contexts without custom objects
	require.Equal(t, []interface{}{
		"https://www.w3.org/2018/credentials/v1",
		"https://www.w3.org/2018/credentials/examples/v1",
	},
		contextToRaw([]string{
			"https://www.w3.org/2018/credentials/v1",
			"https://www.w3.org/2018/credentials/examples/v1",
		},
			[]interface{}{}))

	// context with custom objects
	customContext := map[string]interface{}{
		"image": map[string]interface{}{"@id": "schema:image", "@type": "@id"},
	}
	require.Equal(t,
		[]interface{}{"https://www.w3.org/2018/credentials/v1", customContext},
		contextToRaw([]string{"https://www.w3.org/2018/credentials/v1"},
			[]interface{}{
				customContext,
			}))
}

func Test_JWTVCToJSON(t *testing.T) {
	//nolint: goconst
	issuerKeyID := "did:example:76e12ec712ebc6f1c221ebfeb1f"
	proofCreator, _ := testsupport.NewKMSSigVerPair(t, kms.ED25519Type, issuerKeyID)

	vcSource, err := parseTestCredential(t, []byte(validCredential), WithDisabledProofCheck())
	require.NoError(t, err)

	jwtClaims, err := vcSource.JWTClaims(true)
	require.NoError(t, err)

	jws, err := jwtClaims.MarshalJWSString(EdDSA, proofCreator, issuerKeyID)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		jsonCred, err := JWTVCToJSON([]byte(jws))
		require.NoError(t, err)

		vcActual, err := parseTestCredential(t, jsonCred, WithDisabledProofCheck())
		require.NoError(t, err)
		require.Equal(t, vcSource, vcActual)
	})
}

func TestParseCredentialFromRaw(t *testing.T) {
	issuer := "did:example:76e12ec712ebc6f1c221ebfeb1f"

	vc, err := parseCredentialContents(JSONObject{
		jsonFldSchema:  44,
		jsonFldType:    "VerifiableCredential",
		jsonFldIssuer:  issuer,
		jsonFldContext: "https://www.w3.org/2018/credentials/v1",
	}, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "fill credential schemas from raw")
	require.Nil(t, vc)

	vc, err = parseCredentialContents(JSONObject{
		jsonFldType:    5,
		jsonFldIssuer:  issuer,
		jsonFldContext: "https://www.w3.org/2018/credentials/v1",
	}, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "fill credential types from raw")
	require.Nil(t, vc)

	invalidIssuer, err := json.Marshal(5)
	require.NoError(t, err)

	vc, err = parseCredentialContents(JSONObject{
		jsonFldType:    "VerifiableCredential",
		jsonFldIssuer:  invalidIssuer,
		jsonFldContext: "https://www.w3.org/2018/credentials/v1",
	}, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "fill credential issuer from raw")
	require.Nil(t, vc)

	vc, err = parseCredentialContents(JSONObject{
		jsonFldType:    "VerifiableCredential",
		jsonFldIssuer:  issuer,
		jsonFldContext: 5, // invalid context
	}, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "fill credential context from raw")
	require.Nil(t, vc)

	vc, err = parseCredentialContents(JSONObject{
		jsonFldType:       "VerifiableCredential",
		jsonFldIssuer:     issuer,
		jsonFldContext:    "https://www.w3.org/2018/credentials/v1",
		jsonFldTermsOfUse: []byte("not json"),
	}, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "fill credential terms of use from raw")
	require.Nil(t, vc)

	vc, err = parseCredentialContents(JSONObject{
		jsonFldType:           "VerifiableCredential",
		jsonFldIssuer:         issuer,
		jsonFldContext:        "https://www.w3.org/2018/credentials/v1",
		jsonFldRefreshService: []byte("not json"),
	}, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "fill credential refresh service from raw")
	require.Nil(t, vc)

	proofs, err := parseLDProof([]byte("not json"))

	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported proof value")
	require.Nil(t, proofs)
}

func TestParseCredentialFromRaw_PreserveDates(t *testing.T) {
	vcMap, err := jsonutil.ToMap(validCredential)
	require.NoError(t, err)

	vcMap["issuanceDate"] = "2020-01-01T00:00:00.000Z"
	vcMap["expirationDate"] = "2030-01-01T00:00:00.000Z"

	credentialWithPreciseDate, err := json.Marshal(vcMap)
	require.NoError(t, err)

	cred, err := parseTestCredential(t, credentialWithPreciseDate, WithDisabledProofCheck())
	require.NoError(t, err)
	require.NotEmpty(t, cred)

	vcBytes, err := cred.MarshalJSON()
	require.NoError(t, err)

	// Check that the dates formatting is not corrupted.
	rawMap, err := jsonutil.ToMap(vcBytes)
	require.NoError(t, err)

	require.Contains(t, rawMap, "issuanceDate")
	require.Equal(t, rawMap["issuanceDate"], "2020-01-01T00:00:00.000Z")
	require.Contains(t, rawMap, "expirationDate")
	require.Equal(t, rawMap["expirationDate"], "2030-01-01T00:00:00.000Z")
}

func TestCredential_validateCredential(t *testing.T) {
	t.Parallel()

	r := require.New(t)

	t.Run("test jsonldValidation constraint", func(t *testing.T) {
		vc, err := parseTestCredential(t, []byte(validCredential), WithDisabledProofCheck())
		r.NoError(err)

		vcOpts := []CredentialOpt{
			WithJSONLDDocumentLoader(createTestDocumentLoader(t)),
			WithJSONLDValidation(),
			WithStrictValidation(),
		}

		raw := vc.ToRawJSON()

		_, err = ParseCredentialJSON(raw, vcOpts...)
		r.NoError(err)

		// add a field which is not defined in the schema

		raw["referenceNumber"] = 83294847

		_, err = ParseCredentialJSON(raw, vcOpts...)
		r.Error(err)

		_, err = ParseCredentialJSON(raw, WithJSONLDDocumentLoader(createTestDocumentLoader(t)),
			WithJSONLDValidation())
		r.NoError(err)

		// remove base context
		raw[jsonFldContext] = []string{"https://trustbloc.github.io/context/vc/examples-v1.jsonld"}

		_, err = ParseCredentialJSON(raw, WithJSONLDDocumentLoader(createTestDocumentLoader(t)),
			WithJSONLDValidation())
		r.Error(err)
	})

	t.Run("test baseContextValidation constraint", func(t *testing.T) {
		vc, err := parseTestCredential(t, []byte(validCredential), WithDisabledProofCheck())
		require.NoError(t, err)

		raw := vc.ToRawJSON()

		raw[jsonFldType] = []string{"VerifiableCredential"}
		raw[jsonFldContext] = []string{"https://www.w3.org/2018/credentials/v1"}

		_, err = ParseCredentialJSON(raw, WithBaseContextValidation())
		r.NoError(err)

		raw[jsonFldType] = []string{"VerifiableCredential", "UniversityDegreeCredential"}
		raw[jsonFldContext] = []string{"https://www.w3.org/2018/credentials/v1"}
		_, err = ParseCredentialJSON(raw, WithBaseContextValidation())
		r.Error(err)
		r.EqualError(err, "violated type constraint: not base only type defined")

		raw[jsonFldType] = []string{"UniversityDegreeCredential"}
		raw[jsonFldContext] = []string{"https://www.w3.org/2018/credentials/v1"}
		_, err = ParseCredentialJSON(raw, WithBaseContextValidation())
		r.Error(err)
		r.EqualError(err, "violated type constraint: not base only type defined")

		raw[jsonFldType] = []string{"VerifiableCredential"}
		raw[jsonFldContext] = []string{"https://www.w3.org/2018/credentials/v1", "https://www.exaple.org/udc/v1"}
		_, err = ParseCredentialJSON(raw, WithBaseContextValidation())
		r.Error(err)
		r.EqualError(err, "violated @context constraint: not base only @context defined")

		raw[jsonFldType] = []string{"VerifiableCredential"}
		raw[jsonFldContext] = []string{"https://www.exaple.org/udc/v1"}
		_, err = ParseCredentialJSON(raw, WithBaseContextValidation())
		r.Error(err)
		r.EqualError(err, "violated @context constraint: not base only @context defined")
	})

	t.Run("test baseContextExtendedValidation constraint", func(t *testing.T) {
		vc, err := parseTestCredential(t, []byte(validCredential), WithDisabledProofCheck())
		require.NoError(t, err)

		raw := vc.ToRawJSON()

		raw[jsonFldType] = []string{"VerifiableCredential", "AlumniCredential"}
		raw[jsonFldContext] = []string{"https://www.w3.org/2018/credentials/v1", "https://www.exaple.org/alumni/v1"}

		_, err = ParseCredentialJSON(
			raw,
			WithBaseContextExtendedValidation(
				[]string{"https://www.w3.org/2018/credentials/v1", "https://www.exaple.org/alumni/v1"},
				[]string{"VerifiableCredential", "AlumniCredential"},
			))

		r.NoError(err)

		raw[jsonFldType] = []string{"VerifiableCredential", "UniversityDegreeCredential"}
		raw[jsonFldContext] = []string{"https://www.w3.org/2018/credentials/v1", "https://www.exaple.org/alumni/v1"}
		_, err = ParseCredentialJSON(
			raw,
			WithBaseContextExtendedValidation(
				[]string{"https://www.w3.org/2018/credentials/v1", "https://www.exaple.org/alumni/v1"},
				[]string{"VerifiableCredential", "AlumniCredential"},
			))
		r.Error(err)
		r.EqualError(err, "not allowed type: UniversityDegreeCredential")

		raw[jsonFldType] = []string{"VerifiableCredential", "AlumniCredential"}
		raw[jsonFldContext] = []string{"https://www.w3.org/2018/credentials/v1", "https://www.exaple.org/udc/v1"}
		_, err = ParseCredentialJSON(
			raw,
			WithBaseContextExtendedValidation(
				[]string{"https://www.w3.org/2018/credentials/v1", "https://www.exaple.org/alumni/v1"},
				[]string{"VerifiableCredential", "AlumniCredential"},
			))
		r.Error(err)
		r.EqualError(err, "not allowed @context: https://www.exaple.org/udc/v1")
	})
}

func TestDecodeWithNullValues(t *testing.T) {
	vcJSON := `
{
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
    ],
    "credentialSubject": {
        "degree": {
            "type": "BachelorDegree",
            "university": "MIT"
        },
        "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
        "name": "Jayden Doe",
        "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
    },
    "issuanceDate": "2020-01-08T11:57:26Z",
    "issuer": {
        "id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
        "name": "Example University"
    },
    "type": [
        "VerifiableCredential",
        "UniversityDegreeCredential"
    ],

    "credentialSchema": null,
	"proof": null,
	"expirationDate": null,
	"credentialStatus": null,
	"evidence": null,
	"refreshService": null
}
`

	vc, err := parseTestCredential(t, []byte(vcJSON), WithDisabledProofCheck())
	require.NoError(t, err)
	require.NotNil(t, vc)
}

func TestParseCredentialWithDisabledProofCheck(t *testing.T) {
	issuerKeyID := "did:example:76e12ec712ebc6f1c221ebfeb1f"
	proofCreator, _ := testsupport.NewKMSSigVerPair(t, kms.ED25519Type, issuerKeyID)

	t.Run("ParseUnverifiedCredential() for JWS", func(t *testing.T) {
		// Prepare JWS.
		vc, err := parseTestCredential(t, []byte(validCredential), WithDisabledProofCheck())
		require.NoError(t, err)

		credClaims, err := vc.JWTClaims(true)
		require.NoError(t, err)

		jws, err := credClaims.MarshalJWSString(EdDSA, proofCreator, issuerKeyID)
		require.NoError(t, err)

		// Parse VC with JWS proof.
		vcUnverified, err := ParseCredential([]byte(jws),
			WithJSONLDDocumentLoader(createTestDocumentLoader(t)),
			WithDisabledProofCheck())
		require.NoError(t, err)
		require.NotNil(t, vcUnverified)

		require.Equal(t, jws, vcUnverified.JWTEnvelope.JWT)

		require.Equal(t, vc.Contents(), vcUnverified.Contents())
	})

	t.Run("ParseUnverifiedCredential() for JWT error cases", func(t *testing.T) {
		validCred, err := parseTestCredential(t, []byte(validCredential), WithDisabledProofCheck())
		require.NoError(t, err)

		vcc := validCred.Contents()

		// Manually change URI on 0 position
		vcc.Context = append([]string{"https://w3id.org/security/bbs/v1"}, vcc.Context...)

		vc, err := CreateCredential(vcc, nil)
		require.NoError(t, err)

		credClaims, err := vc.JWTClaims(true)
		require.NoError(t, err)

		unsecuredJWT, err := credClaims.MarshalUnsecuredJWT()
		require.NoError(t, err)

		// Parse VC with JWS proof.
		vcUnverified, err := ParseCredential([]byte(unsecuredJWT),
			WithJSONLDDocumentLoader(createTestDocumentLoader(t)),
			WithDisabledProofCheck(),
			WithJSONLDValidation()) // Apply only JSON-LD validation
		require.Error(t, err)
		require.ErrorContains(t, err, "invalid context URI on position")
		require.Nil(t, vcUnverified)
	})

	t.Run("ParseUnverifiedCredential() for Linked Data proof", func(t *testing.T) {
		// Prepare JWS.
		vc, err := parseTestCredential(t, []byte(validCredential), WithDisabledProofCheck())
		require.NoError(t, err)

		created := time.Now()
		err = vc.AddLinkedDataProof(&LinkedDataProofContext{
			SignatureType:           "Ed25519Signature2018",
			KeyType:                 kms.ED25519Type,
			ProofCreator:            proofCreator,
			SignatureRepresentation: SignatureJWS,
			Created:                 &created,
		}, jsonld.WithDocumentLoader(createTestDocumentLoader(t)))
		require.NoError(t, err)

		vcBytes, err := json.Marshal(vc)
		require.NoError(t, err)

		// Parse VC with linked data proof.
		vcUnverified, err := ParseCredential(vcBytes,
			WithJSONLDDocumentLoader(createTestDocumentLoader(t)),
			WithDisabledProofCheck())
		require.NoError(t, err)
		require.NotNil(t, vcUnverified)
		require.Equal(t, vc.ToRawJSON(), vcUnverified.ToRawJSON())
	})

	t.Run("ParseUnverifiedCredential() error cases", func(t *testing.T) {
		invalidClaims := map[string]interface{}{
			"iss": 33, // JWT issuer must be a string
		}

		invalidUnsecuredJWT, err := marshalUnsecuredJWT(invalidClaims)
		require.NoError(t, err)

		vc, err := ParseCredential([]byte(invalidUnsecuredJWT), WithDisabledProofCheck())
		require.Error(t, err)
		require.Contains(t, err.Error(), "decode new credential")
		require.Nil(t, vc)

		vc, err = ParseCredential([]byte("invalid VC JSON"), WithDisabledProofCheck())
		require.Error(t, err)
		require.Contains(t, err.Error(), "unmarshal new credential")
		require.Nil(t, vc)

		var rawVCMap map[string]interface{}

		require.NoError(t, json.Unmarshal([]byte(validCredential), &rawVCMap))
		rawVCMap["@context"] = 55 // should be string or slice of strings

		rawVCMapBytes, err := json.Marshal(rawVCMap)
		require.NoError(t, err)

		vc, err = ParseCredential(rawVCMapBytes, WithDisabledProofCheck())
		require.Error(t, err)
		require.Contains(t, err.Error(), "context of unknown type")
		require.Nil(t, vc)

		require.NoError(t, json.Unmarshal([]byte(validCredential), &rawVCMap))
		delete(rawVCMap, "issuer")

		rawVCMapBytes, err = json.Marshal(rawVCMap)
		require.NoError(t, err)

		vc, err = ParseCredential(rawVCMapBytes, WithDisabledProofCheck())
		require.Error(t, err)
		require.Contains(t, err.Error(), "verifiable credential is not valid")
		require.Contains(t, err.Error(), "issuer is required")
		require.Nil(t, vc)
	})
}

func TestCredential_ValidateCredential(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		vc, err := ParseCredential([]byte(validCredential), WithCredDisableValidation(), WithDisabledProofCheck())
		require.NoError(t, err)
		require.NotNil(t, vc)
		require.NoError(t, vc.ValidateCredential(WithJSONLDDocumentLoader(createTestDocumentLoader(t))))
	})

	t.Run("Invalid cred", func(t *testing.T) {
		vc, err := ParseCredential([]byte(credentialWithoutIssuanceDate),
			WithCredDisableValidation(), WithDisabledProofCheck())
		require.NoError(t, err)
		require.NotNil(t, vc)
		require.Error(t, vc.ValidateCredential(WithJSONLDDocumentLoader(createTestDocumentLoader(t))))
	})
}

func TestMarshalCredential(t *testing.T) {
	t.Run("test marshalling VC to JSON bytes", func(t *testing.T) {
		vc, err := parseTestCredential(t, []byte(validCredential), WithDisabledProofCheck())
		require.NoError(t, err)
		require.NotNil(t, vc)

		vcc := vc.Contents()

		vcMap, err := serializeCredentialContents(&vcc, vc.Proofs())
		require.NoError(t, err)
		require.Empty(t, vcMap["credentialSchema"])
		require.NotEmpty(t, vcMap["@context"])
		require.NotEmpty(t, vcMap["credentialSubject"])
		require.NotEmpty(t, vcMap["issuer"])
		require.NotEmpty(t, vcMap["type"])

		// now set schema and try again
		vcc.Schemas = []TypedID{{ID: "test1"}, {ID: "test2"}}

		vcMap, err = serializeCredentialContents(&vcc, vc.Proofs())
		require.NoError(t, err)
		require.NotEmpty(t, vcMap["credentialSchema"])
		require.NotEmpty(t, vcMap["@context"])
		require.NotEmpty(t, vcMap["credentialSubject"])
		require.NotEmpty(t, vcMap["issuer"])
		require.NotEmpty(t, vcMap["type"])
	})
}

//nolint:lll
func TestSubjectToBytes(t *testing.T) {
	r := require.New(t)

	t.Run("nil subject", func(t *testing.T) {
		subject := SerializeSubject(nil)
		r.Nil(subject)
	})

	t.Run("Single Subject subject", func(t *testing.T) {
		subject := SerializeSubject([]Subject{{
			ID: "did:example:ebfeb1f712ebc6f1c276e12ec21",
		}})

		subjectBytes, err := json.Marshal(subject)
		r.NoError(err)

		r.Equal("{\"id\":\"did:example:ebfeb1f712ebc6f1c276e12ec21\"}", string(subjectBytes))

		subject = SerializeSubject([]Subject{{
			ID: "did:example:ebfeb1f712ebc6f1c276e12ec21",
			CustomFields: CustomFields{
				"name":   "Jayden Doe",
				"spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1",
			},
		}})

		subjectBytes, err = json.Marshal(subject)
		r.NoError(err)
		r.Equal("{\"id\":\"did:example:ebfeb1f712ebc6f1c276e12ec21\",\"name\":\"Jayden Doe\",\"spouse\":\"did:example:c276e12ec21ebfeb1f712ebc6f1\"}", string(subjectBytes))
	})

	t.Run("Several Subject subjects", func(t *testing.T) {
		subject := SerializeSubject([]Subject{
			{
				ID: "did:example:ebfeb1f712ebc6f1c276e12ec21",
				CustomFields: CustomFields{
					"name":   "Jayden Doe",
					"spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1",
				},
			},
		})

		subjectBytes, err := json.Marshal(subject)
		r.NoError(err)
		r.Equal("{\"id\":\"did:example:ebfeb1f712ebc6f1c276e12ec21\",\"name\":\"Jayden Doe\",\"spouse\":\"did:example:c276e12ec21ebfeb1f712ebc6f1\"}", string(subjectBytes))

		subject = SerializeSubject([]Subject{
			{
				ID: "did:example:ebfeb1f712ebc6f1c276e12ec21",
				CustomFields: CustomFields{
					"name":   "Jayden Doe",
					"spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1",
				},
			},
			{
				ID: "did:example:c276e12ec21ebfeb1f712ebc6f1",
				CustomFields: CustomFields{
					"name":   "Morgan Doe",
					"spouse": "did:example:ebfeb1f712ebc6f1c276e12ec21",
				},
			},
		})

		subjectBytes, err = json.Marshal(subject)
		r.NoError(err)
		r.Equal("[{\"id\":\"did:example:ebfeb1f712ebc6f1c276e12ec21\",\"name\":\"Jayden Doe\",\"spouse\":\"did:example:c276e12ec21ebfeb1f712ebc6f1\"},{\"id\":\"did:example:c276e12ec21ebfeb1f712ebc6f1\",\"name\":\"Morgan Doe\",\"spouse\":\"did:example:ebfeb1f712ebc6f1c276e12ec21\"}]", string(subjectBytes))
	})
}

func TestCredential_WithModified(t *testing.T) {
	cred, err := CreateCredential(CredentialContents{
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://www.w3.org/2018/credentials/examples/v1",
		},
		ID: "http://example.edu/credentials/1872",
		Types: []string{
			"VerifiableCredential",
			"UniversityDegreeCredential",
		},
		Status: &TypedID{
			ID:   "https://example.edu/status/24",
			Type: "CredentialStatusList2017",
		},
		Subject: []Subject{subjectProto},
		Issuer: &Issuer{
			ID:           "did:example:76e12ec712ebc6f1c221ebfeb1f",
			CustomFields: CustomFields{"name": "Example University"},
		},
		Issued:  afgotime.NewTime(time.Now()),
		Expired: afgotime.NewTime(time.Now().Add(time.Hour)),
		Schemas: []TypedID{},
	}, nil)
	require.NoError(t, err)

	cred = cred.
		WithModifiedID("newID").
		WithModifiedSubject([]Subject{{ID: "newID"}}).
		WithModifiedIssuer(&Issuer{ID: "newID"}).
		WithModifiedContext([]string{"newContext"}).
		WithModifiedStatus(&TypedID{
			ID:   "newID",
			Type: "newType",
		})

	require.Equal(t, "newID", cred.Contents().ID)
	require.Equal(t, "newID", cred.Contents().Subject[0].ID)
	require.Equal(t, "newID", cred.Contents().Issuer.ID)
	require.Equal(t, []string{"newContext"}, cred.Contents().Context)
	require.Equal(t, "newID", cred.Contents().Status.ID)
	require.Equal(t, "newType", cred.Contents().Status.Type)

	cred = cred.
		WithModifiedID("").
		WithModifiedSubject(nil).
		WithModifiedIssuer(nil).
		WithModifiedContext(nil).
		WithModifiedStatus(nil)

	require.Empty(t, cred.Contents().ID)
	require.Empty(t, cred.Contents().Subject)
	require.Empty(t, cred.Contents().Issuer)
	require.Empty(t, cred.Contents().Context)
	require.Empty(t, cred.Contents().Status)

	raw := cred.ToRawJSON()

	require.NotContains(t, raw, jsonFldID)
	require.NotContains(t, raw, jsonFldSubject)
	require.NotContains(t, raw, jsonFldIssuer)
	require.NotContains(t, raw, jsonFldContext)
	require.NotContains(t, raw, jsonFldStatus)
}
