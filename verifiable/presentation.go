/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	jsonld "github.com/piprate/json-gold/ld"
	docjsonld "github.com/trustbloc/did-go/doc/ld/validator"
	"github.com/xeipuuv/gojsonschema"

	"github.com/trustbloc/vc-go/dataintegrity"
	jsonutil "github.com/trustbloc/vc-go/util/json"
)

const (
	// VPEnvelopedType indicates that the verifiable presentation is given as an enveloped verifiable presentation.
	// https://www.w3.org/TR/vc-data-model-2.0/#enveloped-verifiable-presentations
	VPEnvelopedType = "EnvelopedVerifiablePresentation"
)

const (
	// VPMediaTypeJWT is the media type for JWT-based verifiable presentations.
	// See https://www.w3.org/TR/vc-jose-cose/#vp-ld-json-jwt.
	VPMediaTypeJWT MediaType = "application/vp-ld+jwt"

	// VPMediaTypeSDJWT is the media type for selective disclosure JWT-based verifiable presentations.
	// See https://www.w3.org/TR/vc-jose-cose/#vp-ld-json-sd-jwt
	VPMediaTypeSDJWT MediaType = "application/vp-ld+sd-jwt"

	// VPMediaTypeCOSE is the media type for COSE-based verifiable presentations.
	// See https://www.w3.org/TR/vc-jose-cose/#vp-ld-json-cose.
	VPMediaTypeCOSE MediaType = "application/vp-ld+cose"
)

const v1BasePresentationSchema = `
{
  "required": [
    "@context",
    "type"
  ],
  "properties": {
    "@context": {
      "oneOf": [
        {
          "type": "string",
          "const": "https://www.w3.org/2018/credentials/v1"
        },
        {
          "type": "array",
          "items": [
            {
              "type": "string",
              "const": "https://www.w3.org/2018/credentials/v1"
            }
          ],
          "uniqueItems": true,
          "additionalItems": {
            "oneOf": [
              {
                "type": "object"
              },
              {
                "type": "string"
              }
            ]
          }
        }
      ]
    },
    "id": {
      "type": "string"
    },
    "type": {
      "oneOf": [
        {
          "type": "array",
          "minItems": 1,
          "contains": {
            "type": "string",
            "pattern": "^VerifiablePresentation$"
          }
        },
        {
          "type": "string",
          "pattern": "^VerifiablePresentation$"
        }
      ]
    },
    "verifiableCredential": {
      "anyOf": [
        {
          "type": "array"
        },
        {
          "type": "object"
        },
        {
          "type": "string"
        },
        {
          "type": "null"
        }
      ]
    },
    "holder": {
      "type": "string",
      "format": "uri"
    },
    "proof": {
      "anyOf": [
        {
          "type": "array",
          "items": [
            {
              "$ref": "#/definitions/proof"
            }
          ]
        },
        {
          "$ref": "#/definitions/proof"
        }
      ]
    },
    "refreshService": {
      "$ref": "#/definitions/typedID"
    }
  },
  "definitions": {
    "typedID": {
      "type": "object",
      "required": [
        "id",
        "type"
      ],
      "properties": {
        "id": {
          "type": "string",
          "format": "uri"
        },
        "type": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "array",
              "items": {
                "type": "string"
              }
            }
          ]
        }
      }
    },
    "proof": {
      "type": "object",
      "required": [
        "type"
      ],
      "properties": {
        "type": {
          "type": "string"
        }
      }
    }
  }
}
`

const v2BasePresentationSchema = `{
  "$id": "https://www.w3.org/2022/credentials/v2/verifiable-presentation-schema.json",
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "description": "JSON Schema for a Verifiable Presentation according to the Verifiable Credentials Data Model v2",
  "type": "object",
  "$defs": {
    "proof": {
      "type": "object",
      "properties": {
        "type": {
          "oneOf": [
            {
              "type": "string"
            },
            {
              "type": "array",
              "minItems": 1
            }
          ]
        },
        "proofPurpose": {
          "type": "string"
        },
        "verificationMethod": {
          "oneOf": [
            {
              "type": "string"
            },
            {
              "type": "array",
              "minItems": 1,
              "items": {
                "type": "object",
                "properties": {
                  "id": {
                    "type": "string"
                  },
                  "type": {
                    "type": "string"
                  },
                  "controller": {
                    "type": "string"
                  }
                },
                "required": [
                  "id",
                  "type",
                  "controller"
                ],
                "additionalProperties": true
              }
            }
          ]
        },
        "created": {
          "type": "string",
          "pattern": "-?([1-9][0-9]{3,}|0[0-9]{3})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T(([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\\.[0-9]+)?|(24:00:00(\\.0+)?))(Z|(\\+|-)((0[0-9]|1[0-3]):[0-5][0-9]|14:00))"
        },
        "domain": {
          "type": "string"
        },
        "challenge": {
          "type": "string"
        },
        "proofValue": {
          "type": "string"
        }
      },
      "required": [
        "type",
        "proofPurpose",
        "verificationMethod",
        "created"
      ],
      "additionalProperties": true
    },
    "proofChain": {
      "type": "array",
      "items": {
        "$ref": "#/$defs/proof"
      },
      "minItems": 1
    }
  },
  "properties": {
    "@context": {
      "type": "array",
      "contains": {
        "const": "https://www.w3.org/ns/credentials/v2"
      },
      "minItems": 1
    },
    "id": {
      "type": "string"
    },
    "type": {
      "oneOf": [
        {
          "type": "array",
          "contains": {
            "const": "VerifiablePresentation"
          }
        },
        {
          "type": "string",
          "enum": ["VerifiablePresentation"]
        }
      ]
    },
    "verifiableCredential": {
      "anyOf": [
        {
          "type": "array"
        },
        {
          "type": "object"
        },
        {
          "type": "string"
        },
        {
          "type": "null"
        }
      ]
    },
    "proof": {
      "oneOf": [
        {
          "$ref": "#/$defs/proof"
        },
        {
          "type": "array",
          "items": {
            "$ref": "#/$defs/proof"
          },
          "minItems": 1
        }
      ]
    },
    "proofChain": {
      "$ref": "#/$defs/proofChain"
    }
  },
  "required": [
    "@context",
    "type"
  ],
  "additionalProperties": true
}`

//nolint:gochecknoglobals
var (
	v1BasePresentationSchemaLoader = gojsonschema.NewStringLoader(v1BasePresentationSchema)
	v2BasePresentationSchemaLoader = gojsonschema.NewStringLoader(v2BasePresentationSchema)
)

// MarshalledCredential defines marshalled Verifiable Credential enclosed into Presentation.
// MarshalledCredential can be passed to verifiable.ParseCredential().
type MarshalledCredential []byte

// CreatePresentationOpt are options for creating a new presentation.
type CreatePresentationOpt func(p *Presentation) error

// Presentation Verifiable Presentation base data model definition.
type Presentation struct {
	Context       []string
	CustomContext []interface{}
	ID            string
	Type          []string
	credentials   []*Credential
	Holder        string
	Proofs        []Proof
	JWT           string
	CWT           *VpCWT

	CustomFields CustomFields
}

// NewPresentation creates a new Presentation with default context and type with the provided credentials.
func NewPresentation(opts ...CreatePresentationOpt) (*Presentation, error) {
	p := Presentation{
		Context: []string{V1ContextURI},
		Type:    []string{VPType},
	}

	for _, o := range opts {
		err := o(&p)
		if err != nil {
			return nil, err
		}
	}

	return &p, nil
}

// WithCredentials sets the provided credentials into the presentation.
func WithCredentials(cs ...*Credential) CreatePresentationOpt {
	return func(p *Presentation) error {
		for _, c := range cs {
			p.credentials = append(p.credentials, c)
		}

		return nil
	}
}

// WithBaseContext sets the base context of the presentation.
func WithBaseContext(ctx string) CreatePresentationOpt {
	return func(p *Presentation) error {
		p.Context = []string{ctx}

		return nil
	}
}

// MarshalJSON converts Verifiable Presentation to JSON bytes.
func (vp *Presentation) MarshalJSON() ([]byte, error) {
	if IsBaseContext(vp.Context, V2ContextURI) {
		if vp.IsJWT() {
			return vp.marshalEnveloped(VPMediaTypeJWT, vp.JWT)
		}

		if vp.IsCWT() {
			return vp.marshalEnveloped(VPMediaTypeCOSE, hex.EncodeToString(vp.CWT.Raw))
		}
	}

	if vp.IsJWT() {
		// If vc.JWT exists, marshal only the JWT, since all other values should be unchanged
		// from when the JWT was parsed.
		return []byte("\"" + vp.JWT + "\""), nil
	}

	raw, err := vp.raw()
	if err != nil {
		return nil, fmt.Errorf("JSON marshalling of verifiable presentation: %w", err)
	}

	byteCred, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("JSON marshalling of verifiable presentation: %w", err)
	}

	return byteCred, nil
}

// marshalEnveloped marshals the presentation as an EnvelopedVerifiablePresentation type.
func (vp *Presentation) marshalEnveloped(mediaType MediaType, data string) ([]byte, error) {
	e := &Envelope{
		Context: []string{V2ContextURI},
		Type:    []string{VPEnvelopedType},
		ID:      NewDataURL(mediaType, "", data),
	}

	vpBytes, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("marshal envelope: %w", err)
	}

	return vpBytes, nil
}

func (vp *Presentation) MarshalCBOR() ([]byte, error) {
	if vp.CWT != nil && len(vp.CWT.Raw) > 0 {
		return vp.CWT.Raw, nil
	}

	raw, err := vp.raw()
	if err != nil {
		return nil, fmt.Errorf("JSON marshalling of verifiable presentation: %w", err)
	}

	return cbor.Marshal(raw)
}

// JWTClaims converts Verifiable Presentation into JWT Presentation claims, which can be than serialized
// e.g. into JWS.
func (vp *Presentation) JWTClaims(audience []string, minimizeVP bool) (*JWTPresClaims, error) {
	return newJWTPresClaims(vp, audience, minimizeVP)
}

// CWTClaims converts Verifiable Presentation into CWT Presentation claims, which can be than serialized
// e.g. into JWS.
func (vp *Presentation) CWTClaims(audience []string, minimizeVP bool) (*CWTPresClaims, error) {
	return newCWTPresClaims(vp, audience, minimizeVP) // for now same as JWT
}

// Credentials returns current credentials of presentation.
func (vp *Presentation) Credentials() []*Credential {
	return vp.credentials
}

// AddCredentials adds credentials to presentation.
func (vp *Presentation) AddCredentials(credentials ...*Credential) {
	for _, credential := range credentials {
		vp.credentials = append(vp.credentials, credential)
	}
}

// MarshalledCredentials provides marshalled credentials enclosed into Presentation in raw byte array format.
// They can be used to decode Credentials into struct.
func (vp *Presentation) MarshalledCredentials() ([]MarshalledCredential, error) {
	mCreds := make([]MarshalledCredential, len(vp.credentials))

	for i := range vp.credentials {
		cred := vp.credentials[i]

		credBytes, err := cred.MarshalJSON()
		if err != nil {
			return nil, fmt.Errorf("marshal credentials from presentation: %w", err)
		}

		mCreds[i] = credBytes
	}

	return mCreds, nil
}

func (vp *Presentation) raw() (rawPresentation, error) {
	rp := rawPresentation{}

	// TODO single value contexts should be compacted as part of Issue [#1730]
	// Not compacting now to support interoperability
	if len(vp.Context) > 0 {
		rp[vpFldContext] = contextToRaw(vp.Context, nil)
	}

	if vp.ID != "" {
		rp[vpFldID] = vp.ID
	}

	if len(vp.Type) > 0 {
		rp[vpFldType] = serializeTypes(vp.Type)
	}

	if len(vp.Holder) > 0 {
		rp[vpFldHolder] = vp.Holder
	}

	if len(vp.Proofs) > 0 {
		rp[vpFldProof] = proofsToRaw(vp.Proofs)
	}

	if len(vp.credentials) > 0 {
		var err error

		rp[vpFldCredential], err = mapSlice2(
			vp.credentials,
			func(cred *Credential) (interface{}, error) {
				return cred.ToUniversalForm()
			},
		)
		if err != nil {
			return nil, fmt.Errorf("serialize credentials to raw presentation: %w", err)
		}
	}

	for cfKey, cfValue := range vp.CustomFields {
		if _, exists := rp[cfKey]; !exists {
			rp[cfKey] = cfValue
		}
	}

	return rp, nil
}

// Clone returns an exact copy of the presentation.
func (vp *Presentation) Clone() *Presentation {
	return &Presentation{
		Context:       vp.Context,
		CustomContext: vp.CustomContext,
		ID:            vp.ID,
		Type:          vp.Type,
		credentials:   vp.credentials,
		Holder:        vp.Holder,
		Proofs:        vp.Proofs,
		CustomFields:  vp.CustomFields,
		JWT:           vp.JWT,
		CWT:           vp.CWT,
	}
}

const (
	vpFldContext    = "@context"
	vpFldID         = "id"
	vpFldType       = "type"
	vpFldCredential = "verifiableCredential"
	vpFldHolder     = "holder"
	vpFldProof      = "proof"
)

// rawPresentation is a basic verifiable credential.
type rawPresentation = map[string]interface{}

// presentationOpts holds options for the Verifiable Presentation decoding.
type presentationOpts struct {
	proofChecker        CombinedProofChecker
	disabledProofCheck  bool
	strictValidation    bool
	requireVC           bool
	requireProof        bool
	disableJSONLDChecks bool
	verifyDataIntegrity *verifyDataIntegrityOpts

	jsonldCredentialOpts
}

// PresentationOpt is the Verifiable Presentation decoding option.
type PresentationOpt func(opts *presentationOpts)

// WithPresProofChecker indicates that Verifiable Presentation should be decoded from JWS using
// provided proofChecker.
func WithPresProofChecker(fetcher CombinedProofChecker) PresentationOpt {
	return func(opts *presentationOpts) {
		opts.proofChecker = fetcher
	}
}

// WithPresDisabledProofCheck option for disabling of proof check.
func WithPresDisabledProofCheck() PresentationOpt {
	return func(opts *presentationOpts) {
		opts.disabledProofCheck = true
	}
}

// WithPresStrictValidation enabled strict JSON-LD validation of VP.
// In case of JSON-LD validation, the comparison of JSON-LD VP document after compaction with original VP one is made.
// In case of mismatch a validation exception is raised.
func WithPresStrictValidation() PresentationOpt {
	return func(opts *presentationOpts) {
		opts.strictValidation = true
	}
}

// WithPresJSONLDDocumentLoader defines custom JSON-LD document loader. If not defined, when decoding VP
// a new document loader will be created using CachingJSONLDLoader() if JSON-LD validation is made.
func WithPresJSONLDDocumentLoader(documentLoader jsonld.DocumentLoader) PresentationOpt {
	return func(opts *presentationOpts) {
		opts.jsonldDocumentLoader = documentLoader
	}
}

// WithDisabledJSONLDChecks disables JSON-LD checks for VP parsing.
// By default, JSON-LD checks are enabled.
func WithDisabledJSONLDChecks() PresentationOpt {
	return func(opts *presentationOpts) {
		opts.disableJSONLDChecks = true
	}
}

// WithPresDataIntegrityVerifier provides the Data Integrity verifier to use when
// the presentation being processed has a Data Integrity proof.
func WithPresDataIntegrityVerifier(v *dataintegrity.Verifier) PresentationOpt {
	return func(opts *presentationOpts) {
		opts.verifyDataIntegrity.Verifier = v
	}
}

// WithPresExpectedDataIntegrityFields validates that a Data Integrity proof has the
// given purpose, domain, and challenge. Empty purpose means the default,
// assertionMethod, will be expected. Empty domain and challenge will mean they
// are not checked.
func WithPresExpectedDataIntegrityFields(purpose, domain, challenge string) PresentationOpt {
	return func(opts *presentationOpts) {
		opts.verifyDataIntegrity.Purpose = purpose
		opts.verifyDataIntegrity.Domain = domain
		opts.verifyDataIntegrity.Challenge = challenge
	}
}

// ParsePresentation creates an instance of Verifiable Presentation by reading a JSON document from bytes.
// It also applies miscellaneous options like custom decoders or settings of schema validation.
func ParsePresentation(vpData []byte, opts ...PresentationOpt) (*Presentation, error) {
	vpOpts := getPresentationOpts(opts)

	parsers := []PresentationParser{
		&presentationEnvelopedParser{},
		&PresentationJSONParser{},
		&PresentationCWTParser{},
	}

	var parsed *parsePresentationResponse
	var finalErr error
	var err error

	for _, parser := range parsers {
		parsed, err = parser.parse(vpData, vpOpts)

		if err != nil {
			finalErr = errors.Join(finalErr, err)
		}

		if parsed != nil {
			finalErr = nil
			err = nil

			break
		}
	}

	if finalErr != nil {
		return nil, finalErr
	}

	if parsed == nil {
		return nil, errors.New("unable to parse presentation")
	}

	err = validateVP(parsed.VPRaw, vpOpts)
	if err != nil {
		return nil, err
	}

	p, err := newPresentation(parsed.VPRaw, vpOpts)
	if err != nil {
		return nil, err
	}

	if vpOpts.requireVC && len(p.credentials) == 0 {
		return nil, fmt.Errorf("verifiableCredential is required")
	}

	p.JWT = parsed.VPJwt
	p.CWT = parsed.VPCwt

	return p, nil
}

func getPresentationOpts(opts []PresentationOpt) *presentationOpts {
	vpOpts := defaultPresentationOpts()

	for _, opt := range opts {
		opt(vpOpts)
	}

	return vpOpts
}

func newPresentation(vpRaw rawPresentation, vpOpts *presentationOpts) (*Presentation, error) {
	types, err := decodeType(vpRaw[vpFldType])
	if err != nil {
		return nil, fmt.Errorf("fill presentation types from raw: %w", err)
	}

	context, customContext, err := decodeContext(vpRaw[vpFldContext])
	if err != nil {
		return nil, fmt.Errorf("fill presentation contexts from raw: %w", err)
	}

	creds, err := decodeCredentials(vpRaw[vpFldCredential], vpOpts)
	if err != nil {
		return nil, fmt.Errorf("decode credentials of presentation: %w", err)
	}

	proofs, err := parseLDProof(vpRaw[vpFldProof])
	if err != nil {
		return nil, fmt.Errorf("fill presentation proof from raw: %w", err)
	}

	id, err := parseStringFld(vpRaw, vpFldID)
	if err != nil {
		return nil, fmt.Errorf("fill presentation id from raw: %w", err)
	}

	holder, err := parseStringFld(vpRaw, vpFldHolder)
	if err != nil {
		return nil, fmt.Errorf("fill presentation holder from raw: %w", err)
	}

	return &Presentation{
		Context:       context,
		CustomContext: customContext,
		ID:            id,
		Type:          types,
		credentials:   creds,
		Holder:        holder,
		Proofs:        proofs,
		CustomFields: jsonutil.CopyExcept(vpRaw,
			vpFldContext,
			vpFldID,
			vpFldType,
			vpFldCredential,
			vpFldHolder,
			vpFldProof,
		),
	}, nil
}

// decodeCredentials decodes credential(s) embedded into presentation.
// It must be one of the following:
// 1) string - it could be credential decoded into e.g. JWS.
// 2) the same as 1) but as array - e.g. zero ore more JWS
// 3) struct (should be map[string]interface{}) representing credential data model
// 4) the same as 3) but as array - i.e. zero or more credentials structs.
func decodeCredentials(rawCred interface{}, opts *presentationOpts) ([]*Credential, error) { //nolint:funlen
	// Accept the case when VP does not have any VCs.
	if rawCred == nil {
		return nil, nil
	}

	unmarshalSingleCredFn := func(cred interface{}) (*Credential, error) {
		credOpts := []CredentialOpt{
			WithProofChecker(opts.proofChecker),
			WithJSONLDDocumentLoader(opts.jsonldCredentialOpts.jsonldDocumentLoader),
		}

		if opts.disabledProofCheck {
			credOpts = append(credOpts, WithDisabledProofCheck())
		}

		// Check the case when VC is defined in string format (e.g. JWT).
		// Decode credential and keep result of decoding.
		if sCred, ok := cred.(string); ok {
			return ParseCredential([]byte(sCred), credOpts...)
		}

		if jsonCred, ok := cred.(JSONObject); ok {
			//TODO: Previous implementation do not validate credentials, should we enable it?
			return ParseCredentialJSON(jsonCred, append(credOpts, WithCredDisableValidation())...)
		}

		return nil,
			fmt.Errorf("invalid credential type should be string or map[string]interface{}, got: %T", cred)
	}

	switch cred := rawCred.(type) {
	case []interface{}:
		// Accept the case when VP does not have any VCs.
		if len(cred) == 0 {
			return nil, nil
		}

		// 1 or more credentials
		creds := make([]*Credential, len(cred))

		for i := range cred {
			c, err := unmarshalSingleCredFn(cred[i])
			if err != nil {
				return nil, err
			}

			creds[i] = c
		}

		return creds, nil
	default:
		// single credential
		c, err := unmarshalSingleCredFn(cred)
		if err != nil {
			return nil, err
		}

		return []*Credential{c}, nil
	}
}

func validateVP(data rawPresentation, opts *presentationOpts) error {
	err := validateVPJSONSchema(data)
	if err != nil {
		return err
	}

	if opts.disableJSONLDChecks {
		return nil
	}

	return validateVPJSONLD(data, opts)
}

func validateVPJSONLD(vpBytes rawPresentation, opts *presentationOpts) error {
	return docjsonld.ValidateJSONLDMap(vpBytes,
		docjsonld.WithDocumentLoader(opts.jsonldCredentialOpts.jsonldDocumentLoader),
		docjsonld.WithExternalContext(opts.jsonldCredentialOpts.externalContext),
		docjsonld.WithStrictValidation(opts.strictValidation),
	)
}

func validateVPJSONSchema(data rawPresentation) error {
	validate := func(schemaLoader gojsonschema.JSONLoader, data rawPresentation) error {
		loader := gojsonschema.NewGoLoader(data)

		result, err := gojsonschema.Validate(schemaLoader, loader)
		if err != nil {
			return fmt.Errorf("validation of verifiable credential: %w", err)
		}

		if !result.Valid() {
			errMsg := describeSchemaValidationError(result, "verifiable presentation")
			return errors.New(errMsg)
		}

		return nil
	}

	baseContext, err := GetBaseContextFromRawDocument(data)
	if err != nil {
		return err
	}

	switch baseContext {
	case V1ContextURI:
		return validate(v1BasePresentationSchemaLoader, data)
	case V2ContextURI:
		return validate(v2BasePresentationSchemaLoader, data)
	default:
		return fmt.Errorf("unsupported verifiable presentation context: %s", baseContext)
	}
}

func decodeVPFromJSON(vpData []byte) (rawPresentation, error) {
	// unmarshal VP from JSON
	var raw rawPresentation

	err := json.Unmarshal(vpData, &raw)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshalling of verifiable presentation: %w", err)
	}

	return raw, nil
}

func defaultPresentationOpts() *presentationOpts {
	return &presentationOpts{
		verifyDataIntegrity: &verifyDataIntegrityOpts{},
	}
}
