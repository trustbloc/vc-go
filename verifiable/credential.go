/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	jsonld "github.com/piprate/json-gold/ld"
	"github.com/trustbloc/did-go/doc/ld/processor"
	"github.com/trustbloc/did-go/doc/ld/proof"
	docjsonld "github.com/trustbloc/did-go/doc/ld/validator"
	"github.com/trustbloc/kms-go/doc/jose"
	"github.com/veraison/go-cose"
	"github.com/xeipuuv/gojsonschema"

	util "github.com/trustbloc/did-go/doc/util/time"

	"github.com/trustbloc/vc-go/cwt"
	"github.com/trustbloc/vc-go/dataintegrity"
	"github.com/trustbloc/vc-go/jwt"
	"github.com/trustbloc/vc-go/sdjwt/common"
	jsonutil "github.com/trustbloc/vc-go/util/json"
	cwt2 "github.com/trustbloc/vc-go/verifiable/cwt"
	"github.com/trustbloc/vc-go/verifiable/lddocument"
)

var errLogger = log.New(os.Stderr, " [vc-go/verifiable] ", log.Ldate|log.Ltime|log.LUTC)

const (
	schemaPropertyType              = "type"
	schemaPropertyCredentialSubject = "credentialSubject"
	schemaPropertyIssuer            = "issuer"
	schemaPropertyIssuanceDate      = "issuanceDate"

	jsonLDStructureErrStr = "JSON-LD doc has different structure after compaction"
)

// DefaultSchemaTemplate describes default schema.
const DefaultSchemaTemplate = `{
  "required": [
    "@context"
    %s    
  ],
  "properties": {
    "@context": {
      "anyOf": [
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
            "anyOf": [
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
            "pattern": "^VerifiableCredential$"
          }
        },
        {
          "type": "string",
          "pattern": "^VerifiableCredential$"
        }
      ]
    },
    "credentialSubject": {
      "anyOf": [
        {
          "type": "array"
        },
        {
          "type": "object"
        },
        {
          "type": "string"
        }
      ]
    },
    "issuer": {
      "anyOf": [
        {
          "type": "string",
          "format": "uri"
        },
        {
          "type": "object",
          "required": [
            "id"
          ],
          "properties": {
            "id": {
              "type": "string",
              "format": "uri"
            }
          }
        }
      ]
    },
    "issuanceDate": {
      "type": "string",
      "format": "date-time"
    },
    "proof": {
      "anyOf": [
        {
          "$ref": "#/definitions/proof"
        },
        {
          "type": "array",
          "items": {
            "$ref": "#/definitions/proof"
          }
        },
        {
          "type": "null"
        }
      ]
    },
    "expirationDate": {
      "type": [
        "string",
        "null"
      ],
      "format": "date-time"
    },
    "credentialStatus": {
      "$ref": "#/definitions/typedID"
    },
    "credentialSchema": {
      "$ref": "#/definitions/typedIDs"
    },
    "evidence": {
      "$ref": "#/definitions/typedIDs"
    },
    "refreshService": {
      "$ref": "#/definitions/typedID"
    }
  },
  "definitions": {
    "typedID": {
      "anyOf": [
        {
          "type": "null"
        },
        {
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
        }
      ]
    },
    "typedIDs": {
      "anyOf": [
        {
          "$ref": "#/definitions/typedID"
        },
        {
          "type": "array",
          "items": {
            "$ref": "#/definitions/typedID"
          }
        },
        {
          "type": "null"
        }
      ]
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

// https://www.w3.org/TR/vc-data-model/#data-schemas
const jsonSchema2018Type = "JsonSchemaValidator2018"

const (
	// https://www.w3.org/TR/vc-data-model/#base-context
	baseContext = "https://www.w3.org/2018/credentials/v1"

	// https://www.w3.org/TR/vc-data-model/#types
	vcType = "VerifiableCredential"

	// https://www.w3.org/TR/vc-data-model/#presentations-0
	vpType = "VerifiablePresentation"
)

// vcModelValidationMode defines constraint put on context and type of VC.
type vcModelValidationMode int

const (
	// combinedValidation when set it makes JSON validation using JSON Schema and JSON-LD validation.
	//
	// JSON validation verifies the format of the fields and the presence of
	// mandatory fields. It can also decline VC with field(s) not defined in the schema if
	// additionalProperties=true is configured in that schema. To enable such check for base JSON schema, use
	// WithStrictValidation() option.
	//
	// JSON-LD validation is applied when there is more than one (base) context defined. In this case,
	// JSON-LD parser can load machine-readable vocabularies used to describe information in the data model.
	// In JSON-LD schemas, it's not possible to define custom mandatory fields. A possibility to decline
	// JSON document with field(s) not defined in any of JSON-LD schema is built on top of JSON-LD parser and is
	// enabled using WithStrictValidation().
	//
	// This is a default validation mode.
	combinedValidation vcModelValidationMode = iota

	// jsonldValidation when set it uses JSON-LD parser for validation.
	jsonldValidation

	// baseContextValidation when defined it's validated that only the fields and values (when applicable)
	// are present in the document. No extra fields are allowed (outside of credentialSubject).
	baseContextValidation

	// baseContextExtendedValidation when set it's validated that fields that are specified in base context are
	// as specified. Additional fields are allowed.
	baseContextExtendedValidation
)

// SchemaCache defines a cache of credential schemas.
type SchemaCache interface {

	// Put element to the cache.
	Put(k string, v []byte)

	// Get element from the cache, returns false at second return value if element is not present.
	Get(k string) ([]byte, bool)
}

// cache defines a cache interface.
type cache interface {
	Set(k, v []byte)

	HasGet(dst, k []byte) ([]byte, bool)

	Del(k []byte)
}

// ExpirableSchemaCache is an implementation of SchemaCache based fastcache.Cache with expirable elements.
type ExpirableSchemaCache struct {
	cache      cache
	expiration time.Duration
}

// CredentialSchemaLoader defines expirable cache.
type CredentialSchemaLoader struct {
	schemaDownloadClient *http.Client
	cache                SchemaCache
	jsonLoader           gojsonschema.JSONLoader
}

// CredentialSchemaLoaderBuilder defines a builder of CredentialSchemaLoader.
type CredentialSchemaLoaderBuilder struct {
	loader *CredentialSchemaLoader
}

// NewCredentialSchemaLoaderBuilder creates a new instance of CredentialSchemaLoaderBuilder.
func NewCredentialSchemaLoaderBuilder() *CredentialSchemaLoaderBuilder {
	return &CredentialSchemaLoaderBuilder{
		loader: &CredentialSchemaLoader{},
	}
}

// SetSchemaDownloadClient sets HTTP client to be used to download the schema.
func (b *CredentialSchemaLoaderBuilder) SetSchemaDownloadClient(client *http.Client) *CredentialSchemaLoaderBuilder {
	b.loader.schemaDownloadClient = client
	return b
}

// SetCache defines SchemaCache.
func (b *CredentialSchemaLoaderBuilder) SetCache(cache SchemaCache) *CredentialSchemaLoaderBuilder {
	b.loader.cache = cache
	return b
}

// SetJSONLoader defines gojsonschema.JSONLoader.
func (b *CredentialSchemaLoaderBuilder) SetJSONLoader(loader gojsonschema.JSONLoader) *CredentialSchemaLoaderBuilder {
	b.loader.jsonLoader = loader
	return b
}

// Build constructed CredentialSchemaLoader.
// It creates default HTTP client and JSON schema loader if not defined.
func (b *CredentialSchemaLoaderBuilder) Build() *CredentialSchemaLoader {
	l := b.loader

	if l.schemaDownloadClient == nil {
		l.schemaDownloadClient = &http.Client{}
	}

	if l.jsonLoader == nil {
		l.jsonLoader = defaultSchemaLoader()
	}

	return l
}

// Put element to the cache. It also adds a mark of when the element will expire.
func (sc *ExpirableSchemaCache) Put(k string, v []byte) {
	expires := time.Now().Add(sc.expiration).Unix()

	const numBytesTime = 8

	b := make([]byte, numBytesTime)
	binary.LittleEndian.PutUint64(b, uint64(expires))

	ve := make([]byte, numBytesTime+len(v))
	copy(ve[:numBytesTime], b)
	copy(ve[numBytesTime:], v)

	sc.cache.Set([]byte(k), ve)
}

// Get element from the cache. If element is present, it checks if the element is expired.
// If yes, it clears the element from the cache and indicates that the key is not found.
func (sc *ExpirableSchemaCache) Get(k string) ([]byte, bool) {
	b, ok := sc.cache.HasGet(nil, []byte(k))
	if !ok {
		return nil, false
	}

	const numBytesTime = 8

	expires := int64(binary.LittleEndian.Uint64(b[:numBytesTime]))
	if expires < time.Now().Unix() {
		// cache expires
		sc.cache.Del([]byte(k))
		return nil, false
	}

	return b[numBytesTime:], true
}

// Evidence defines evidence of Verifiable Credential.
type Evidence interface{}

const (
	jsonFldIssuerID = "id"
)

// Issuer of the Verifiable Credential.
type Issuer struct {
	ID string `json:"id,omitempty"`

	CustomFields CustomFields `json:"-"`
}

// IssuerToJSON converts issuer to raw json object.
func IssuerToJSON(issuer Issuer) JSONObject {
	jsonObj := jsonutil.ShallowCopyObj(issuer.CustomFields)

	if issuer.ID != "" {
		jsonObj[jsonFldIssuerID] = issuer.ID
	}

	return jsonObj
}

// IssuerFromJSON creates issuer from raw json object.
func IssuerFromJSON(issuerObj JSONObject) (*Issuer, error) {
	flds, rest := jsonutil.SplitJSONObj(issuerObj, jsonFldIssuerID)

	id, err := parseStringFld(flds, jsonFldIssuerID)
	if err != nil {
		return nil, fmt.Errorf("fill issuer id from raw: %w", err)
	}

	if id == "" {
		return nil, errors.New("issuer ID is not defined")
	}

	return &Issuer{
		ID:           id,
		CustomFields: rest,
	}, nil
}

const (
	jsonFldSubjectID = "id"
)

// Subject of the Verifiable Credential.
type Subject struct {
	ID string `json:"id,omitempty"`

	CustomFields CustomFields `json:"-"`
}

// SubjectToJSON converts credential subject to json object.
func SubjectToJSON(subject Subject) JSONObject {
	jsonObj := jsonutil.ShallowCopyObj(subject.CustomFields)

	if subject.ID != "" {
		jsonObj[jsonFldSubjectID] = subject.ID
	}

	return jsonObj
}

// SubjectFromJSON creates credential subject form json object.
func SubjectFromJSON(subjectObj JSONObject) (Subject, error) {
	flds, rest := jsonutil.SplitJSONObj(subjectObj, jsonFldSubjectID)

	id, err := parseStringFld(flds, jsonFldSubjectID)
	if err != nil {
		return Subject{}, fmt.Errorf("fill subject id from raw: %w", err)
	}

	return Subject{
		ID:           id,
		CustomFields: rest,
	}, nil
}

// CredentialContents store credential contents as typed structure.
type CredentialContents struct {
	Context        []string
	CustomContext  []interface{}
	ID             string
	Types          []string
	Subject        []Subject
	Issuer         *Issuer
	Issued         *util.TimeWrapper
	Expired        *util.TimeWrapper
	Status         *TypedID
	Schemas        []TypedID
	Evidence       Evidence
	TermsOfUse     []TypedID
	RefreshService *RefreshService
	SDJWTHashAlg   *crypto.Hash
}

// JSONObject used to store json object.
type JSONObject = map[string]interface{}

// Credential Verifiable Credential definition.
type Credential struct {
	// credentialJSON contains vc as json object. For json-ld vc this will be original json object.
	// For jwt vc it will be jwt claims json object.
	credentialJSON     JSONObject
	credentialContents CredentialContents
	ldProofs           []Proof
	//TODO: make this private. Currently used in tests to create invalid jwt vc's.
	JWTEnvelope *JWTEnvelope
	CWTEnvelope *CWTEnvelope
}

// JWTEnvelope contains information about JWT that envelops credential.
type JWTEnvelope struct {
	JWT        string
	JWTHeaders jose.Headers

	SDJWTVersion     common.SDJWTVersion
	SDJWTDisclosures []*common.DisclosureClaim
	SDHolderBinding  string
}

// CWTEnvelope contains information about CWT that envelops credential.
type CWTEnvelope struct {
	Sign1MessageRaw    []byte
	Sign1MessageParsed *cose.Sign1Message
}

// Contents returns credential contents as typed structure.
func (vc *Credential) Contents() CredentialContents {
	// TODO: consider deep copy
	return vc.credentialContents
}

// ToRawJSON return vc as json object. For json-ld vc this will be original json object.
// For jwt vc it will be jwt claims json object.
func (vc *Credential) ToRawJSON() JSONObject {
	// TODO: consider deep copy
	raw := jsonutil.ShallowCopyObj(vc.credentialJSON)

	if len(vc.ldProofs) > 0 {
		raw[jsonFldLDProof] = proofsToRaw(vc.ldProofs)
	}

	return raw
}

// ToJWTString returns vc as a jwt string. Works only for jwt vc, in other case returns error.
func (vc *Credential) ToJWTString() (string, error) {
	if !vc.IsJWT() {
		return "", errors.New("to jwt string can be called only for jwt vc")
	}

	if vc.credentialContents.SDJWTHashAlg != nil {
		sdJWT, err := vc.MarshalWithDisclosure(DiscloseAll())
		if err != nil {
			return "", err
		}

		return sdJWT, nil
	}

	// If vc.JWTEnvelope exists, marshal only the JWT, since all other values should be unchanged
	// from when the JWT was parsed.
	return vc.JWTEnvelope.JWT, nil
}

// ToUniversalForm returns vc in its natural form. For jwt-vc it is a jwt string. For json-ld vc it is a json object.
func (vc *Credential) ToUniversalForm() (interface{}, error) {
	if vc.IsCWT() {
		return vc.MarshalAsCWTLDHex()
	}

	if vc.IsJWT() {
		jwtStr, err := vc.ToJWTString()
		if err != nil {
			return nil, fmt.Errorf("converting to universal form: %w", err)
		}

		return jwtStr, nil
	}

	return vc.ToRawJSON(), nil
}

// Proofs returns json-ld and data integrity proofs.
func (vc *Credential) Proofs() []Proof {
	return vc.ldProofs
}

// IsJWT returns is vc envelop into jwt.
func (vc *Credential) IsJWT() bool {
	return vc.JWTEnvelope != nil
}

// IsCWT returns is vc envelop into cwt.
func (vc *Credential) IsCWT() bool {
	return vc.CWTEnvelope != nil
}

// JWTHeaders returns jwt headers for jwt-vc.
func (vc *Credential) JWTHeaders() jose.Headers {
	if vc.JWTEnvelope == nil {
		return nil
	}

	return vc.JWTEnvelope.JWTHeaders
}

// SDJWTDisclosures returns sd disclosures for sdjwt.
func (vc *Credential) SDJWTDisclosures() []*common.DisclosureClaim {
	if vc.JWTEnvelope == nil {
		return nil
	}

	return vc.JWTEnvelope.SDJWTDisclosures
}

// SetSDJWTDisclosures sets sd disclosures for sdjwt.
func (vc *Credential) SetSDJWTDisclosures(disclosures []*common.DisclosureClaim) error {
	if vc.JWTEnvelope == nil {
		return fmt.Errorf("non jws credentials not support sd jwt disclosure")
	}

	vc.JWTEnvelope.SDJWTDisclosures = disclosures

	return nil
}

// CustomField returns custom field by name.
func (vc *Credential) CustomField(name string) interface{} {
	return vc.credentialJSON[name]
}

const (
	jsonFldContext        = "@context"
	jsonFldID             = "id"
	jsonFldType           = "type"
	jsonFldSubject        = "credentialSubject"
	jsonFldIssued         = "issuanceDate"
	jsonFldExpired        = "expirationDate"
	jsonFldLDProof        = "proof"
	jsonFldStatus         = "credentialStatus"
	jsonFldIssuer         = "issuer"
	jsonFldSchema         = "credentialSchema"
	jsonFldEvidence       = "evidence"
	jsonFldTermsOfUse     = "termsOfUse"
	jsonFldRefreshService = "refreshService"
	jsonFldSDJWTHashAlg   = "_sd_alg"
)

// CombinedProofChecker universal proof checker for both LD and JWT proofs.
type CombinedProofChecker interface {
	CheckLDProof(proof *proof.Proof, expectedProofIssuer string, msg, signature []byte) error

	// GetLDPCanonicalDocument will return normalized/canonical version of the document
	GetLDPCanonicalDocument(proof *proof.Proof, doc map[string]interface{}, opts ...processor.Opts) ([]byte, error)

	// GetLDPDigest returns document digest
	GetLDPDigest(proof *proof.Proof, doc []byte) ([]byte, error)

	CheckJWTProof(headers jose.Headers, expectedProofIssuer string, msg, signature []byte) error

	cwt.ProofChecker
}

// CredentialDecoder makes a custom decoding of Verifiable Credential in JSON form to existent
// instance of Credential.
type CredentialDecoder func(dataJSON []byte, vc *Credential) error

// CredentialTemplate defines a factory method to create new Credential template.
type CredentialTemplate func() *Credential

// credentialOpts holds options for the Verifiable Credential decoding.
type credentialOpts struct {
	ldProofChecker        lddocument.ProofChecker
	jwtProofChecker       jwt.ProofChecker
	cwtProofChecker       cwt.ProofChecker
	disabledCustomSchema  bool
	schemaLoader          *CredentialSchemaLoader
	modelValidationMode   vcModelValidationMode
	allowedCustomContexts map[string]bool
	allowedCustomTypes    map[string]bool
	disabledProofCheck    bool
	strictValidation      bool
	defaultSchema         string
	disableValidation     bool
	verifyDataIntegrity   *verifyDataIntegrityOpts

	jsonldCredentialOpts
}

// CredentialOpt is the Verifiable Credential decoding option.
type CredentialOpt func(opts *credentialOpts)

// WithDisabledProofCheck option for disabling of proof check.
func WithDisabledProofCheck() CredentialOpt {
	return func(opts *credentialOpts) {
		opts.disabledProofCheck = true
	}
}

// WithCredDisableValidation options for disabling of JSON-LD and json-schema validation.
func WithCredDisableValidation() CredentialOpt {
	return func(opts *credentialOpts) {
		opts.disableValidation = true
	}
}

// WithSchema option to set custom schema.
func WithSchema(schema string) CredentialOpt {
	return func(opts *credentialOpts) {
		opts.defaultSchema = schema
	}
}

// WithNoCustomSchemaCheck option is for disabling of Credential Schemas download if defined
// in Verifiable Credential. Instead, the Verifiable Credential is checked against default Schema.
func WithNoCustomSchemaCheck() CredentialOpt {
	return func(opts *credentialOpts) {
		opts.disabledCustomSchema = true
	}
}

// WithProofChecker set proofChecker that used for validation of ldp-vc and jwt proof.
func WithProofChecker(verifier CombinedProofChecker) CredentialOpt {
	return func(opts *credentialOpts) {
		opts.jwtProofChecker = verifier
		opts.ldProofChecker = verifier
		opts.cwtProofChecker = verifier
	}
}

// WithLDProofChecker set proofChecker that used for validation of ldp-vc proof.
func WithLDProofChecker(verifier lddocument.ProofChecker) CredentialOpt {
	return func(opts *credentialOpts) {
		opts.ldProofChecker = verifier
	}
}

// WithJWTProofChecker set proofChecker that used for validation of jwt proof.
func WithJWTProofChecker(verifier jwt.ProofChecker) CredentialOpt {
	return func(opts *credentialOpts) {
		opts.jwtProofChecker = verifier
	}
}

// WithCWTProofChecker set proofChecker that used for validation of cwt proof.
func WithCWTProofChecker(verifier cwt.ProofChecker) CredentialOpt {
	return func(opts *credentialOpts) {
		opts.cwtProofChecker = verifier
	}
}

// WithCredentialSchemaLoader option is used to define custom credentials schema loader.
// If not defined, the default one is created with default HTTP client to download the schema
// and no caching of the schemas.
func WithCredentialSchemaLoader(loader *CredentialSchemaLoader) CredentialOpt {
	return func(opts *credentialOpts) {
		opts.schemaLoader = loader
	}
}

// WithJSONLDValidation uses the JSON LD parser for validation.
func WithJSONLDValidation() CredentialOpt {
	return func(opts *credentialOpts) {
		opts.modelValidationMode = jsonldValidation
	}
}

// WithBaseContextValidation validates that only the fields and values (when applicable) are present
// in the document. No extra fields are allowed (outside of credentialSubject).
func WithBaseContextValidation() CredentialOpt {
	return func(opts *credentialOpts) {
		opts.modelValidationMode = baseContextValidation
	}
}

// WithDataIntegrityVerifier provides the Data Integrity verifier to use when
// the credential being processed has a Data Integrity proof.
func WithDataIntegrityVerifier(v *dataintegrity.Verifier) CredentialOpt {
	return func(opts *credentialOpts) {
		opts.verifyDataIntegrity.Verifier = v
	}
}

// WithExpectedDataIntegrityFields validates that a Data Integrity proof has the
// given purpose, domain, and challenge. Empty purpose means the default,
// assertionMethod, will be expected. Empty domain and challenge will mean they
// are not checked.
func WithExpectedDataIntegrityFields(purpose, domain, challenge string) CredentialOpt {
	return func(opts *credentialOpts) {
		opts.verifyDataIntegrity.Purpose = purpose
		opts.verifyDataIntegrity.Domain = domain
		opts.verifyDataIntegrity.Challenge = challenge
	}
}

// WithBaseContextExtendedValidation validates that fields that are specified in base context are as specified.
// Additional fields are allowed.
func WithBaseContextExtendedValidation(customContexts, customTypes []string) CredentialOpt {
	return func(opts *credentialOpts) {
		opts.modelValidationMode = baseContextExtendedValidation

		opts.allowedCustomContexts = make(map[string]bool)
		for _, context := range customContexts {
			opts.allowedCustomContexts[context] = true
		}

		opts.allowedCustomContexts[baseContext] = true

		opts.allowedCustomTypes = make(map[string]bool)
		for _, context := range customTypes {
			opts.allowedCustomTypes[context] = true
		}

		opts.allowedCustomTypes[vcType] = true
	}
}

// WithJSONLDDocumentLoader defines a JSON-LD document loader.
func WithJSONLDDocumentLoader(documentLoader jsonld.DocumentLoader) CredentialOpt {
	return func(opts *credentialOpts) {
		opts.jsonldDocumentLoader = documentLoader
	}
}

// WithStrictValidation enabled strict validation of VC.
//
// In case of JSON Schema validation, additionalProperties=true is set on the schema.
//
// In case of JSON-LD validation, the comparison of JSON-LD VC document after compaction with original VC one is made.
// In case of mismatch a validation exception is raised.
func WithStrictValidation() CredentialOpt {
	return func(opts *credentialOpts) {
		opts.strictValidation = true
	}
}

// WithExternalJSONLDContext defines external JSON-LD contexts to be used in JSON-LD validation and
// Linked Data Signatures verification.
func WithExternalJSONLDContext(context ...string) CredentialOpt {
	return func(opts *credentialOpts) {
		opts.externalContext = context
	}
}

// WithJSONLDOnlyValidRDF indicates the need to remove all invalid RDF dataset from normalize document
// when verifying linked data signatures of verifiable credential.
func WithJSONLDOnlyValidRDF() CredentialOpt {
	return func(opts *credentialOpts) {
		opts.jsonldOnlyValidRDF = true
	}
}

// parseIssuer parses raw issuer.
//
// Issuer can be defined by:
//
// - a string which is ID of the issuer;
//
// - object with mandatory "id" field and optional "name" field.
func parseIssuer(issuerRaw interface{}) (*Issuer, error) {
	if issuerRaw == nil {
		return nil, nil
	}

	switch issuer := issuerRaw.(type) {
	case string:
		if issuer == "" {
			return nil, errors.New("issuer ID is not defined")
		}

		return &Issuer{ID: issuer}, nil
	case map[string]interface{}:
		return IssuerFromJSON(issuer)
	}

	return nil, fmt.Errorf("should be json object or string but got %v", issuerRaw)
}

func serializeIssuer(issuer Issuer) interface{} {
	if len(issuer.CustomFields) == 0 {
		return issuer.ID
	}

	return IssuerToJSON(issuer)
}

// parseSubject parses raw credential subject.
//
// Subject can be defined as a string (subject ID) or single object or array of objects.
func parseSubject(subjectRaw interface{}) ([]Subject, error) {
	if subjectRaw == nil {
		return nil, nil
	}

	switch subject := subjectRaw.(type) {
	case string:
		return []Subject{{ID: subject}}, nil
	case map[string]interface{}:
		parsed, err := SubjectFromJSON(subject)
		if err != nil {
			return nil, fmt.Errorf("parse subject: %w", err)
		}

		return []Subject{parsed}, nil
	case []interface{}:
		var subjects []Subject

		for _, raw := range subject {
			sub, ok := raw.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("verifiable credential subject of unsupported format")
			}

			parsed, err := SubjectFromJSON(sub)
			if err != nil {
				return nil, fmt.Errorf("parse subjects array: %w", err)
			}

			subjects = append(subjects, parsed)
		}

		return subjects, nil
	}

	return nil, fmt.Errorf("verifiable credential subject of unsupported format")
}

// decodeCredentialSchemas decodes credential schema(s).
//
// credential schema can be defined as a single object or array of objects.
func decodeCredentialSchemas(schema interface{}) ([]TypedID, error) {
	return parseTypedID(schema)
}

// CreateCredential creates vc from CredentialContents.
func CreateCredential(vcc CredentialContents, customFields CustomFields) (*Credential, error) {
	vcJSON, err := serializeCredentialContents(&vcc, nil)
	if err != nil {
		return nil, fmt.Errorf("converting credential contents: %w", err)
	}

	jsonutil.AddCustomFields(vcJSON, customFields)

	return &Credential{
		credentialJSON:     vcJSON,
		credentialContents: vcc,
	}, nil
}

// CreateCredentialWithProofs creates vc from CredentialContents, with provided proofs.
func CreateCredentialWithProofs(vcc CredentialContents, customFields CustomFields,
	proofs []Proof) (*Credential, error) {
	vcJSON, err := serializeCredentialContents(&vcc, proofs)
	if err != nil {
		return nil, fmt.Errorf("converting credential contents: %w", err)
	}

	jsonutil.AddCustomFields(vcJSON, customFields)

	return &Credential{
		credentialJSON:     vcJSON,
		credentialContents: vcc,
		ldProofs:           proofs,
	}, nil
}

// ParseCredentialJSON parses Verifiable Credential from json-ld object.
func ParseCredentialJSON(vcJSON JSONObject, opts ...CredentialOpt) (*Credential, error) {
	vcOpts := getCredentialOpts(opts)

	ldProofs, err := parseLDProof(vcJSON[jsonFldLDProof])
	if err != nil {
		return nil, fmt.Errorf("fill credential proof from raw: %w", err)
	}

	contents, err := parseCredentialContents(vcJSON, false)
	if err != nil {
		return nil, err
	}

	if !vcOpts.disableValidation {
		err = validateCredential(contents, vcJSON, vcOpts)
		if err != nil {
			return nil, err
		}
	}

	return &Credential{
		credentialJSON:     vcJSON,
		credentialContents: *contents,
		ldProofs:           ldProofs,
	}, nil
}

// ParseCredential parses Verifiable Credential from bytes which could be marshalled JSON or serialized JWT.
// It also applies miscellaneous options like settings of schema validation.
// It returns decoded Credential.
func ParseCredential(vcData []byte, opts ...CredentialOpt) (*Credential, error) { // nolint:funlen,gocyclo
	// Apply options.
	vcOpts := getCredentialOpts(opts)

	parsers := []CredentialParser{
		&CredentialJSONParser{},
		&CredentialCBORParser{},
	}

	var finalErr error
	var vc *Credential
	var err error

	for _, parser := range parsers {
		vc, err = parser.Parse(vcData, vcOpts)

		if err != nil {
			if strings.HasPrefix(err.Error(), jsonLDStructureErrStr) {
				return nil, err
			}

			finalErr = errors.Join(finalErr, err)
		}

		if vc != nil {
			break
		}
	}

	if vc == nil {
		return nil, finalErr
	}

	if !vcOpts.disabledProofCheck {
		err = vc.CheckProof(opts...)
		if err != nil {
			return nil, err
		}
	}

	return vc, nil
}

func validateDisclosures(vcBytes []byte, disclosures []string) error {
	if len(disclosures) == 0 {
		return nil
	}

	vcPayload := &jwt.JSONWebToken{}

	err := json.Unmarshal(vcBytes, &vcPayload.Payload)
	if err != nil {
		return fmt.Errorf("decode credential for sdjwt: %w", err)
	}

	if _, hasSDAlg := vcPayload.Payload["_sd_alg"]; !hasSDAlg {
		subjSDAlg, hasSubjSDAlg := vcPayload.Payload["credentialSubject"].(map[string]interface{})["_sd_alg"]
		if hasSubjSDAlg {
			vcPayload.Payload["_sd_alg"] = subjSDAlg
		}
	}

	err = common.VerifyDisclosuresInSDJWT(disclosures, vcPayload)
	if err != nil {
		return fmt.Errorf("invalid SDJWT disclosures: %w", err)
	}

	return nil
}

func parseCredentialJSON(vcJSON []byte) (JSONObject, error) {
	// Unmarshal raw credential from JSON.
	var raw JSONObject

	err := json.Unmarshal(vcJSON, &raw)
	if err != nil {
		return nil, fmt.Errorf("unmarshal new credential: %w", err)
	}

	return raw, nil
}

// ValidateCredential validate both ld and jwt credentials. WithCredDisableValidation is ignored.
func (vc *Credential) ValidateCredential(opts ...CredentialOpt) error {
	vcOpts := getCredentialOpts(opts)

	return validateCredential(&vc.credentialContents, vc.credentialJSON, vcOpts)
}

func validateCredential(vcc *CredentialContents, vcJSON JSONObject, vcOpts *credentialOpts) error {
	// Credential and type constraint.
	switch vcOpts.modelValidationMode {
	case combinedValidation:
		// TODO Validation mechanism will be changed after completing of #968 and #976
		// Validate VC using JSON schema. Even in case of VC data model extension (i.e. more than one @context
		// is defined and thus JSON-LD validation is made), it's reasonable to do JSON Schema validation
		// prior to the JSON-LD one as the former does not check several aspects like mandatory fields or fields format.
		err := validateJSONSchema(vcJSON, vcc, vcOpts)
		if err != nil {
			return err
		}

		return validateJSONLD(vcJSON, vcOpts)

	case jsonldValidation:
		return validateJSONLD(vcJSON, vcOpts)

	case baseContextValidation:
		return validateBaseContext(vcJSON, vcc, vcOpts)

	case baseContextExtendedValidation:
		return validateBaseContextWithExtendedValidation(vcJSON, vcc, vcOpts)

	default:
		return fmt.Errorf("unsupported vcModelValidationMode: %v", vcOpts.modelValidationMode)
	}
}

func validateBaseContext(vcJSON JSONObject, vcc *CredentialContents, vcOpts *credentialOpts) error {
	if len(vcc.Types) > 1 || vcc.Types[0] != vcType {
		return errors.New("violated type constraint: not base only type defined")
	}

	if len(vcc.Context) > 1 || vcc.Context[0] != baseContext {
		return errors.New("violated @context constraint: not base only @context defined")
	}

	return validateJSONSchema(vcJSON, vcc, vcOpts)
}

func validateBaseContextWithExtendedValidation(vcJSON JSONObject, vcc *CredentialContents,
	vcOpts *credentialOpts) error {
	for _, vcContext := range vcc.Context {
		if _, ok := vcOpts.allowedCustomContexts[vcContext]; !ok {
			return fmt.Errorf("not allowed @context: %s", vcContext)
		}
	}

	for _, vcType := range vcc.Types {
		if _, ok := vcOpts.allowedCustomTypes[vcType]; !ok {
			return fmt.Errorf("not allowed type: %s", vcType)
		}
	}

	return validateJSONSchema(vcJSON, vcc, vcOpts)
}

func validateJSONLD(vcJSON JSONObject, vcOpts *credentialOpts) error {
	// TODO: docjsonld.ValidateJSONLDMap has bug that it modify contexts of input vcJSON. Fix in did-go
	return docjsonld.ValidateJSONLDMap(jsonutil.ShallowCopyObj(vcJSON),
		docjsonld.WithDocumentLoader(vcOpts.jsonldCredentialOpts.jsonldDocumentLoader),
		docjsonld.WithExternalContext(vcOpts.jsonldCredentialOpts.externalContext),
		docjsonld.WithStrictValidation(vcOpts.strictValidation),
		docjsonld.WithStrictContextURIPosition(baseContext),
	)
}

// nolint: funlen,gocyclo
func parseCredentialContents(raw JSONObject, isSDJWT bool) (*CredentialContents, error) {
	var schemas []TypedID

	rawSchemas := raw[jsonFldSchema]
	if rawSchemas != nil {
		var err error

		schemas, err = decodeCredentialSchemas(rawSchemas)
		if err != nil {
			return nil, fmt.Errorf("fill credential schemas from raw: %w", err)
		}
	} else {
		schemas = make([]TypedID, 0)
	}

	types, err := decodeType(raw[jsonFldType])
	if err != nil {
		return nil, fmt.Errorf("fill credential types from raw: %w", err)
	}

	issuer, err := parseIssuer(raw[jsonFldIssuer])
	if err != nil {
		return nil, fmt.Errorf("fill credential issuer from raw: %w", err)
	}

	context, customContext, err := decodeContext(raw[jsonFldContext])
	if err != nil {
		return nil, fmt.Errorf("fill credential context from raw: %w", err)
	}

	termsOfUse, err := parseTypedID(raw[jsonFldTermsOfUse])
	if err != nil {
		return nil, fmt.Errorf("fill credential terms of use from raw: %w", err)
	}

	refreshService, err := parseRefreshService(raw[jsonFldRefreshService])
	if err != nil {
		return nil, fmt.Errorf("fill credential refresh service from raw: %w", err)
	}

	subjects, err := parseSubject(raw[jsonFldSubject])
	if err != nil {
		return nil, fmt.Errorf("fill credential subject from raw: %w", err)
	}

	sdJWTHashAlgCode, err := parseSDAlg(raw, subjects, isSDJWT)
	if err != nil {
		return nil, fmt.Errorf("fill credential sd jwt alg from raw: %w", err)
	}

	id, err := parseStringFld(raw, jsonFldID)
	if err != nil {
		return nil, fmt.Errorf("fill credential id from raw: %w", err)
	}

	issued, err := parseTimeFld(raw, jsonFldIssued)
	if err != nil {
		return nil, fmt.Errorf("fill credential issued from raw: %w", err)
	}

	expired, err := parseTimeFld(raw, jsonFldExpired)
	if err != nil {
		return nil, fmt.Errorf("fill credential expired from raw: %w", err)
	}

	status, err := newNilableTypedID(raw[jsonFldStatus])
	if err != nil {
		return nil, fmt.Errorf("fill credential status from raw: %w", err)
	}

	return &CredentialContents{
		Context:        context,
		CustomContext:  customContext,
		ID:             id,
		Types:          types,
		Subject:        subjects,
		Issuer:         issuer,
		Issued:         issued,
		Expired:        expired,
		Status:         status,
		Schemas:        schemas,
		Evidence:       raw[jsonFldEvidence],
		TermsOfUse:     termsOfUse,
		RefreshService: refreshService,
		SDJWTHashAlg:   sdJWTHashAlgCode,
	}, nil
}

func parseRefreshService(typeIDRaw interface{}) (*RefreshService, error) {
	typed, err := parseTypedID(typeIDRaw)
	if err != nil {
		return nil, fmt.Errorf("parse refresh service: %w", err)
	}

	if len(typed) == 0 {
		return nil, nil
	}

	urlVal := typed[0].CustomFields[jsonFldTypedURLType]
	delete(typed[0].CustomFields, jsonFldTypedURLType)

	srv := &RefreshService{
		TypedID: typed[0],
		Url:     fmt.Sprint(urlVal),
	}

	return srv, nil
}

func parseTypedID(typeIDRaw interface{}) ([]TypedID, error) {
	if typeIDRaw == nil {
		return nil, nil
	}

	switch typeID := typeIDRaw.(type) {
	case map[string]interface{}:
		parsed, err := parseTypedIDObj(typeID)
		if err != nil {
			return nil, fmt.Errorf("parse type id: %w", err)
		}

		return []TypedID{parsed}, nil
	case []interface{}:
		var typedIDS []TypedID

		for _, s := range typeID {
			json, ok := s.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("slice with typeIDs of unsupported format, %v", typeIDRaw)
			}

			parsed, err := parseTypedIDObj(json)
			if err != nil {
				return nil, fmt.Errorf("parse type ids array: %w", err)
			}

			typedIDS = append(typedIDS, parsed)
		}

		return typedIDS, nil
	}

	return nil, fmt.Errorf("typeID of unsupported format, %v", typeIDRaw)
}

func parseSDAlg(rawCred JSONObject, subjects []Subject, isSDJWT bool) (*crypto.Hash, error) {
	if !isSDJWT {
		return nil, nil
	}

	sdJWTHashAlgStr, err := parseStringFld(rawCred, jsonFldSDJWTHashAlg)
	if err != nil {
		return nil, fmt.Errorf("get %q fld: %w", jsonFldSDJWTHashAlg, err)
	}

	sdJWTHashAlgCode, err := parseSDAlgValue(sdJWTHashAlgStr, subjects)
	if err != nil {
		return nil, fmt.Errorf("parse sd jwt alg string: %w", err)
	}

	return &sdJWTHashAlgCode, nil
}

func parseSDAlgValue(sdJWTHashAlg string, subjects []Subject) (crypto.Hash, error) {
	if sdJWTHashAlg == "" {
		if len(subjects) > 0 && len(subjects[0].CustomFields) > 0 {
			return common.GetCryptoHashFromClaims(subjects[0].CustomFields)
		}
	}

	return common.ParseCryptoHashAlg(sdJWTHashAlg)
}

func parseDisclosures(disclosures []string, hash *crypto.Hash) ([]*common.DisclosureClaim, error) {
	if len(disclosures) == 0 {
		return nil, nil
	}

	if hash == nil {
		return nil, fmt.Errorf("inconsistent state, if selective disclosures are present, sd alg should be set")
	}

	disc, err := common.GetDisclosureClaims(disclosures, *hash)
	if err != nil {
		return nil, fmt.Errorf("parsing disclosures from SD-JWT credential: %w", err)
	}

	return disc, nil
}

type externalJWTVC struct {
	JWT string `json:"jwt,omitempty"`
}

func unQuote(s []byte) []byte {
	if len(s) <= 1 {
		return s
	}

	if s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}

	return s
}

func unwrapStringVC(vcData []byte) string {
	vcStr := string(unQuote(vcData))

	jwtHolder := &externalJWTVC{}
	e := json.Unmarshal(vcData, jwtHolder)

	hasJWT := e == nil && jwtHolder.JWT != ""
	if hasJWT {
		vcStr = jwtHolder.JWT
	}

	return vcStr
}

type jwsVCParseResult struct {
	isJWS   bool
	isSDJWT bool
	// If original JWS is a combined SD-JWT, 'onlyJWT' contains only the JWT part,
	onlyJWT         string
	sdDisclosures   []string
	sdHolderBinding string
}

func tryParseAsJWSVC(vcStr string) jwsVCParseResult {
	var (
		disclosures   []string
		holderBinding string
		isSDJWT       bool
	)

	tmpVCStr := vcStr

	if strings.Contains(tmpVCStr, common.CombinedFormatSeparator) {
		isSDJWT = true
		sdTokens := strings.Split(vcStr, common.CombinedFormatSeparator)
		lastElem := sdTokens[len(sdTokens)-1]

		isPresentation := lastElem == "" || jwt.IsJWS(lastElem)
		if isPresentation {
			cffp := common.ParseCombinedFormatForPresentation(vcStr)

			disclosures = cffp.Disclosures
			tmpVCStr = cffp.SDJWT
			holderBinding = cffp.HolderVerification
		} else {
			cffi := common.ParseCombinedFormatForIssuance(vcStr)
			disclosures = cffi.Disclosures

			tmpVCStr = cffi.SDJWT
		}
	}

	if jwt.IsJWS(tmpVCStr) {
		return jwsVCParseResult{
			isJWS:           true,
			isSDJWT:         isSDJWT,
			onlyJWT:         tmpVCStr,
			sdDisclosures:   disclosures,
			sdHolderBinding: holderBinding,
		}
	}

	return jwsVCParseResult{
		isJWS:           false,
		onlyJWT:         "",
		sdDisclosures:   nil,
		sdHolderBinding: "",
	}
}

// CheckProof checks credential proofs.
func (vc *Credential) CheckProof(opts ...CredentialOpt) error {
	vcOpts := getCredentialOpts(opts)

	if vc.credentialContents.Issuer == nil {
		return fmt.Errorf("proof check failuer: issuer is missed")
	}

	issuerID := vc.credentialContents.Issuer.ID

	if vc.JWTEnvelope != nil {
		if vcOpts.jwtProofChecker == nil {
			return errors.New("jwt proofChecker is not defined")
		}

		err := jwt.CheckProof(vc.JWTEnvelope.JWT, vcOpts.jwtProofChecker, &issuerID, nil)
		if err != nil {
			return fmt.Errorf("JWS proof check: %w", err)
		}

		return nil
	}

	if vc.CWTEnvelope != nil {
		if vcOpts.cwtProofChecker == nil {
			return errors.New("cwt proofChecker is not defined")
		}

		proofValue, err := cwt2.GetProofValue(vc.CWTEnvelope.Sign1MessageParsed)
		if err != nil {
			return err
		}

		err = cwt.CheckProof(
			vc.CWTEnvelope.Sign1MessageParsed,
			vcOpts.cwtProofChecker,
			&issuerID,
			proofValue,
			vc.CWTEnvelope.Sign1MessageParsed.Signature,
		)

		if err != nil {
			return fmt.Errorf("CWT proof check: %w", err)
		}

		return nil
	}

	return checkEmbeddedProof(vc.credentialJSON, &issuerID, getEmbeddedProofCheckOpts(vcOpts))
}

func decodeJWTVC(vcStr string) (jose.Headers, []byte, error) {
	joseHeaders, vcDecodedBytes, err := decodeCredJWT(vcStr)
	if err != nil {
		return nil, nil, fmt.Errorf("JWS decoding: %w", err)
	}

	return joseHeaders, vcDecodedBytes, nil
}

func decodeLDVC(vcData []byte, vcStr string) ([]byte, error) {
	if jwt.IsJWTUnsecured(vcStr) { // Embedded proof.
		var e error

		vcData, e = decodeCredJWTUnsecured(vcStr)
		if e != nil {
			return nil, fmt.Errorf("unsecured JWT decoding: %w", e)
		}
	}

	// Embedded proof.
	return vcData, nil
}

// JWTVCToJSON parses a JWT VC without verifying, and returns the JSON VC contents.
func JWTVCToJSON(vc []byte) ([]byte, error) {
	vc = bytes.Trim(vc, "\"' ")

	_, jsonVC, err := decodeCredJWT(string(vc))

	return jsonVC, err
}

func getEmbeddedProofCheckOpts(vcOpts *credentialOpts) *embeddedProofCheckOpts {
	return &embeddedProofCheckOpts{
		proofChecker:         vcOpts.ldProofChecker,
		disabledProofCheck:   vcOpts.disabledProofCheck,
		jsonldCredentialOpts: vcOpts.jsonldCredentialOpts,
		dataIntegrityOpts:    vcOpts.verifyDataIntegrity,
	}
}

func getCredentialOpts(opts []CredentialOpt) *credentialOpts {
	crOpts := &credentialOpts{
		modelValidationMode: combinedValidation,
		verifyDataIntegrity: &verifyDataIntegrityOpts{},
	}

	for _, opt := range opts {
		opt(crOpts)
	}

	if crOpts.schemaLoader == nil {
		crOpts.schemaLoader = newDefaultSchemaLoader()
	}

	return crOpts
}

func newDefaultSchemaLoader() *CredentialSchemaLoader {
	return &CredentialSchemaLoader{
		schemaDownloadClient: &http.Client{},
		jsonLoader:           defaultSchemaLoader(),
	}
}

// SerializeSubject converts subject(s) JSON object or array
// If the subject is nil no error will be returned.
func SerializeSubject(subject []Subject) interface{} {
	if subject == nil {
		return nil
	}

	if len(subject) == 1 {
		return SubjectToJSON(subject[0])
	}

	return mapSlice(subject, SubjectToJSON)
}

func validateJSONSchema(vcJSON JSONObject, vcc *CredentialContents, opts *credentialOpts) error {
	return validateCredentialUsingJSONSchema(vcJSON, vcc.Schemas, opts)
}

func validateCredentialUsingJSONSchema(vcJSON JSONObject, schemas []TypedID, opts *credentialOpts) error {
	// Validate that the Verifiable Credential conforms to the serialization of the Verifiable Credential data model
	// (https://w3c.github.io/vc-data-model/#example-1-a-simple-example-of-a-verifiable-credential)
	schemaLoader, err := getSchemaLoader(schemas, opts)
	if err != nil {
		return err
	}

	loader := gojsonschema.NewGoLoader(vcJSON)

	result, err := gojsonschema.Validate(schemaLoader, loader)
	if err != nil {
		return fmt.Errorf("validation of verifiable credential: %w", err)
	}

	if !result.Valid() {
		errMsg := describeSchemaValidationError(result, "verifiable credential")
		return errors.New(errMsg)
	}

	return nil
}

func getSchemaLoader(schemas []TypedID, opts *credentialOpts) (gojsonschema.JSONLoader, error) {
	if opts.disabledCustomSchema {
		return defaultSchemaLoaderWithOpts(opts), nil
	}

	for _, schema := range schemas {
		switch schema.Type {
		case jsonSchema2018Type:
			customSchemaData, err := getJSONSchema(schema.ID, opts)
			if err != nil {
				return nil, fmt.Errorf("load of custom credential schema from %s: %w", schema.ID, err)
			}

			return gojsonschema.NewBytesLoader(customSchemaData), nil
		default:
			// TODO: should unsupported schema be ignored or should this cause an error?
			errLogger.Printf("unsupported credential schema: %s. Using default schema for validation", schema.Type)
		}
	}

	// If no custom schema is chosen, use default one
	return defaultSchemaLoaderWithOpts(opts), nil
}

type schemaOpts struct {
	disabledChecks []string
}

// SchemaOpt is create default schema options.
type SchemaOpt func(*schemaOpts)

// WithDisableRequiredField disabled check of required field in default schema.
func WithDisableRequiredField(fieldName string) SchemaOpt {
	return func(opts *schemaOpts) {
		opts.disabledChecks = append(opts.disabledChecks, fieldName)
	}
}

// JSONSchemaLoader creates default schema with the option to disable the check of specific properties.
func JSONSchemaLoader(opts ...SchemaOpt) string {
	defaultRequired := []string{
		schemaPropertyType,
		schemaPropertyCredentialSubject,
		schemaPropertyIssuer,
		schemaPropertyIssuanceDate,
	}

	dsOpts := &schemaOpts{}
	for _, opt := range opts {
		opt(dsOpts)
	}

	required := ""

	for _, prop := range defaultRequired {
		filterOut := false

		for _, d := range dsOpts.disabledChecks {
			if prop == d {
				filterOut = true
				break
			}
		}

		if !filterOut {
			required += fmt.Sprintf(",%q", prop)
		}
	}

	return fmt.Sprintf(DefaultSchemaTemplate, required)
}

func defaultSchemaLoaderWithOpts(opts *credentialOpts) gojsonschema.JSONLoader {
	if opts.defaultSchema != "" {
		return gojsonschema.NewStringLoader(opts.defaultSchema)
	}

	return defaultSchemaLoader()
}

func defaultSchemaLoader() gojsonschema.JSONLoader {
	return gojsonschema.NewStringLoader(JSONSchemaLoader())
}

func getJSONSchema(url string, opts *credentialOpts) ([]byte, error) {
	loader := opts.schemaLoader
	cache := loader.cache

	if cache == nil {
		return loadJSONSchema(url, loader.schemaDownloadClient)
	}

	// Check the cache first.
	if cachedBytes, ok := cache.Get(url); ok {
		return cachedBytes, nil
	}

	schemaBytes, err := loadJSONSchema(url, loader.schemaDownloadClient)
	if err != nil {
		return nil, err
	}

	// Put the loaded schema into cache
	cache.Put(url, schemaBytes)

	return schemaBytes, nil
}

func loadJSONSchema(url string, client *http.Client) ([]byte, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("load credential schema: %w", err)
	}

	defer func() {
		e := resp.Body.Close()
		if e != nil {
			errLogger.Printf("closing response body failed [%v]", e)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("credential schema endpoint HTTP failure [%v]", resp.StatusCode)
	}

	var gotBody []byte

	gotBody, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("credential schema: read response body: %w", err)
	}

	return gotBody, nil
}

// JWTClaims converts Verifiable Credential into JWT Credential claims, which can be than serialized
// e.g. into JWS.
// TODO: review JWT and SDJWT implementation. Do not expose claims externally.
// TODO: JWTClaims not take to account "sub" claim from jwt, should it?
func (vc *Credential) JWTClaims(minimizeVC bool) (*JWTCredClaims, error) {
	return newJWTCredClaims(vc, minimizeVC)
}

// CreateSignedJWTVC envelops current vc into signed jwt.
func (vc *Credential) CreateSignedJWTVC(
	minimizeVC bool,
	signatureAlg JWSAlgorithm,
	proofCreator jwt.ProofCreator,
	keyID string,
) (*Credential, error) {
	jwtClaims, err := vc.JWTClaims(minimizeVC)
	if err != nil {
		return nil, err
	}

	jwsString, joseHeaders, err := jwtClaims.MarshalJWS(signatureAlg, proofCreator, keyID)
	if err != nil {
		return nil, err
	}

	return &Credential{
		credentialJSON:     vc.ToRawJSON(),
		credentialContents: vc.Contents(),
		ldProofs:           vc.ldProofs,
		JWTEnvelope: &JWTEnvelope{
			JWT:        jwsString,
			JWTHeaders: joseHeaders,
		},
	}, nil
}

// CreateSignedCOSEVC envelops current vc into signed COSE.
func (vc *Credential) CreateSignedCOSEVC(
	signatureAlg cose.Algorithm,
	proofCreator cwt.ProofCreator,
	keyID string,
) (*Credential, error) {
	claims, err := vc.CWTClaims()
	if err != nil {
		return nil, err
	}

	msgRaw, msg, err := claims.MarshaCOSE(signatureAlg, proofCreator, keyID)
	if err != nil {
		return nil, err
	}

	return &Credential{
		credentialJSON:     claims.VC,
		credentialContents: vc.Contents(),
		ldProofs:           vc.ldProofs,
		CWTEnvelope: &CWTEnvelope{
			Sign1MessageRaw:    msgRaw,
			Sign1MessageParsed: msg,
		},
	}, nil
}

// CreateUnsecuredJWTVC envelops current vc into unsigned jwt.
func (vc *Credential) CreateUnsecuredJWTVC(minimizeVC bool) (*Credential, error) {
	jwtClaims, err := vc.JWTClaims(minimizeVC)
	if err != nil {
		return nil, err
	}

	jwtString, err := jwtClaims.MarshalUnsecuredJWT()
	if err != nil {
		return nil, fmt.Errorf("limitDisclosure MarshalUnsecuredJWT: %w", err)
	}

	return &Credential{
		credentialJSON:     vc.ToRawJSON(),
		credentialContents: vc.Contents(),
		ldProofs:           vc.ldProofs,
		JWTEnvelope: &JWTEnvelope{
			JWT: jwtString,
		},
	}, nil
}

// SubjectID gets ID of single subject if present or
// returns error if there are several subjects or one without ID defined.
func SubjectID(subject []Subject) (string, error) { //nolint:funlen
	if len(subject) == 0 {
		return "", errors.New("no subject is defined")
	}

	if len(subject) > 1 {
		return "", errors.New("more than one subject is defined")
	}

	if subject[0].ID == "" {
		return "", errors.New("subject id is not defined")
	}

	return subject[0].ID, nil
}

func serializeCredentialContents(vcc *CredentialContents, proofs []Proof) (JSONObject, error) { //nolint:funlen,gocyclo
	contexts := contextToRaw(vcc.Context, vcc.CustomContext)

	vcJSON := map[string]interface{}{}

	if len(contexts) > 0 {
		vcJSON[jsonFldContext] = contexts
	}

	if vcc.ID != "" {
		vcJSON[jsonFldID] = vcc.ID
	}

	if len(vcc.Types) > 0 {
		vcJSON[jsonFldType] = serializeTypes(vcc.Types)
	}

	if len(vcc.Subject) > 0 {
		vcJSON[jsonFldSubject] = SerializeSubject(vcc.Subject)
	}

	if len(proofs) > 0 {
		vcJSON[jsonFldLDProof] = proofsToRaw(proofs)
	}

	if vcc.Status != nil {
		vcJSON[jsonFldStatus] = serializeTypedIDObj(*vcc.Status)
	}

	if vcc.Issuer != nil {
		vcJSON[jsonFldIssuer] = serializeIssuer(*vcc.Issuer)
	}

	if len(vcc.Schemas) > 0 {
		vcJSON[jsonFldSchema] = typedIDsToRaw(vcc.Schemas)
	}

	if vcc.Evidence != nil {
		vcJSON[jsonFldEvidence] = vcc.Evidence
	}

	if vcc.RefreshService != nil {
		vcJSON[jsonFldRefreshService] = serializeRefreshObj(*vcc.RefreshService)
	}

	if len(vcc.TermsOfUse) > 0 {
		vcJSON[jsonFldTermsOfUse] = typedIDsToRaw(vcc.TermsOfUse)
	}

	if vcc.Issued != nil {
		vcJSON[jsonFldIssued] = serializeTime(vcc.Issued)
	}

	if vcc.Expired != nil {
		vcJSON[jsonFldExpired] = serializeTime(vcc.Expired)
	}

	if vcc.SDJWTHashAlg != nil {
		sdHashAlg, err := common.FormatCryptoHashAlg(*vcc.SDJWTHashAlg)
		if err != nil {
			return nil, fmt.Errorf("try to serialize %s: %w", jsonFldSDJWTHashAlg, err)
		}

		vcJSON[jsonFldSDJWTHashAlg] = sdHashAlg
	}

	return vcJSON, nil
}

func serializeTime(t *util.TimeWrapper) interface{} {
	return t.FormatToString()
}

func serializeTypes(types []string) interface{} {
	if len(types) == 1 {
		// as string
		return types[0]
	}

	// as []interface{} if strings
	return mapSlice(types, func(t string) interface{} {
		return t
	})
}

func contextToRaw(context []string, cContext []interface{}) []interface{} {
	// return as array
	sContext := make([]interface{}, len(context), len(context)+len(cContext))
	for i := range context {
		sContext[i] = context[i]
	}

	sContext = append(sContext, cContext...)

	return sContext
}

func typedIDsToRaw(typedIDs []TypedID) interface{} {
	switch len(typedIDs) {
	case 1:
		return serializeTypedIDObj(typedIDs[0])
	default:
		return mapSlice(typedIDs, serializeTypedIDObj)
	}
}

//TODO: Credential shouldn't be directly marshalable, this create a lot of confusions.
// change this function into two functions, one is returning JSONObject or string
// Other returns credential bytes

// MarshalJSON converts Verifiable Credential to JSON bytes.
func (vc *Credential) MarshalJSON() ([]byte, error) {
	if vc.JWTEnvelope != nil && vc.JWTEnvelope.JWT != "" {
		if vc.credentialContents.SDJWTHashAlg != nil {
			sdJWT, err := vc.MarshalWithDisclosure(DiscloseAll())
			if err != nil {
				return nil, err
			}

			return []byte("\"" + sdJWT + "\""), nil
		}

		// If vc.JWT exists, marshal only the JWT, since all other values should be unchanged
		// from when the JWT was parsed.
		return []byte("\"" + vc.JWTEnvelope.JWT + "\""), nil
	}

	obj, err := vc.ToUniversalForm()
	if err != nil {
		return nil, fmt.Errorf("object marshalling of verifiable credential: %w", err)
	}

	byteCred, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("JSON marshalling of verifiable credential: %w", err)
	}

	return byteCred, nil
}

// MarshalAsJSONLD converts Verifiable Credential to JSON bytes ignoring that it is in JWT form.
func (vc *Credential) MarshalAsJSONLD() ([]byte, error) {
	byteCred, err := json.Marshal(vc.ToRawClaimsMap())
	if err != nil {
		return nil, fmt.Errorf("JSON marshalling of verifiable credential: %w", err)
	}

	return byteCred, nil
}

// ToRawClaimsMap returns raw map[string]interface{} of VC claims.
func (vc *Credential) ToRawClaimsMap() JSONObject {
	return vc.ToRawJSON()
}

// MarshalAsCWTLD converts Verifiable Credential to CBOR bytes.
func (vc *Credential) MarshalAsCWTLD() ([]byte, error) {
	if vc.CWTEnvelope == nil {
		return nil, errors.New("no COSE envelope found")
	}

	return vc.CWTEnvelope.Sign1MessageRaw, nil
}

// MarshalAsCWTLDHex converts Verifiable Credential to CBOR hex string.
func (vc *Credential) MarshalAsCWTLDHex() (string, error) {
	data, err := vc.MarshalAsCWTLD()
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(data), nil
}

// WithModifiedID creates new credential with modified id and without proofs as they become invalid.
func (vc *Credential) WithModifiedID(id string) *Credential {
	newCredJSON := copyCredentialJSONWithoutProofs(vc.credentialJSON)
	newContents := vc.Contents()

	newContents.ID = id

	if id != "" {
		newCredJSON[jsonFldID] = id
	} else {
		delete(newCredJSON, jsonFldID)
	}

	return &Credential{
		credentialJSON:     newCredJSON,
		credentialContents: newContents,
	}
}

// WithModifiedIssued creates new credential with modified issued time and without proofs as they become invalid.
func (vc *Credential) WithModifiedIssued(wrapper *util.TimeWrapper) *Credential {
	newCredJSON := copyCredentialJSONWithoutProofs(vc.credentialJSON)
	newContents := vc.Contents()

	newContents.Issued = wrapper
	newCredJSON[jsonFldIssued] = serializeTime(wrapper)

	return &Credential{
		credentialJSON:     newCredJSON,
		credentialContents: newContents,
	}
}

// WithModifiedExpired creates new credential with modified expired time and without proofs as they become invalid.
func (vc *Credential) WithModifiedExpired(wrapper *util.TimeWrapper) *Credential {
	newCredJSON := copyCredentialJSONWithoutProofs(vc.credentialJSON)
	newContents := vc.Contents()

	newContents.Expired = wrapper
	newCredJSON[jsonFldExpired] = serializeTime(wrapper)

	return &Credential{
		credentialJSON:     newCredJSON,
		credentialContents: newContents,
	}
}

// WithModifiedContext creates new credential with modified context and without proofs as they become invalid.
func (vc *Credential) WithModifiedContext(context []string) *Credential {
	newCredJSON := copyCredentialJSONWithoutProofs(vc.credentialJSON)
	newContents := vc.Contents()

	newContents.Context = context
	rawContext := contextToRaw(context, newContents.CustomContext)

	if len(rawContext) > 0 {
		newCredJSON[jsonFldContext] = rawContext
	} else {
		delete(newCredJSON, jsonFldContext)
	}

	return &Credential{
		credentialJSON:     newCredJSON,
		credentialContents: newContents,
	}
}

// WithModifiedStatus creates new credential with modified status and without proofs as they become invalid.
func (vc *Credential) WithModifiedStatus(status *TypedID) *Credential {
	newCredJSON := copyCredentialJSONWithoutProofs(vc.credentialJSON)
	newContents := vc.Contents()

	newContents.Status = status

	if status != nil {
		newCredJSON[jsonFldStatus] = serializeTypedIDObj(*status)
	} else {
		delete(newCredJSON, jsonFldStatus)
	}

	return &Credential{
		credentialJSON:     newCredJSON,
		credentialContents: newContents,
	}
}

// WithModifiedRefreshService creates new credential with modified status and without proofs as they become invalid.
func (vc *Credential) WithModifiedRefreshService(refreshService *RefreshService) *Credential {
	newCredJSON := copyCredentialJSONWithoutProofs(vc.credentialJSON)
	newContents := vc.Contents()

	newContents.RefreshService = refreshService

	if refreshService != nil {
		newCredJSON[jsonFldRefreshService] = serializeRefreshObj(*refreshService)
	} else {
		delete(newCredJSON, jsonFldRefreshService)
	}

	return &Credential{
		credentialJSON:     newCredJSON,
		credentialContents: newContents,
	}
}

// WithModifiedIssuer creates new credential with modified issuer and without proofs as they become invalid.
func (vc *Credential) WithModifiedIssuer(issuer *Issuer) *Credential {
	newCredJSON := copyCredentialJSONWithoutProofs(vc.credentialJSON)
	newContents := vc.Contents()

	newContents.Issuer = issuer

	if issuer != nil {
		newCredJSON[jsonFldIssuer] = serializeIssuer(*issuer)
	} else {
		delete(newCredJSON, jsonFldIssuer)
	}

	return &Credential{
		credentialJSON:     newCredJSON,
		credentialContents: newContents,
	}
}

// WithModifiedSubject creates new credential with modified issuer and without proofs as they become invalid.
func (vc *Credential) WithModifiedSubject(subject []Subject) *Credential {
	newCredJSON := copyCredentialJSONWithoutProofs(vc.credentialJSON)
	newContents := vc.Contents()

	newContents.Subject = subject

	if len(subject) > 0 {
		newCredJSON[jsonFldSubject] = SerializeSubject(subject)
	} else {
		delete(newCredJSON, jsonFldSubject)
	}

	return &Credential{
		credentialJSON:     newCredJSON,
		credentialContents: newContents,
	}
}

// SetCustomField should be used only in tests. Remove after proper vc test tool created.
func (vc *Credential) SetCustomField(name string, value interface{}) {
	vc.credentialJSON[name] = value
}

func copyCredentialJSONWithoutProofs(credentialJSON JSONObject) JSONObject {
	newContent := jsonutil.ShallowCopyObj(credentialJSON)
	delete(newContent, jsonFldLDProof)

	return newContent
}
