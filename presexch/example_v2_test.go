/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presexch_test

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/bbs-signature-go/bbs12381g2pub"
	ldprocessor "github.com/trustbloc/did-go/doc/ld/processor"
	ldtestutil "github.com/trustbloc/did-go/doc/ld/testutil"
	"github.com/trustbloc/kms-go/spi/kms"

	utiltime "github.com/trustbloc/did-go/doc/util/time"

	"github.com/trustbloc/vc-go/crypto-ext/testutil"
	"github.com/trustbloc/vc-go/jwt"
	"github.com/trustbloc/vc-go/proof/creator"
	"github.com/trustbloc/vc-go/proof/ldproofs/bbsblssignature2020"
	"github.com/trustbloc/vc-go/proof/testsupport"

	. "github.com/trustbloc/vc-go/presexch"
	"github.com/trustbloc/vc-go/sdjwt/common"
	jsonutil "github.com/trustbloc/vc-go/util/json"
	"github.com/trustbloc/vc-go/verifiable"
)

func ExamplePresentationDefinition_CreateVP_v2() {
	required := Required

	pd := &PresentationDefinition{
		ID:      "c1b88ce1-8460-4baf-8f16-4759a2f055fd",
		Purpose: "To sell you a drink we need to know that you are an adult.",
		InputDescriptors: []*InputDescriptor{{
			ID:      "age_descriptor",
			Purpose: "Your age should be greater or equal to 18.",
			Constraints: &Constraints{
				LimitDisclosure: &required,
				Fields: []*Field{
					{
						Path:      []string{"$.credentialSubject.age", "$.vc.credentialSubject.age", "$.age"},
						Predicate: &required,
						Filter: &Filter{
							Type:    &intFilterType,
							Minimum: 18,
						},
					},
					{
						Path: []string{"$.credentialSchema[0].id", "$.credentialSchema.id", "$.vc.credentialSchema.id"},
						Filter: &Filter{
							Type:  &strFilterType,
							Const: "hub://did:foo:123/Collections/schema.us.gov/passport.json",
						},
					},
				},
			},
		}},
	}

	loader, err := ldtestutil.DocumentLoader()
	if err != nil {
		panic(err)
	}

	vp, err := pd.CreateVP(createExampleCredentials([]credentialProto{
		{
			ID:      "http://example.edu/credentials/777",
			Context: []string{verifiable.ContextURI},
			Types:   []string{verifiable.VCType},
			Issuer: &verifiable.Issuer{
				ID: "did:example:76e12ec712ebc6f1c221ebfeb1f",
			},
			Issued: &utiltime.TimeWrapper{
				Time: time.Time{},
			},
			Schemas: []verifiable.TypedID{{
				ID:   "hub://did:foo:123/Collections/schema.us.gov/passport.json",
				Type: "JsonSchemaValidator2018",
			}},

			Subject: parseSubject(map[string]interface{}{
				"id":         "did:example:ebfeb1f712ebc6f1c276e12ec21",
				"first_name": "Jesse",
				"last_name":  "Pinkman",
				"age":        21,
			}),
		},
	}), loader, WithSDCredentialOptions(verifiable.WithJSONLDDocumentLoader(loader)))
	if err != nil {
		panic(err)
	}

	vp.ID = dummy
	vp.CustomFields["presentation_submission"].(*PresentationSubmission).ID = dummy

	vpBytes, err := json.MarshalIndent(vp, "", "\t")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(vpBytes))
	// Output:
	// {
	//	"@context": [
	//		"https://www.w3.org/2018/credentials/v1",
	//		"https://identity.foundation/presentation-exchange/submission/v1"
	//	],
	//	"id": "DUMMY",
	//	"presentation_submission": {
	//		"id": "DUMMY",
	//		"definition_id": "c1b88ce1-8460-4baf-8f16-4759a2f055fd",
	//		"descriptor_map": [
	//			{
	//				"id": "age_descriptor",
	//				"format": "ldp_vp",
	//				"path": "$",
	//				"path_nested": {
	//					"id": "age_descriptor",
	//					"format": "ldp_vc",
	//					"path": "$.verifiableCredential[0]"
	//				}
	//			}
	//		]
	//	},
	//	"type": [
	//		"VerifiablePresentation",
	//		"PresentationSubmission"
	//	],
	//	"verifiableCredential": [
	//		{
	//			"@context": [
	//				"https://www.w3.org/2018/credentials/v1"
	//			],
	//			"credentialSubject": {
	//				"age": true,
	//				"id": "did:example:ebfeb1f712ebc6f1c276e12ec21"
	//			},
	//			"id": "http://example.edu/credentials/777",
	//			"issuanceDate": "0001-01-01T00:00:00Z",
	//			"issuer": "did:example:76e12ec712ebc6f1c221ebfeb1f",
	//			"type": "VerifiableCredential"
	//		}
	//	]
	// }
}

func ExamplePresentationDefinition_CreateVP_with_LdpVC_Format() {
	required := Required

	pd := &PresentationDefinition{
		ID:      "c1b88ce1-8460-4baf-8f16-4759a2f055fd",
		Purpose: "To sell you a drink we need to know that you are an adult.",
		Format: &Format{
			LdpVC: &LdpType{
				ProofType: []string{"Ed25519Signature2018"},
			},
		},
		InputDescriptors: []*InputDescriptor{{
			ID:      "age_descriptor",
			Purpose: "Your age should be greater or equal to 18.",
			Constraints: &Constraints{
				LimitDisclosure: &required,
				Fields: []*Field{
					{
						Path:      []string{"$.credentialSubject.age", "$.vc.credentialSubject.age", "$.age"},
						Predicate: &required,
						Filter: &Filter{
							Type:    &intFilterType,
							Minimum: 18,
						},
					},
					{
						Path: []string{"$.credentialSchema[0].id", "$.credentialSchema.id", "$.vc.credentialSchema.id"},
						Filter: &Filter{
							Type:  &strFilterType,
							Const: "hub://did:foo:123/Collections/schema.us.gov/passport.json",
						},
					},
				},
			},
		}},
	}

	loader, err := ldtestutil.DocumentLoader()
	if err != nil {
		panic(err)
	}

	vp, err := pd.CreateVP(createExampleCredentials([]credentialProto{
		{
			ID:      "http://example.edu/credentials/777",
			Context: []string{verifiable.ContextURI},
			Types:   []string{verifiable.VCType},
			Issuer: &verifiable.Issuer{
				ID: "did:example:76e12ec712ebc6f1c221ebfeb1f",
			},
			Issued: &utiltime.TimeWrapper{
				Time: time.Time{},
			},
			Schemas: []verifiable.TypedID{{
				ID:   "hub://did:foo:123/Collections/schema.us.gov/passport.json",
				Type: "JsonSchemaValidator2018",
			}},

			Subject: parseSubject(map[string]interface{}{
				"id":         "did:example:ebfeb1f712ebc6f1c276e12ec21",
				"first_name": "Jesse",
				"last_name":  "Pinkman",
				"age":        21,
			}),
			Proofs: []verifiable.Proof{
				{"type": "Ed25519Signature2018"},
			},
		},
	}), loader, WithSDCredentialOptions(verifiable.WithJSONLDDocumentLoader(loader)))
	if err != nil {
		panic(err)
	}

	vp.ID = dummy
	vp.CustomFields["presentation_submission"].(*PresentationSubmission).ID = dummy

	vpBytes, err := json.MarshalIndent(vp, "", "\t")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(vpBytes))
	// Output:
	// {
	//	"@context": [
	//		"https://www.w3.org/2018/credentials/v1",
	//		"https://identity.foundation/presentation-exchange/submission/v1"
	//	],
	//	"id": "DUMMY",
	//	"presentation_submission": {
	//		"id": "DUMMY",
	//		"definition_id": "c1b88ce1-8460-4baf-8f16-4759a2f055fd",
	//		"descriptor_map": [
	//			{
	//				"id": "age_descriptor",
	//				"format": "ldp_vc",
	//				"path": "$",
	//				"path_nested": {
	//					"id": "age_descriptor",
	//					"format": "ldp_vc",
	//					"path": "$.verifiableCredential[0]"
	//				}
	//			}
	//		]
	//	},
	//	"type": [
	//		"VerifiablePresentation",
	//		"PresentationSubmission"
	//	],
	//	"verifiableCredential": [
	//		{
	//			"@context": [
	//				"https://www.w3.org/2018/credentials/v1"
	//			],
	//			"credentialSubject": {
	//				"age": true,
	//				"id": "did:example:ebfeb1f712ebc6f1c276e12ec21"
	//			},
	//			"id": "http://example.edu/credentials/777",
	//			"issuanceDate": "0001-01-01T00:00:00Z",
	//			"issuer": "did:example:76e12ec712ebc6f1c221ebfeb1f",
	//			"type": "VerifiableCredential"
	//		}
	//	]
	// }
}

func ExamplePresentationDefinition_CreateVP_with_Ldp_Format() {
	required := Required

	pd := &PresentationDefinition{
		ID:      "c1b88ce1-8460-4baf-8f16-4759a2f055fd",
		Purpose: "To sell you a drink we need to know that you are an adult.",
		Format: &Format{
			Ldp: &LdpType{
				ProofType: []string{"Ed25519Signature2018"},
			},
		},
		InputDescriptors: []*InputDescriptor{{
			ID:      "age_descriptor",
			Purpose: "Your age should be greater or equal to 18.",
			Constraints: &Constraints{
				LimitDisclosure: &required,
				Fields: []*Field{
					{
						Path:      []string{"$.credentialSubject.age", "$.vc.credentialSubject.age", "$.age"},
						Predicate: &required,
						Filter: &Filter{
							Type:    &intFilterType,
							Minimum: 18,
						},
					},
					{
						Path: []string{"$.credentialSchema[0].id", "$.credentialSchema.id", "$.vc.credentialSchema.id"},
						Filter: &Filter{
							Type:  &strFilterType,
							Const: "hub://did:foo:123/Collections/schema.us.gov/passport.json",
						},
					},
				},
			},
		}},
	}

	loader, err := ldtestutil.DocumentLoader()
	if err != nil {
		panic(err)
	}

	vp, err := pd.CreateVP(createExampleCredentials([]credentialProto{
		{
			ID:      "http://example.edu/credentials/777",
			Context: []string{verifiable.ContextURI},
			Types:   []string{verifiable.VCType},
			Issuer: &verifiable.Issuer{
				ID: "did:example:76e12ec712ebc6f1c221ebfeb1f",
			},
			Issued: &utiltime.TimeWrapper{
				Time: time.Time{},
			},
			Schemas: []verifiable.TypedID{{
				ID:   "hub://did:foo:123/Collections/schema.us.gov/passport.json",
				Type: "JsonSchemaValidator2018",
			}},

			Subject: parseSubject(map[string]interface{}{
				"id":         "did:example:ebfeb1f712ebc6f1c276e12ec21",
				"first_name": "Jesse",
				"last_name":  "Pinkman",
				"age":        21,
			}),
			Proofs: []verifiable.Proof{
				{"type": "Ed25519Signature2018"},
			},
		},
	}), loader, WithSDCredentialOptions(verifiable.WithJSONLDDocumentLoader(loader)))
	if err != nil {
		panic(err)
	}

	vp.ID = dummy
	vp.CustomFields["presentation_submission"].(*PresentationSubmission).ID = dummy

	vpBytes, err := json.MarshalIndent(vp, "", "\t")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(vpBytes))
	// Output:
	// {
	//	"@context": [
	//		"https://www.w3.org/2018/credentials/v1",
	//		"https://identity.foundation/presentation-exchange/submission/v1"
	//	],
	//	"id": "DUMMY",
	//	"presentation_submission": {
	//		"id": "DUMMY",
	//		"definition_id": "c1b88ce1-8460-4baf-8f16-4759a2f055fd",
	//		"descriptor_map": [
	//			{
	//				"id": "age_descriptor",
	//				"format": "ldp",
	//				"path": "$",
	//				"path_nested": {
	//					"id": "age_descriptor",
	//					"format": "ldp_vc",
	//					"path": "$.verifiableCredential[0]"
	//				}
	//			}
	//		]
	//	},
	//	"type": [
	//		"VerifiablePresentation",
	//		"PresentationSubmission"
	//	],
	//	"verifiableCredential": [
	//		{
	//			"@context": [
	//				"https://www.w3.org/2018/credentials/v1"
	//			],
	//			"credentialSubject": {
	//				"age": true,
	//				"id": "did:example:ebfeb1f712ebc6f1c276e12ec21"
	//			},
	//			"id": "http://example.edu/credentials/777",
	//			"issuanceDate": "0001-01-01T00:00:00Z",
	//			"issuer": "did:example:76e12ec712ebc6f1c221ebfeb1f",
	//			"type": "VerifiableCredential"
	//		}
	//	]
	// }
}

func ExamplePresentationDefinition_CreateVP_withFormatInInputDescriptor() {
	required := Required

	pd := &PresentationDefinition{
		ID:      "c1b88ce1-8460-4baf-8f16-4759a2f055fd",
		Purpose: "To sell you a drink we need to know that you are an adult.",
		InputDescriptors: []*InputDescriptor{{
			ID:      "age_descriptor",
			Purpose: "Your age should be greater or equal to 18.",
			Format: &Format{
				LdpVP: &LdpType{
					ProofType: []string{"Ed25519Signature2018"},
				},
			},
			Constraints: &Constraints{
				LimitDisclosure: &required,
				Fields: []*Field{
					{
						Path:      []string{"$.credentialSubject.age", "$.vc.credentialSubject.age", "$.age"},
						Predicate: &required,
						Filter: &Filter{
							Type:    &intFilterType,
							Minimum: 18,
						},
					},
					{
						Path: []string{"$.credentialSchema[0].id", "$.credentialSchema.id", "$.vc.credentialSchema.id"},
						Filter: &Filter{
							Type:  &strFilterType,
							Const: "hub://did:foo:123/Collections/schema.us.gov/passport.json",
						},
					},
				},
			},
		}},
	}

	loader, err := ldtestutil.DocumentLoader()
	if err != nil {
		panic(err)
	}

	vp, err := pd.CreateVP(createExampleCredentials([]credentialProto{
		{
			ID:      "http://example.edu/credentials/777",
			Context: []string{verifiable.ContextURI},
			Types:   []string{verifiable.VCType},
			Issuer: &verifiable.Issuer{
				ID: "did:example:76e12ec712ebc6f1c221ebfeb1f",
			},
			Issued: &utiltime.TimeWrapper{
				Time: time.Time{},
			},
			Schemas: []verifiable.TypedID{{
				ID:   "hub://did:foo:123/Collections/schema.us.gov/passport.json",
				Type: "JsonSchemaValidator2018",
			}},

			Subject: parseSubject(map[string]interface{}{
				"id":         "did:example:ebfeb1f712ebc6f1c276e12ec21",
				"first_name": "Jesse",
				"last_name":  "Pinkman",
				"age":        21,
			}),
			Proofs: []verifiable.Proof{
				{"type": "Ed25519Signature2018"},
			},
		},
	}), loader, WithSDCredentialOptions(verifiable.WithJSONLDDocumentLoader(loader)))
	if err != nil {
		panic(err)
	}

	vp.ID = dummy
	vp.CustomFields["presentation_submission"].(*PresentationSubmission).ID = dummy

	vpBytes, err := json.MarshalIndent(vp, "", "\t")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(vpBytes))
	// Output:
	// {
	//	"@context": [
	//		"https://www.w3.org/2018/credentials/v1",
	//		"https://identity.foundation/presentation-exchange/submission/v1"
	//	],
	//	"id": "DUMMY",
	//	"presentation_submission": {
	//		"id": "DUMMY",
	//		"definition_id": "c1b88ce1-8460-4baf-8f16-4759a2f055fd",
	//		"descriptor_map": [
	//			{
	//				"id": "age_descriptor",
	//				"format": "ldp_vp",
	//				"path": "$",
	//				"path_nested": {
	//					"id": "age_descriptor",
	//					"format": "ldp_vc",
	//					"path": "$.verifiableCredential[0]"
	//				}
	//			}
	//		]
	//	},
	//	"type": [
	//		"VerifiablePresentation",
	//		"PresentationSubmission"
	//	],
	//	"verifiableCredential": [
	//		{
	//			"@context": [
	//				"https://www.w3.org/2018/credentials/v1"
	//			],
	//			"credentialSubject": {
	//				"age": true,
	//				"id": "did:example:ebfeb1f712ebc6f1c276e12ec21"
	//			},
	//			"id": "http://example.edu/credentials/777",
	//			"issuanceDate": "0001-01-01T00:00:00Z",
	//			"issuer": "did:example:76e12ec712ebc6f1c221ebfeb1f",
	//			"type": "VerifiableCredential"
	//		}
	//	]
	// }
}

func TestExamplePresentationDefinition_CreateVPWithFormat_NoMatch(t *testing.T) {
	required := Required

	pd := &PresentationDefinition{
		ID:      "c1b88ce1-8460-4baf-8f16-4759a2f055fd",
		Purpose: "To sell you a drink we need to know that you are an adult.",
		Format: &Format{
			LdpVP: &LdpType{
				ProofType: []string{"Ed25519Signature2018"},
			},
		},
		InputDescriptors: []*InputDescriptor{{
			ID:      "age_descriptor",
			Purpose: "Your age should be greater or equal to 18.",
			Constraints: &Constraints{
				LimitDisclosure: &required,
				Fields: []*Field{
					{
						Path:      []string{"$.credentialSubject.age", "$.vc.credentialSubject.age", "$.age"},
						Predicate: &required,
						Filter: &Filter{
							Type:    &intFilterType,
							Minimum: 18,
						},
					},
					{
						Path: []string{"$.credentialSchema[0].id", "$.credentialSchema.id", "$.vc.credentialSchema.id"},
						Filter: &Filter{
							Type:  &strFilterType,
							Const: "hub://did:foo:123/Collections/schema.us.gov/passport.json",
						},
					},
				},
			},
		}},
	}

	loader, err := ldtestutil.DocumentLoader()
	if err != nil {
		panic(err)
	}

	_, err = pd.CreateVP(createExampleCredentials([]credentialProto{
		{
			ID:      "http://example.edu/credentials/777",
			Context: []string{verifiable.ContextURI},
			Types:   []string{verifiable.VCType},
			Issuer: &verifiable.Issuer{
				ID: "did:example:76e12ec712ebc6f1c221ebfeb1f",
			},
			Issued: &utiltime.TimeWrapper{
				Time: time.Time{},
			},
			Schemas: []verifiable.TypedID{{
				ID:   "hub://did:foo:123/Collections/schema.us.gov/passport.json",
				Type: "JsonSchemaValidator2018",
			}},

			Subject: parseSubject(map[string]interface{}{
				"id":         "did:example:ebfeb1f712ebc6f1c276e12ec21",
				"first_name": "Jesse",
				"last_name":  "Pinkman",
				"age":        21,
			}),
			Proofs: []verifiable.Proof{
				{"type": "JsonWebSignature2020"},
			},
		},
	}), loader, WithSDCredentialOptions(verifiable.WithJSONLDDocumentLoader(loader)))

	require.EqualError(t, err, "credentials do not satisfy requirements")
}

func ExamplePresentationDefinition_CreateVP_withFrame() {
	vcJSON := `
	{
	 "@context": [
	   "https://www.w3.org/2018/credentials/v1",
	   "https://w3id.org/citizenship/v1",
	   "https://w3id.org/security/bbs/v1"
	 ],
	 "id": "https://issuer.oidp.uscis.gov/credentials/83627465",
	 "type": [
	   "VerifiableCredential",
	   "PermanentResidentCard"
	 ],
	 "issuer": "did:example:489398593",
	 "identifier": "83627465",
	 "name": "Permanent Resident Card",
	 "description": "Government of Example Permanent Resident Card.",
	 "issuanceDate": "2019-12-03T12:19:52Z",
	 "expirationDate": "2029-12-03T12:19:52Z",
	 "credentialSubject": {
	   "id": "did:example:b34ca6cd37bbf23",
	   "type": [
	     "PermanentResident",
	     "Person"
	   ],
	   "givenName": "JOHN",
	   "familyName": "SMITH",
	   "gender": "Male",
	   "image": "data:image/png;base64,iVBORw0KGgokJggg==",
	   "residentSince": "2015-01-01",
	   "lprCategory": "C09",
	   "lprNumber": "999-999-999",
	   "commuterClassification": "C1",
	   "birthCountry": "Bahamas",
	   "birthDate": "1958-07-17"
	 }
	}
	`

	frameJSONWithMissingIssuer := `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/citizenship/v1",
    "https://w3id.org/security/bbs/v1"
  ],
  "type": ["VerifiableCredential", "PermanentResidentCard"],
  "@explicit": true,
  "identifier": {},
  "issuer": {},
  "issuanceDate": {},
  "credentialSubject": {
    "@explicit": true,
    "type": ["PermanentResident", "Person"],
    "givenName": {},
    "familyName": {},
    "gender": {},
	"birthCountry": {}
  }
}
`

	frameDoc, err := jsonutil.ToMap(frameJSONWithMissingIssuer)
	if err != nil {
		panic(err)
	}

	required := Required

	pd := &PresentationDefinition{
		ID:    "c1b88ce1-8460-4baf-8f16-4759a2f055fd",
		Frame: frameDoc,
		InputDescriptors: []*InputDescriptor{{
			ID: "country_descriptor",
			Constraints: &Constraints{
				Fields: []*Field{
					{
						Path:      []string{"$.credentialSubject.birthCountry", "$.vc.credentialSubject.birthCountry"},
						Predicate: &required,
						Filter: &Filter{
							Type:  &strFilterType,
							Const: "Bahamas",
						},
					},
				},
			},
		}},
	}

	loader, err := ldtestutil.DocumentLoader()
	if err != nil {
		panic(err)
	}

	vc, err := verifiable.ParseCredential([]byte(vcJSON), verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(loader))
	if err != nil {
		panic(err)
	}

	pubKey, privKey, err := bbs12381g2pub.GenerateKeyPair(sha256.New, nil)
	if err != nil {
		panic(err)
	}

	pubKeyBytes, err := pubKey.Marshal()
	if err != nil {
		panic(err)
	}

	signVCWithBBS(privKey, vc, loader)

	bbsProofCreator := &verifiable.BBSProofCreator{
		ProofDerivation: bbs12381g2pub.New(),
		VerificationMethodResolver: testsupport.NewSingleKeyResolver(
			"did:example:123456#key1", pubKeyBytes, "Bls12381G2Key2020"),
	}

	vp, err := pd.CreateVP([]*verifiable.Credential{vc}, loader,
		WithSDBBSProofCreator(bbsProofCreator),
		WithSDCredentialOptions(
			verifiable.WithJSONLDDocumentLoader(loader)))
	if err != nil {
		panic(err)
	}

	vp.ID = dummy
	vp.CustomFields["presentation_submission"].(*PresentationSubmission).ID = dummy
	vp.Credentials()[0].Proofs()[0]["created"] = dummy
	vp.Credentials()[0].Proofs()[0]["proofValue"] = dummy

	vpBytes, err := json.MarshalIndent(vp, "", "\t")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(vpBytes))
	// Output:
	// {
	//	"@context": [
	//		"https://www.w3.org/2018/credentials/v1",
	//		"https://identity.foundation/presentation-exchange/submission/v1"
	//	],
	//	"id": "DUMMY",
	//	"presentation_submission": {
	//		"id": "DUMMY",
	//		"definition_id": "c1b88ce1-8460-4baf-8f16-4759a2f055fd",
	//		"descriptor_map": [
	//			{
	//				"id": "country_descriptor",
	//				"format": "ldp_vp",
	//				"path": "$",
	//				"path_nested": {
	//					"id": "country_descriptor",
	//					"format": "ldp_vc",
	//					"path": "$.verifiableCredential[0]"
	//				}
	//			}
	//		]
	//	},
	//	"type": [
	//		"VerifiablePresentation",
	//		"PresentationSubmission"
	//	],
	//	"verifiableCredential": [
	//		{
	//			"@context": [
	//				"https://www.w3.org/2018/credentials/v1",
	//				"https://w3id.org/citizenship/v1",
	//				"https://w3id.org/security/bbs/v1"
	//			],
	//			"credentialSubject": {
	//				"birthCountry": true,
	//				"familyName": "SMITH",
	//				"gender": "Male",
	//				"givenName": "JOHN",
	//				"id": "did:example:b34ca6cd37bbf23",
	//				"type": [
	//					"Person",
	//					"PermanentResident"
	//				]
	//			},
	//			"id": "https://issuer.oidp.uscis.gov/credentials/83627465",
	//			"identifier": "83627465",
	//			"issuanceDate": "2019-12-03T12:19:52Z",
	//			"issuer": "did:example:489398593",
	//			"proof": {
	//				"created": "DUMMY",
	//				"nonce": "",
	//				"proofPurpose": "assertionMethod",
	//				"proofValue": "DUMMY",
	//				"type": "BbsBlsSignatureProof2020",
	//				"verificationMethod": "did:example:123456#key1"
	//			},
	//			"type": [
	//				"PermanentResidentCard",
	//				"VerifiableCredential"
	//			]
	//		}
	//	]
	// }
}

// nolint:gocyclo
func ExamplePresentationDefinition_CreateVP_limitedDisclosureSkipsNonSDVCs() {
	required := Required

	pd := &PresentationDefinition{
		ID:      "c1b88ce1-8460-4baf-8f16-4759a2f055fd",
		Purpose: "To provide mauve alerts, we need to verify your authorization to receive mauve alert warnings.",
		InputDescriptors: []*InputDescriptor{{
			ID:      "mauve_alert",
			Purpose: "You are authorized to receive warnings for mauve alerts.",
			Constraints: &Constraints{
				LimitDisclosure: &required,
				Fields: []*Field{
					{
						Path: []string{"$.credentialSubject.warn_alert", "$.vc.credentialSubject.warn_alert", "$.warn_alert"},
						// Predicate: &required,
						Filter: &Filter{
							Type:  &strFilterType,
							Const: "mauve",
						},
					},
				},
			},
		}},
	}

	loader, err := ldtestutil.DocumentLoader()
	if err != nil {
		panic(err)
	}

	makeVC := func(id string) *verifiable.Credential {
		vc, makeErr := verifiable.CreateCredential(verifiable.CredentialContents{
			ID:      id,
			Context: []string{verifiable.ContextURI},
			Types:   []string{verifiable.VCType},
			Issuer: &verifiable.Issuer{
				ID: "did:example:76e12ec712ebc6f1c221ebfeb1f",
			},
			Issued: &utiltime.TimeWrapper{
				Time: time.Time{},
			},
			Schemas: []verifiable.TypedID{{
				ID:   "hub://did:foo:123/Collections/schema.us.gov/passport.json",
				Type: "JsonSchemaValidator2018",
			}},

			Subject: parseSubject(map[string]interface{}{
				"id":         "did:example:ebfeb1f712ebc6f1c276e12ec21",
				"first_name": "Jesse",
				"last_name":  "Pinkman",
				"warn_alert": "mauve",
			}),
		}, nil)
		if makeErr != nil {
			panic(fmt.Errorf("make vc :%w", makeErr))
		}

		return vc
	}

	proofCreators, _, err := testsupport.NewKMSSignersAndVerifierErr([]testsupport.SigningKey{
		{Type: kms.ECDSAP256TypeIEEEP1363, PublicKeyID: "#key-1"},
	})
	if err != nil {
		panic(err)
	}

	jwtSrc := makeVC("http://example.edu/credentials/888")

	claims, err := jwtSrc.JWTClaims(false)
	if err != nil {
		panic(err)
	}

	credJWT, err := claims.MarshalJWSString(verifiable.ECDSASecp256r1, proofCreators[0], "#key-1")
	if err != nil {
		panic(err)
	}

	jwtVC, err := verifiable.ParseCredential([]byte(credJWT), verifiable.WithDisabledProofCheck())
	if err != nil {
		panic(err)
	}

	sdJWTSrc := makeVC("http://example.edu/credentials/999")

	joseSig, err := jwt.NewJOSESigner(jwt.SignParameters{
		KeyID:  "#key-1",
		JWTAlg: "ES256",
	}, proofCreators[0])
	if err != nil {
		panic(err)
	}

	marshaledSDJWTVC, err := sdJWTSrc.MarshalWithDisclosure(verifiable.DiscloseAll(), verifiable.DisclosureSigner(joseSig, "#key-1"))
	if err != nil {
		panic(err)
	}

	sdJWTVC, err := verifiable.ParseCredential([]byte(marshaledSDJWTVC), verifiable.WithDisabledProofCheck())
	if err != nil {
		panic(err)
	}

	vp, err := pd.CreateVP([]*verifiable.Credential{
		jwtVC,
		sdJWTVC,
		makeVC("http://example.edu/credentials/777"),
	}, loader, WithSDCredentialOptions(verifiable.WithJSONLDDocumentLoader(loader)))
	if err != nil {
		panic(err)
	}

	vp.ID = dummy
	vp.CustomFields["presentation_submission"].(*PresentationSubmission).ID = dummy

	presentedVC := vp.Credentials()[0]

	vcBytes, err := json.MarshalIndent(presentedVC.ToRawJSON(), "", "\t")
	if err != nil {
		panic(err)
	}

	vcStr := string(vcBytes)

	for _, sd := range presentedVC.Contents().Subject[0].CustomFields["_sd"].([]interface{}) {
		vcStr = strings.ReplaceAll(vcStr, sd.(string), "DUMMY")
	}

	vpBytes, err := json.MarshalIndent(vp, "", "\t")
	if err != nil {
		panic(err)
	}

	presentedJWT, err := presentedVC.ToJWTString()
	if err != nil {
		panic(err)
	}

	vpStr := strings.ReplaceAll(string(vpBytes), presentedJWT, "DUMMY")

	fmt.Println(vpStr)
	fmt.Println(vcStr)
	fmt.Println(prettifyDisclosures(presentedVC.SDJWTDisclosures()))
	// Output:
	//{
	//	"@context": [
	//		"https://www.w3.org/2018/credentials/v1",
	//		"https://identity.foundation/presentation-exchange/submission/v1"
	//	],
	//	"id": "DUMMY",
	//	"presentation_submission": {
	//		"id": "DUMMY",
	//		"definition_id": "c1b88ce1-8460-4baf-8f16-4759a2f055fd",
	//		"descriptor_map": [
	//			{
	//				"id": "mauve_alert",
	//				"format": "ldp_vp",
	//				"path": "$",
	//				"path_nested": {
	//					"id": "mauve_alert",
	//					"format": "jwt_vc",
	//					"path": "$.verifiableCredential[0]"
	//				}
	//			}
	//		]
	//	},
	//	"type": [
	//		"VerifiablePresentation",
	//		"PresentationSubmission"
	//	],
	//	"verifiableCredential": [
	//		"DUMMY"
	//	]
	//}
	//{
	//	"@context": [
	//		"https://www.w3.org/2018/credentials/v1"
	//	],
	//	"_sd_alg": "sha-256",
	//	"credentialSchema": {
	//		"id": "hub://did:foo:123/Collections/schema.us.gov/passport.json",
	//		"type": "JsonSchemaValidator2018"
	//	},
	//	"credentialSubject": {
	//		"_sd": [
	//			"DUMMY",
	//			"DUMMY",
	//			"DUMMY"
	//		],
	//		"id": "did:example:ebfeb1f712ebc6f1c276e12ec21"
	//	},
	//	"id": "http://example.edu/credentials/999",
	//	"issuanceDate": "0001-01-01T00:00:00Z",
	//	"issuer": "did:example:76e12ec712ebc6f1c221ebfeb1f",
	//	"type": "VerifiableCredential"
	// }
	// ('warn_alert': mauve)
}

func prettifyDisclosures(disclosures []*common.DisclosureClaim) string {
	out := []string{}

	for _, disclosure := range disclosures {
		out = append(out, fmt.Sprintf("('%s': %v)", disclosure.Name, disclosure.Value))
	}

	return strings.Join(out, ", ")
}

func signVCWithBBS(privKey *bbs12381g2pub.PrivateKey, vc *verifiable.Credential, documentLoader ld.DocumentLoader) {
	bbsSigner, err := testutil.NewBBSSigner(privKey)
	if err != nil {
		panic(err)
	}

	bbsProofCreator := creator.New(creator.WithLDProofType(bbsblssignature2020.New(), bbsSigner))

	ldpContext := &verifiable.LinkedDataProofContext{
		SignatureType:           "BbsBlsSignature2020",
		KeyType:                 kms.BLS12381G2Type,
		SignatureRepresentation: verifiable.SignatureProofValue,
		ProofCreator:            bbsProofCreator,
		VerificationMethod:      "did:example:123456#key1",
	}

	err = vc.AddLinkedDataProof(ldpContext, ldprocessor.WithDocumentLoader(documentLoader))
	if err != nil {
		panic(err)
	}
}

func parseSubject(raw map[string]interface{}) []verifiable.Subject {
	subject, err := verifiable.SubjectFromJSON(raw)
	if err != nil {
		panic(fmt.Errorf("subject parsing %w", err))
	}

	return []verifiable.Subject{subject}
}
