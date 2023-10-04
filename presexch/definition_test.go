/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presexch_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/PaesslerAG/gval"
	"github.com/PaesslerAG/jsonpath"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/bbs-signature-go/bbs12381g2pub"
	lddocloader "github.com/trustbloc/did-go/doc/ld/documentloader"
	ldprocessor "github.com/trustbloc/did-go/doc/ld/processor"
	ldtestutil "github.com/trustbloc/did-go/doc/ld/testutil"
	utiltime "github.com/trustbloc/did-go/doc/util/time"
	"github.com/trustbloc/kms-go/spi/kms"

	"github.com/trustbloc/vc-go/jwt"
	. "github.com/trustbloc/vc-go/presexch"
	"github.com/trustbloc/vc-go/proof/creator"
	"github.com/trustbloc/vc-go/proof/defaults"
	"github.com/trustbloc/vc-go/proof/ldproofs/bbsblssignature2020"
	"github.com/trustbloc/vc-go/proof/ldproofs/bbsblssignatureproof2020"
	"github.com/trustbloc/vc-go/proof/testsupport"
	"github.com/trustbloc/vc-go/verifiable"
)

const errMsgSchema = "credentials do not satisfy requirements"

// nolint: gochecknoglobals
var (
	strFilterType = "string"
	arrFilterType = "array"
	intFilterType = "integer"

	subIsIssuerRequired = Required
)

func TestPresentationDefinition_IsValid(t *testing.T) {
	samples := []string{"sample_1.json", "sample_2.json", "sample_3.json"}

	for _, sample := range samples {
		file := sample
		t.Run(file, func(t *testing.T) {
			var pd *PresentationDefinition
			parseJSONFile(t, "testdata/"+file, &pd)

			require.NoError(t, pd.ValidateSchema())
		})
	}

	t.Run("id is required", func(t *testing.T) {
		errMsg := "presentation_definition: id is required,presentation_definition: input_descriptors is required"
		pd := &PresentationDefinition{
			SubmissionRequirements: []*SubmissionRequirement{{Rule: All, From: "A"}},
		}
		require.EqualError(t, pd.ValidateSchema(), errMsg)
	})
}

func TestPresentationDefinition_CreateVP(t *testing.T) {
	lddl := createTestJSONLDDocumentLoader(t)

	t.Run("Checks schema", func(t *testing.T) {
		pd := &PresentationDefinition{ID: uuid.New().String()}

		vp, err := pd.CreateVP(nil, nil)

		require.EqualError(t, err, "presentation_definition: input_descriptors is required")
		require.Nil(t, vp)
	})

	t.Run("Checks submission requirements", func(t *testing.T) {
		issuerID := "did:example:76e12ec712ebc6f1c221ebfeb1f"

		vc1 := createTestCredential(t, credentialProto{
			Issued:  utiltime.NewTime(time.Now()),
			Context: []string{verifiable.ContextURI},
			Types:   []string{verifiable.VCType},
			ID:      "http://example.edu/credentials/1872",
			Subject: []verifiable.Subject{{ID: issuerID}},
			Issuer:  &verifiable.Issuer{ID: issuerID},
			CustomFields: map[string]interface{}{
				"first_name": "Jesse",
				"last_name":  "Travis",
				"age":        17,
			},
			// vc as jwt does not use proof, do not set it here.
		})

		ed25519ProofCreator, _ := testsupport.NewKMSSigVerPair(t, kms.ED25519Type, testsupport.AnyPubKeyID)

		vc1JWT, err := vc1.CreateSignedJWTVC(true,
			verifiable.EdDSA,
			ed25519ProofCreator,
			issuerID+"#keys-76e12ec712ebc6f1c221ebfeb1f")
		require.NoError(t, err)

		candidateVCs := []*verifiable.Credential{
			vc1JWT,
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      "http://example.edu/credentials/1872",
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
				},
				Proofs: []verifiable.Proof{{"type": "JsonWebSignature2020"}},
			}),
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      "http://example.edu/credentials/1872",
				Subject: []verifiable.Subject{{ID: issuerID}},
				Issuer:  &verifiable.Issuer{ID: issuerID},
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
					"last_name":  "Travis",
					"age":        17,
				},
				Proofs: []verifiable.Proof{{"type": "JsonWebSignature2020"}},
			}),
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      "http://example.edu/credentials/1872",
				Subject: []verifiable.Subject{{ID: issuerID}},
				Issuer:  &verifiable.Issuer{ID: issuerID},
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
					"last_name":  "Travis",
					"age":        2,
				},
				Proofs: []verifiable.Proof{{"type": "JsonWebSignature2020"}},
			}),
		}

		tests := []struct {
			name    string
			format  string
			vFormat *Format
		}{
			{
				name:   "test LDP format",
				format: FormatLDP,
				vFormat: &Format{
					Ldp: &LdpType{ProofType: []string{"JsonWebSignature2020"}},
				},
			},
			{
				name:   "test LDPVP format",
				format: FormatLDPVP,
				vFormat: &Format{
					LdpVP: &LdpType{ProofType: []string{"JsonWebSignature2020"}},
				},
			},
			{
				name:   "test LDPVC format",
				format: FormatLDPVC,
				vFormat: &Format{
					LdpVC: &LdpType{ProofType: []string{"JsonWebSignature2020"}},
				},
			},
			{
				name:   "test JWT format",
				format: FormatJWT,
				vFormat: &Format{
					Jwt: &JwtType{Alg: []string{"EdDSA"}},
				},
			},
			{
				name:   "test JWTVC format",
				format: FormatJWTVC,
				vFormat: &Format{
					JwtVC: &JwtType{Alg: []string{"EdDSA"}},
				},
			},
			{
				name:   "test JWTVP format",
				format: FormatJWTVP,
				vFormat: &Format{
					JwtVP: &JwtType{Alg: []string{"EdDSA"}},
				},
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				pd := &PresentationDefinition{
					ID: uuid.New().String(),
					SubmissionRequirements: []*SubmissionRequirement{
						{
							Rule: "all",
							From: "A",
						},
						{
							Rule:  "pick",
							Count: 1,
							FromNested: []*SubmissionRequirement{
								{
									Rule: "all",
									From: "teenager",
								},
								{
									Rule: "all",
									From: "child",
								},
								{
									Rule: "pick",
									From: "adult",
									Min:  2,
								},
							},
						},
					},
					InputDescriptors: []*InputDescriptor{{
						ID:    uuid.New().String(),
						Group: []string{"A"},
						Schema: []*Schema{{
							URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
						}},
						Constraints: &Constraints{
							SubjectIsIssuer: &subIsIssuerRequired,
							Fields: []*Field{{
								Path: []string{"$.first_name", "$.last_name"},
							}},
						},
					}, {
						ID:    uuid.New().String(),
						Group: []string{"child"},
						Schema: []*Schema{{
							URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
						}},
						Constraints: &Constraints{
							SubjectIsIssuer: &subIsIssuerRequired,
							Fields: []*Field{{
								Path: []string{"$.age"},
								Filter: &Filter{
									Type:    &intFilterType,
									Minimum: 3,
									Maximum: 12,
								},
							}},
						},
					}, {
						ID:    uuid.New().String(),
						Group: []string{"teenager"},
						Schema: []*Schema{{
							URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
						}},
						Constraints: &Constraints{
							SubjectIsIssuer: &subIsIssuerRequired,
							Fields: []*Field{{
								Path: []string{"$.age"},
								Filter: &Filter{
									Type:    &intFilterType,
									Minimum: 13,
									Maximum: 17,
								},
							}},
						},
					}, {
						ID:    uuid.New().String(),
						Group: []string{"adult"},
						Schema: []*Schema{{
							URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
						}},
						Constraints: &Constraints{
							SubjectIsIssuer: &subIsIssuerRequired,
							Fields: []*Field{{
								Path: []string{"$.age"},
								Filter: &Filter{
									Type:    &intFilterType,
									Minimum: 18,
									Maximum: 23,
								},
							}},
						},
					}},
					Format: tc.vFormat,
				}

				vp, err := pd.CreateVP(candidateVCs, lddl)

				require.NoError(t, err)
				require.NotNil(t, vp)
				require.Equal(t, 1, len(vp.Credentials()))

				checkSubmission(t, vp, pd)
				checkVP(t, vp)
			})
		}
	})

	t.Run("Checks submission requirements (no descriptor)", func(t *testing.T) {
		issuerID := uuid.New().String()

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			SubmissionRequirements: []*SubmissionRequirement{
				{
					Rule: "all",
					From: "A",
				},
				{
					Rule:  "pick",
					Count: 1,
					FromNested: []*SubmissionRequirement{
						{
							Rule: "all",
							From: "teenager",
						},
					},
				},
			},
			InputDescriptors: []*InputDescriptor{{
				ID:    uuid.New().String(),
				Group: []string{"A"},
				Schema: []*Schema{{
					URI: verifiable.ContextURI,
				}},
				Constraints: &Constraints{
					SubjectIsIssuer: &subIsIssuerRequired,
					Fields: []*Field{{
						Path: []string{"$.first_name", "$.last_name"},
					}},
				},
			}},
		}

		vp, err := pd.CreateVP([]*verifiable.Credential{
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
				},
			}), createTestCredential(t, credentialProto{
				ID:      uuid.New().String(),
				Subject: []verifiable.Subject{{ID: issuerID}},
				Issuer:  &verifiable.Issuer{ID: issuerID},
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
					"last_name":  "Travis",
					"age":        17,
				},
			}),
		}, lddl)

		require.EqualError(t, err, "no descriptors for from: teenager")
		require.Nil(t, vp)
	})

	t.Run("request two VCs using separate submission requirements", func(t *testing.T) {
		requirements := []*SubmissionRequirement{
			{
				Rule: All,
				From: "A",
			},
			{
				Rule: All,
				From: "B",
			},
		}

		makeInputDescriptor := func(claim string, groups ...string) *InputDescriptor {
			return &InputDescriptor{
				ID:    "get_" + claim,
				Group: groups,
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
				}},
				Constraints: &Constraints{
					Fields: []*Field{{
						Path: []string{"$." + claim},
					}},
				},
			}
		}

		makeCredential := func(claims ...string) *verifiable.Credential {
			selfIssuedID := uuid.NewString()

			customFields := map[string]interface{}{}

			for _, claim := range claims {
				customFields[claim] = "foo"
			}

			vc := createTestCredential(t, credentialProto{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      "https://example.com/credential/" + uuid.NewString(),
				Subject: []verifiable.Subject{{ID: selfIssuedID}},
				Issued: &utiltime.TimeWrapper{
					Time: time.Now(),
				},
				Issuer: &verifiable.Issuer{
					ID: selfIssuedID,
				},
				CustomFields: customFields,
			})

			return vc
		}

		pd := &PresentationDefinition{
			ID:                     uuid.NewString(),
			SubmissionRequirements: requirements,
			InputDescriptors: []*InputDescriptor{
				makeInputDescriptor("A", "A"),
				makeInputDescriptor("B", "B"),
			},
		}

		credentials := []*verifiable.Credential{
			makeCredential("A"),
			makeCredential("B"),
		}

		vp, err := pd.CreateVP(credentials, lddl)
		require.NoError(t, err)

		require.Equal(t, 2, len(vp.Credentials()))
		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})

	t.Run("Predicate", func(t *testing.T) {
		predicate := Required

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
				}},
				Constraints: &Constraints{
					Fields: []*Field{{
						Path:      []string{"$.first_name", "$.last_name"},
						Predicate: &predicate,
						Filter:    &Filter{Type: &strFilterType},
					}},
				},
			}},
		}

		vp, err := pd.CreateVP([]*verifiable.Credential{
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      "http://example.edu/credentials/1872",
				Subject: []verifiable.Subject{{ID: "did:example:76e12ec712ebc6f1c221ebfeb1f"}},
				Issued: &utiltime.TimeWrapper{
					Time: time.Now(),
				},
				Issuer: &verifiable.Issuer{
					ID: "did:example:76e12ec712ebc6f1c221ebfeb1f",
				},
				CustomFields: map[string]interface{}{
					"first_name": "First name",
					"last_name":  "Last name",
					"info":       "Info",
				},
			}),
		}, lddl, WithSDCredentialOptions(verifiable.WithJSONLDDocumentLoader(createTestJSONLDDocumentLoader(t))))

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, 1, len(vp.Credentials()))

		vc := vp.Credentials()[0]

		require.True(t, vc.CustomField("first_name").(bool))
		require.True(t, vc.CustomField("last_name").(bool))
		require.EqualValues(t, "Info", vc.CustomField("info"))

		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})

	t.Run("Get By Credential Type", func(t *testing.T) {
		const queryByCredType = `{
				   "id": "69ddc987-55c2-4f1f-acea-f2838be10607",
				   "input_descriptors": [
					   {
						   "id": "26b00531-caa1-49f3-a5a1-4a0eae8c0925",
						   "constraints": {
							   "fields": [
								   {
									   "path": [
										   "$.type",
										   "$.vc.type"
									   ],
								 "filter": {
									"type": "array",
									"contains": {
											"type": "string",
											"const": "DemoCred"
											}
								   		}
								   }
							   ]
						   }
					   }
				   ]
				}`

		var pd PresentationDefinition
		require.NoError(t, json.Unmarshal([]byte(queryByCredType), &pd))

		vp, err := pd.CreateVP([]*verifiable.Credential{
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType, "DemoCred"},
				ID:      "http://example.edu/credentials/1872",
				Subject: []verifiable.Subject{{ID: "did:example:76e12ec712ebc6f1c221ebfeb1f"}},
				Issued: &utiltime.TimeWrapper{
					Time: time.Now(),
				},
				Issuer: &verifiable.Issuer{
					ID: "did:example:76e12ec712ebc6f1c221ebfeb1f",
				},
				CustomFields: map[string]interface{}{
					"first_name": "First name",
					"last_name":  "Last name",
					"info":       "Info",
				},
			}),
		}, lddl, WithSDCredentialOptions(verifiable.WithJSONLDDocumentLoader(createTestJSONLDDocumentLoader(t))))

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, 1, len(vp.Credentials()))

		checkSubmission(t, vp, &pd)
		checkVP(t, vp)
	})

	t.Run("Predicate (limit disclosure) LDP", func(t *testing.T) {
		required := Required

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
				}},
				Constraints: &Constraints{
					LimitDisclosure: &required,
					Fields: []*Field{{
						Path:      []string{"$.first_name", "$.last_name"},
						Predicate: &required,
						Filter:    &Filter{Type: &strFilterType},
					}},
				},
			}},
		}

		vp, err := pd.CreateVP([]*verifiable.Credential{
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      "http://example.edu/credentials/1872",
				Subject: []verifiable.Subject{{ID: "did:example:76e12ec712ebc6f1c221ebfeb1f"}},
				Issued: &utiltime.TimeWrapper{
					Time: time.Now(),
				},
				Issuer: &verifiable.Issuer{
					ID: "did:example:76e12ec712ebc6f1c221ebfeb1f",
				},
				CustomFields: map[string]interface{}{
					"first_name": "First name",
					"last_name":  "Last name",
					"info":       "Info",
				},
			}),
		}, lddl, WithSDCredentialOptions(verifiable.WithJSONLDDocumentLoader(createTestJSONLDDocumentLoader(t))))

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, 1, len(vp.Credentials()))

		vc := vp.Credentials()[0]

		require.True(t, vc.CustomField("first_name").(bool))
		require.True(t, vc.CustomField("last_name").(bool))
		require.False(t, vc.IsJWT())
		require.Nil(t, vc.Proofs())

		require.Nil(t, vc.CustomField("info"))

		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})

	t.Run("Predicate (limit disclosure) JWT", func(t *testing.T) {
		required := Required

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
				}},
				Constraints: &Constraints{
					LimitDisclosure: &required,
					Fields: []*Field{{
						Path:      []string{"$.first_name", "$.last_name"},
						Predicate: &required,
						Filter:    &Filter{Type: &strFilterType},
					}},
				},
			}},
		}

		credProto := createTestCredential(t, credentialProto{
			Context: []string{verifiable.ContextURI},
			Types:   []string{verifiable.VCType},
			ID:      "http://example.edu/credentials/1872",
			Subject: []verifiable.Subject{{ID: "did:example:76e12ec712ebc6f1c221ebfeb1f"}},
			Issued: &utiltime.TimeWrapper{
				Time: time.Now(),
			},
			Issuer: &verifiable.Issuer{
				ID: "did:example:76e12ec712ebc6f1c221ebfeb1f",
			},
			CustomFields: map[string]interface{}{
				"first_name": "First name",
				"last_name":  "Last name",
				"info":       "Info",
			},
		})

		cred, err := credProto.CreateUnsecuredJWTVC(false)
		require.NoError(t, err)

		originalJWTStr, err := cred.ToJWTString()
		require.NoError(t, err)

		vp, err := pd.CreateVP([]*verifiable.Credential{cred},
			lddl, WithSDCredentialOptions(verifiable.WithJSONLDDocumentLoader(createTestJSONLDDocumentLoader(t))))

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, 1, len(vp.Credentials()))

		vc := vp.Credentials()[0]

		require.True(t, vc.CustomField("first_name").(bool))
		require.True(t, vc.CustomField("last_name").(bool))
		require.Nil(t, vc.Proofs())

		require.Nil(t, vc.CustomField("info"))

		jwtStr, err := vc.ToJWTString()

		// Check parsed JWT.
		require.NoError(t, err)
		require.False(t, jwtStr == originalJWTStr)
		vc, err = verifiable.ParseCredential([]byte(jwtStr),
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(createTestJSONLDDocumentLoader(t)))
		require.NoError(t, err)

		require.True(t, vc.CustomField("first_name").(bool))
		require.True(t, vc.CustomField("last_name").(bool))
		require.Nil(t, vc.Proofs())

		require.Nil(t, vc.CustomField("info"))

		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})

	t.Run("SD-JWT: Limit Disclosure + SD Claim paths", func(t *testing.T) {
		required := Required

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
				}},
				Constraints: &Constraints{
					LimitDisclosure: &required,
					Fields: []*Field{{
						Path: []string{
							"$.credentialSubject.family_name",
							"$.credentialSubject.given_name",
							"$.credentialSubject.address.country",
						},
					}},
				},
			}},
		}

		ed25519ProofCreator, proofChecker := testsupport.NewKMSSigVerPair(t, kms.ED25519Type, testsupport.AnyPubKeyID)

		sdJwtVC := newSdJwtVC(t, ed25519ProofCreator, proofChecker)

		vp, err := pd.CreateVP([]*verifiable.Credential{sdJwtVC},
			lddl, WithSDCredentialOptions(verifiable.WithJSONLDDocumentLoader(createTestJSONLDDocumentLoader(t))))

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, 1, len(vp.Credentials()))

		vc := vp.Credentials()[0]
		vcc := vc.Contents()

		require.Len(t, vc.SDJWTDisclosures(), 3)

		require.Len(t, vcc.Subject[0].CustomFields["_sd"].([]interface{}), 6)
		require.NotNil(t, vcc.Subject[0].CustomFields["address"])

		_, ok := vcc.Subject[0].CustomFields["email"]
		require.False(t, ok)

		displayVC, err := vc.CreateDisplayCredential(verifiable.DisplayAllDisclosures())
		require.NoError(t, err)

		displayVCC := displayVC.Contents()

		printObject(t, "Display VC - Limited", displayVC)

		require.Equal(t, "John", displayVCC.Subject[0].CustomFields["given_name"])
		require.Equal(t, "Doe", displayVCC.Subject[0].CustomFields["family_name"])

		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})

	t.Run("SD-JWT: Limit Disclosure + SD Claim paths + additional filter", func(t *testing.T) {
		required := Required

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
				}},
				Constraints: &Constraints{
					LimitDisclosure: &required,
					Fields: []*Field{
						{
							Path: []string{
								"$.credentialSubject.family_name",
								"$.credentialSubject.given_name",
								"$.credentialSubject.address.country",
							},
						},
						{
							Path: []string{
								"$.credentialSchema[0].id", "$.credentialSchema.id", "$.vc.credentialSchema.id"},
							Filter: &Filter{
								Type:  &strFilterType,
								Const: "https://www.w3.org/TR/vc-data-model/2.0/#types",
							},
						},
					},
				},
			}},
		}

		ed25519ProofCreator, proofChecker := testsupport.NewKMSSigVerPair(t, kms.ED25519Type, testsupport.AnyPubKeyID)

		sdJwtVC := newSdJwtVC(t, ed25519ProofCreator, proofChecker)

		vp, err := pd.CreateVP([]*verifiable.Credential{sdJwtVC},
			lddl, WithSDCredentialOptions(verifiable.WithJSONLDDocumentLoader(createTestJSONLDDocumentLoader(t))))

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, 1, len(vp.Credentials()))

		vc := vp.Credentials()[0]
		vcc := vc.Contents()

		require.Len(t, vc.SDJWTDisclosures(), 3)

		require.Len(t, vcc.Subject[0].CustomFields["_sd"].([]interface{}), 6)
		require.NotNil(t, vcc.Subject[0].CustomFields["address"])

		_, ok := vcc.Subject[0].CustomFields["email"]
		require.False(t, ok)

		displayVC, err := vc.CreateDisplayCredential(verifiable.DisplayAllDisclosures())
		require.NoError(t, err)

		displayVCC := displayVC.Contents()

		printObject(t, "Display VC", displayVC)

		require.Equal(t, "John", displayVCC.Subject[0].CustomFields["given_name"])
		require.Equal(t, "Doe", displayVCC.Subject[0].CustomFields["family_name"])

		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})

	t.Run("SD-JWT: Limit Disclosure + non-SD claim path", func(t *testing.T) {
		required := Required

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
				}},
				Constraints: &Constraints{
					LimitDisclosure: &required,
					Fields: []*Field{{
						Path: []string{
							"$.id",
						},
					}},
				},
			}},
		}

		ed25519ProofCreator, proofChecker := testsupport.NewKMSSigVerPair(t, kms.ED25519Type, testsupport.AnyPubKeyID)

		sdJwtVC := newSdJwtVC(t, ed25519ProofCreator, proofChecker)

		vp, err := pd.CreateVP([]*verifiable.Credential{sdJwtVC},
			lddl, WithSDCredentialOptions(verifiable.WithJSONLDDocumentLoader(createTestJSONLDDocumentLoader(t))))

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, 1, len(vp.Credentials()))

		vc := vp.Credentials()[0]
		vcc := vc.Contents()

		// there is only one non-SD claim path is in the fields array - hence no selective disclosures
		require.Len(t, vc.SDJWTDisclosures(), 0)

		require.Len(t, vcc.Subject[0].CustomFields["_sd"].([]interface{}), 6)

		displayVC, err := vc.CreateDisplayCredential(verifiable.DisplayAllDisclosures())
		require.NoError(t, err)

		displayVCC := displayVC.Contents()

		printObject(t, "Display VC - No Selective Disclosures", displayVC)

		require.Nil(t, displayVCC.Subject[0].CustomFields["given_name"])
		require.Nil(t, displayVCC.Subject[0].CustomFields["email"])

		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})

	t.Run("SD-JWT: No Limit Disclosure + Predicate Satisfied", func(t *testing.T) {
		required := Required

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
				}},
				Constraints: &Constraints{
					Fields: []*Field{{
						Path: []string{
							"$.credentialSubject.family_name",
						},
						Predicate: &required,
						Filter:    &Filter{Type: &strFilterType},
					}},
				},
			}},
		}

		ed25519ProofCreator, proofChecker := testsupport.NewKMSSigVerPair(t, kms.ED25519Type, testsupport.AnyPubKeyID)

		sdJwtVC := newSdJwtVC(t, ed25519ProofCreator, proofChecker)

		vp, err := pd.CreateVP([]*verifiable.Credential{sdJwtVC},
			lddl, WithSDCredentialOptions(verifiable.WithJSONLDDocumentLoader(createTestJSONLDDocumentLoader(t))))

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, 1, len(vp.Credentials()))

		vc := vp.Credentials()[0]
		vcc := vc.Contents()

		require.Len(t, vc.SDJWTDisclosures(), 10)

		require.Len(t, vcc.Subject[0].CustomFields["_sd"].([]interface{}), 6)
		require.NotNil(t, vcc.Subject[0].CustomFields["address"])

		_, ok := vcc.Subject[0].CustomFields["email"]
		require.False(t, ok)

		displayVC, err := vc.CreateDisplayCredential(verifiable.DisplayAllDisclosures())
		require.NoError(t, err)

		displayVCC := displayVC.Contents()

		printObject(t, "Display VC - No Limit Disclosure (all fields displayed)", displayVC)

		require.Equal(t, "John", displayVCC.Subject[0].CustomFields["given_name"])
		require.Equal(t, "Doe", displayVCC.Subject[0].CustomFields["family_name"])
		require.Equal(t, "johndoe@example.com", displayVCC.Subject[0].CustomFields["email"])

		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})

	/*t.Run("SD-JWT: hash algorithm not supported", func(t *testing.T) {
		required := Required

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
				}},
				Constraints: &Constraints{
					LimitDisclosure: &required,
					Fields: []*Field{{
						Path: []string{
							"$.credentialSubject.given_name",
						},
					}},
				},
			}},
		}

		ed25519ProofCreator, proofChecker := testsupport.NewKMSSigVerPair(t,  kms.ED25519Type)

		sdJwtVC := newSdJwtVC(t, ed25519ProofCreator, proofChecker)

		sdJwtVC.SDJWTHashAlg = "sha-128"

		vp, err := pd.CreateVP([]*verifiable.Credential{sdJwtVC},
			lddl, WithSDCredentialOptions(verifiable.WithJSONLDDocumentLoader(createTestJSONLDDocumentLoader(t))))

		require.Error(t, err)
		require.Nil(t, vp)
		require.Contains(t, err.Error(), "_sd_alg 'sha-128' not supported")
	})*/

	t.Run("SD-JWT: invalid JSON path ", func(t *testing.T) {
		required := Required

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
				}},
				Constraints: &Constraints{
					LimitDisclosure: &required,
					Fields: []*Field{{
						Path: []string{
							"123",
						},
					}},
				},
			}},
		}

		ed25519ProofCreator, proofChecker := testsupport.NewKMSSigVerPair(t, kms.ED25519Type, testsupport.AnyPubKeyID)

		sdJwtVC := newSdJwtVC(t, ed25519ProofCreator, proofChecker)

		vp, err := pd.CreateVP([]*verifiable.Credential{sdJwtVC},
			lddl, WithSDCredentialOptions(verifiable.WithJSONLDDocumentLoader(createTestJSONLDDocumentLoader(t))))

		require.Error(t, err)
		require.Nil(t, vp)
		require.Contains(t, err.Error(), "Expected $ or @ at start of path instead of  U+0031")
	})

	t.Run("SD-JWT: Limit Disclosure (credentials don't meet requirement)", func(t *testing.T) {
		required := Required

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
				}},
				Constraints: &Constraints{
					LimitDisclosure: &required,
					Fields: []*Field{{
						Path: []string{
							"$.credentialSubject.family_name",
							"$.credentialSubject.given_name",
							"$.credentialSubject.address.country",
						},
						Predicate: &required,
						Filter:    &Filter{Type: &arrFilterType},
					}},
				},
			}},
		}

		ed25519ProofCreator, proofChecker := testsupport.NewKMSSigVerPair(t, kms.ED25519Type, testsupport.AnyPubKeyID)

		sdJwtVC := newSdJwtVC(t, ed25519ProofCreator, proofChecker)

		vp, err := pd.CreateVP([]*verifiable.Credential{sdJwtVC},
			lddl, WithSDCredentialOptions(verifiable.WithJSONLDDocumentLoader(createTestJSONLDDocumentLoader(t))))

		require.Error(t, err)
		require.Nil(t, vp)
		require.Contains(t, err.Error(), "credentials do not satisfy requirements")
	})

	t.Run("SD-JWT: No Limit Disclosure (credentials don't meet requirement)", func(t *testing.T) {
		required := Required

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
				}},
				Constraints: &Constraints{
					Fields: []*Field{{
						Path: []string{
							"$.credentialSubject.family_name",
							"$.credentialSubject.given_name",
							"$.credentialSubject.address.country",
						},
						Predicate: &required,
						Filter:    &Filter{Type: &arrFilterType},
					}},
				},
			}},
		}

		ed25519ProofCreator, proofChecker := testsupport.NewKMSSigVerPair(t, kms.ED25519Type, testsupport.AnyPubKeyID)

		sdJwtVC := newSdJwtVC(t, ed25519ProofCreator, proofChecker)

		vp, err := pd.CreateVP([]*verifiable.Credential{sdJwtVC},
			lddl, WithSDCredentialOptions(verifiable.WithJSONLDDocumentLoader(createTestJSONLDDocumentLoader(t))))

		require.Error(t, err)
		require.Nil(t, vp)
		require.Contains(t, err.Error(), "credentials do not satisfy requirements")
	})

	t.Run("SD-JWT: Limit Disclosure with invalid field (credentials don't meet requirement)", func(t *testing.T) {
		required := Required

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
				}},
				Constraints: &Constraints{
					LimitDisclosure: &required,
					Fields: []*Field{{
						Path: []string{
							"$.credentialSubject.invalid",
						},
					}},
				},
			}},
		}

		ed25519ProofCreator, proofChecker := testsupport.NewKMSSigVerPair(t, kms.ED25519Type, testsupport.AnyPubKeyID)

		sdJwtVC := newSdJwtVC(t, ed25519ProofCreator, proofChecker)

		vp, err := pd.CreateVP([]*verifiable.Credential{sdJwtVC},
			lddl, WithSDCredentialOptions(verifiable.WithJSONLDDocumentLoader(createTestJSONLDDocumentLoader(t))))

		require.Error(t, err)
		require.Nil(t, vp)
		require.Contains(t, err.Error(), "credentials do not satisfy requirements")
	})

	t.Run("Limit disclosure BBS+", func(t *testing.T) {
		required := Required

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
				}},
				ID: uuid.New().String(),
				Constraints: &Constraints{
					LimitDisclosure: &required,
					Fields: []*Field{{
						Path:   []string{"$.credentialSubject.degree.degreeSchool"},
						Filter: &Filter{Type: &strFilterType},
					}},
				},
			}},
		}

		vc := createTestCredential(t, credentialProto{
			ID: "https://issuer.oidp.uscis.gov/credentials/83627465",
			Context: []string{
				verifiable.ContextURI,
				"https://www.w3.org/2018/credentials/examples/v1",
				"https://w3id.org/security/bbs/v1",
			},
			Types: []string{
				"VerifiableCredential",
				"UniversityDegreeCredential",
			},
			Subject: []verifiable.Subject{{
				ID: "did:example:b34ca6cd37bbf23",
				CustomFields: map[string]interface{}{
					"name":   "Jayden Doe",
					"spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1",
					"degree": map[string]interface{}{
						"degree":       "MIT",
						"degreeSchool": "MIT school",
						"type":         "BachelorDegree",
					},
				}},
			},
			Issued: &utiltime.TimeWrapper{
				Time: time.Now(),
			},
			Expired: &utiltime.TimeWrapper{
				Time: time.Now().AddDate(1, 0, 0),
			},
			Issuer: &verifiable.Issuer{
				ID: "did:example:489398593",
			},
			CustomFields: map[string]interface{}{
				"identifier":  "83627465",
				"name":        "Permanent Resident Card",
				"description": "Government of Example Permanent Resident Card.",
			},
		})

		publicKey, privateKey, err := bbs12381g2pub.GenerateKeyPair(sha256.New, nil)
		require.NoError(t, err)

		srcPublicKey, err := publicKey.Marshal()
		require.NoError(t, err)

		signer, err := newBBSSigner(privateKey)
		require.NoError(t, err)

		require.NoError(t, vc.AddLinkedDataProof(&verifiable.LinkedDataProofContext{
			SignatureType:           "BbsBlsSignature2020",
			KeyType:                 kms.BLS12381G2Type,
			SignatureRepresentation: verifiable.SignatureProofValue,
			ProofCreator:            creator.New(creator.WithProofType(bbsblssignature2020.New(), signer)),
			VerificationMethod:      "did:example:123456#key1",
		}, ldprocessor.WithDocumentLoader(createTestJSONLDDocumentLoader(t))))

		vp, err := pd.CreateVP([]*verifiable.Credential{vc}, lddl,
			WithSDBBSProofCreator(&bbsblssignatureproof2020.Creator{
				ProofDelivery: bbs12381g2pub.New(),
				VerificationMethodResolver: testsupport.NewSingleKeyResolver(
					"did:example:123456#key1", srcPublicKey, "Bls12381G2Key2020"),
			}),
			WithSDCredentialOptions(
				verifiable.WithJSONLDDocumentLoader(createTestJSONLDDocumentLoader(t)),
			),
		)
		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, 1, len(vp.Credentials()))

		vc = vp.Credentials()[0]
		vcc := vc.Contents()

		subject := vcc.Subject[0]
		degree := subject.CustomFields["degree"]
		require.NotNil(t, degree)

		degreeMap, ok := degree.(map[string]interface{})
		require.True(t, ok)

		require.Equal(t, "MIT school", degreeMap["degreeSchool"])
		require.Equal(t, "BachelorDegree", degreeMap["type"])
		require.Empty(t, degreeMap["degree"])
		require.Equal(t, "did:example:b34ca6cd37bbf23", subject.ID)
		require.Empty(t, subject.CustomFields["spouse"])
		require.Empty(t, vc.CustomField("name"))

		require.NotEmpty(t, vc.Proofs())

		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})

	t.Run("Predicate and limit disclosure BBS+ (no proof)", func(t *testing.T) {
		required := Required

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
				}},
				ID: uuid.New().String(),
				Constraints: &Constraints{
					LimitDisclosure: &required,
					Fields: []*Field{{
						Path:      []string{"$.credentialSubject.givenName", "$.credentialSubject.familyName"},
						Filter:    &Filter{Type: &strFilterType},
						Predicate: &required,
					}, {
						Path:   []string{"$.credentialSubject.type"},
						Filter: &Filter{Type: &arrFilterType},
					}},
				},
			}},
		}

		vc := createTestCredential(t, credentialProto{
			ID: "https://issuer.oidp.uscis.gov/credentials/83627465",
			Context: []string{
				verifiable.ContextURI,
				"https://w3id.org/citizenship/v1",
				"https://w3id.org/security/bbs/v1",
			},
			Types: []string{
				"VerifiableCredential",
				"PermanentResidentCard",
			},
			Subject: []verifiable.Subject{{
				ID: "did:example:b34ca6cd37bbf23",
				CustomFields: map[string]interface{}{
					"type": []interface{}{
						"PermanentResident",
						"Person",
					},
					"givenName":              "JOHN",
					"familyName":             "SMITH",
					"gender":                 "Male",
					"image":                  "data:image/png;base64,iVBORw0KGgokJggg==",
					"residentSince":          "2015-01-01",
					"lprCategory":            "C09",
					"lprNumber":              "999-999-999",
					"commuterClassification": "C1",
					"birthCountry":           "Bahamas",
					"birthDate":              "1958-07-17",
				},
			}},
			Issued: &utiltime.TimeWrapper{
				Time: time.Now(),
			},
			Expired: &utiltime.TimeWrapper{
				Time: time.Now().AddDate(1, 0, 0),
			},
			Issuer: &verifiable.Issuer{
				ID: "did:example:489398593",
			},
			CustomFields: map[string]interface{}{
				"identifier":  "83627465",
				"name":        "Permanent Resident Card",
				"description": "Government of Example Permanent Resident Card.",
			},
		})

		publicKey, privateKey, err := bbs12381g2pub.GenerateKeyPair(sha256.New, nil)
		require.NoError(t, err)

		srcPublicKey, err := publicKey.Marshal()
		require.NoError(t, err)

		signer, err := newBBSSigner(privateKey)
		require.NoError(t, err)

		require.NoError(t, vc.AddLinkedDataProof(&verifiable.LinkedDataProofContext{
			SignatureType:           "BbsBlsSignature2020",
			KeyType:                 kms.BLS12381G2Type,
			SignatureRepresentation: verifiable.SignatureProofValue,
			ProofCreator:            creator.New(creator.WithProofType(bbsblssignature2020.New(), signer)),
			VerificationMethod:      "did:example:123456#key1",
		}, ldprocessor.WithDocumentLoader(createTestJSONLDDocumentLoader(t))))

		vp, err := pd.CreateVP([]*verifiable.Credential{vc}, lddl,
			WithSDCredentialOptions(
				verifiable.WithJSONLDDocumentLoader(createTestJSONLDDocumentLoader(t)),
				verifiable.WithProofChecker(defaults.NewDefaultProofChecker(testsupport.NewSingleKeyResolver(
					"did:example:123456#key1", srcPublicKey, "Bls12381G2Key2020"))),
			),
		)
		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, 1, len(vp.Credentials()))

		vc = vp.Credentials()[0]
		vcc := vc.Contents()

		require.Equal(t, true, vcc.Subject[0].CustomFields["givenName"])
		require.Equal(t, true, vcc.Subject[0].CustomFields["familyName"])
		require.Empty(t, vcc.Subject[0].CustomFields["gender"])
		require.Empty(t, vc.Proofs())

		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})

	t.Run("Predicate (marshal error)", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: verifiable.ContextID,
				}},
				Constraints: &Constraints{
					Fields: []*Field{{
						Path:   []string{"$.last_name"},
						Filter: &Filter{Type: &strFilterType},
					}},
				},
			}},
		}

		vp, err := pd.CreateVP([]*verifiable.Credential{
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				CustomFields: map[string]interface{}{
					"first_name": make(chan struct{}),
					"last_name":  "Jon",
				},
			}),
		}, lddl)

		require.EqualError(t, err, errMsgSchema)
		require.Nil(t, vp)
	})

	t.Run("No matches (path)", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: verifiable.ContextID,
				}},
				Constraints: &Constraints{
					Fields: []*Field{{
						Path: []string{"$.first_name", "$.last_name"},
					}},
				},
			}},
		}

		vp, err := pd.CreateVP([]*verifiable.Credential{
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
				},
			}),
			createTestCredential(t, credentialProto{
				ID: uuid.New().String(),
				CustomFields: map[string]interface{}{
					"last_name": "Travis",
				},
			}),
		}, lddl)

		require.EqualError(t, err, errMsgSchema)
		require.Nil(t, vp)
	})

	t.Run("No matches (one field path)", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: verifiable.ContextID,
				}},
				Constraints: &Constraints{
					Fields: []*Field{{
						Path: []string{"$.first_name"},
					}, {
						Path: []string{"$.last_name"},
					}},
				},
			}},
		}

		vp, err := pd.CreateVP([]*verifiable.Credential{
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
				},
			}),
			createTestCredential(t, credentialProto{
				ID: uuid.New().String(),
				CustomFields: map[string]interface{}{
					"last_name": "Travis",
				},
			}),
		}, lddl)

		require.EqualError(t, err, errMsgSchema)
		require.Nil(t, vp)
	})

	t.Run("Matches one credentials (two fields)", func(t *testing.T) {
		issuerID := uuid.New().String()

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
				}},
				Constraints: &Constraints{
					SubjectIsIssuer: &subIsIssuerRequired,
					Fields: []*Field{{
						Path:   []string{"$.first_name"},
						Filter: &Filter{Type: &strFilterType},
					}, {
						Path:   []string{"$.last_name"},
						Filter: &Filter{Type: &strFilterType},
					}},
				},
			}},
		}

		vp, err := pd.CreateVP([]*verifiable.Credential{
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Subject: []verifiable.Subject{},
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
				},
			}), createTestCredential(t, credentialProto{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Subject: []verifiable.Subject{{ID: issuerID}},
				Issuer:  &verifiable.Issuer{ID: issuerID},
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
					"last_name":  "Travis",
				},
			}),
		}, lddl)

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, 1, len(vp.Credentials()))

		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})

	t.Run("Matches one credentials (three fields - disclosure)", func(t *testing.T) {
		issuerID := "did:example:76e12ec712ebc6f1c221ebfeb1f"
		required := Required

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
				}},
				Constraints: &Constraints{
					SubjectIsIssuer: &subIsIssuerRequired,
					LimitDisclosure: &required,
					Fields: []*Field{{
						Path:   []string{"$.first_name"},
						Filter: &Filter{Type: &strFilterType},
					}, {
						Path:   []string{"$.issuer"},
						Filter: &Filter{Type: &strFilterType},
					}, {
						Path: []string{"$.all[*].authors[*].name"},
						Filter: &Filter{
							Type: &arrFilterType,
						},
					}},
				},
			}},
		}

		vp, err := pd.CreateVP([]*verifiable.Credential{
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Subject: []verifiable.Subject{{}},
				Issuer:  &verifiable.Issuer{ID: uuid.New().String()},
				CustomFields: map[string]interface{}{
					"last_name": "Travis",
				},
			}),
			createTestCredential(t, credentialProto{
				ID:      "http://example.edu/credentials/1872",
				Context: []string{verifiable.ContextURI},
				Types:   []string{"VerifiableCredential"},
				Subject: []verifiable.Subject{{ID: issuerID}},
				Issuer:  &verifiable.Issuer{ID: issuerID},
				Issued: &utiltime.TimeWrapper{
					Time: time.Now(),
				},
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
					"ssn":        "000-00-000",
					"last_name":  "Travis",
					"all": []interface{}{
						map[string]interface{}{
							"authors": []interface{}{map[string]interface{}{
								"name":    "Andrew",
								"license": "yes",
							}, map[string]interface{}{
								"name":    "Jessy",
								"license": "no",
							}},
						},
						map[string]interface{}{
							"authors": []interface{}{map[string]interface{}{
								"license": "unknown",
							}},
						},
						map[string]interface{}{
							"authors": []interface{}{map[string]interface{}{
								"name":    "Bob",
								"license": "yes",
							}, map[string]interface{}{
								"name":    "Carol",
								"license": "no",
							}},
						},
					},
				},
			}),
		}, lddl, WithSDCredentialOptions(verifiable.WithJSONLDDocumentLoader(createTestJSONLDDocumentLoader(t))))

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, 1, len(vp.Credentials()))

		cred := vp.Credentials()[0]
		require.NotEmpty(t, cred.Contents().Issuer)

		require.EqualValues(t, []interface{}{
			map[string]interface{}{
				"authors": []interface{}{map[string]interface{}{
					"name": "Andrew",
				}, map[string]interface{}{
					"name": "Jessy",
				}},
			},
			map[string]interface{}{
				"authors": []interface{}{map[string]interface{}{
					"name": "Bob",
				}, map[string]interface{}{
					"name": "Carol",
				}},
			},
		}, cred.CustomField("all"))

		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})

	t.Run("Create new credential (error)", func(t *testing.T) {
		required := Required

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
				}},
				Constraints: &Constraints{
					LimitDisclosure: &required,
					Fields: []*Field{{
						Path: []string{"$.first_name"},
						Filter: &Filter{
							Type:    &strFilterType,
							Pattern: "^Jesse",
						},
						Predicate: &required,
					}},
				},
			}},
		}

		vp, err := pd.CreateVP([]*verifiable.Credential{
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Issuer:  &verifiable.Issuer{CustomFields: map[string]interface{}{"k": "v"}},
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
				},
			}),
		}, lddl)

		require.Error(t, err)
		require.True(t, strings.HasPrefix(err.Error(), "create new credential"))
		require.Nil(t, vp)
	})

	t.Run("Matches one credentials (field pattern)", func(t *testing.T) {
		issuerID := uuid.New().String()

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
				}},
				Constraints: &Constraints{
					SubjectIsIssuer: &subIsIssuerRequired,
					Fields: []*Field{{
						Path: []string{"$.first_name"},
						Filter: &Filter{
							Type:    &strFilterType,
							Pattern: "^Jesse",
						},
					}},
				},
			}},
		}

		vp, err := pd.CreateVP([]*verifiable.Credential{
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Subject: []verifiable.Subject{{ID: issuerID}},
				Issuer:  &verifiable.Issuer{ID: issuerID},
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
				},
			}),
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Subject: []verifiable.Subject{{ID: "123"}},
				CustomFields: map[string]interface{}{
					"first_name": "Travis",
					"last_name":  "Jesse",
				},
			}),
		}, lddl)

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, 1, len(vp.Credentials()))

		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})

	t.Run("Matches one credentials", func(t *testing.T) {
		issuerID := uuid.New().String()

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
				}},
				Constraints: &Constraints{
					SubjectIsIssuer: &subIsIssuerRequired,
					Fields: []*Field{{
						Path: []string{"$.first_name", "$.last_name"},
					}},
				},
			}},
		}

		vp, err := pd.CreateVP([]*verifiable.Credential{
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
				},
			}),
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Subject: []verifiable.Subject{{ID: issuerID}},
				Issuer:  &verifiable.Issuer{ID: issuerID},
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
					"last_name":  "Travis",
				},
			}),
		}, lddl)

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, 1, len(vp.Credentials()))

		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})

	t.Run("Matches one credentials (two descriptors)", func(t *testing.T) {
		issuerID := uuid.New().String()

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
				}},
				Constraints: &Constraints{
					SubjectIsIssuer: &subIsIssuerRequired,
					Fields: []*Field{{
						Path: []string{"$.first_name"},
					}, {
						Path: []string{"$.last_name"},
					}},
				},
			}, {
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
				}},
				Constraints: &Constraints{
					Fields: []*Field{{
						Path: []string{"$.first_name"},
					}, {
						Path: []string{"$.last_name"},
					}},
				},
			}},
		}

		vp, err := pd.CreateVP([]*verifiable.Credential{
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Subject: []verifiable.Subject{{ID: issuerID}},
				Issuer:  &verifiable.Issuer{ID: issuerID},
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
				},
			}),
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Subject: []verifiable.Subject{{ID: issuerID}},
				Issuer:  &verifiable.Issuer{ID: issuerID},
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
					"last_name":  "Travis",
				},
			}),
		}, lddl)

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, 1, len(vp.Credentials()))

		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})

	t.Run("Matches two credentials (one descriptor)", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
				}},
				Constraints: &Constraints{
					Fields: []*Field{{
						Path: []string{"$.first_name"},
					}},
				},
			}},
		}

		vp, err := pd.CreateVP([]*verifiable.Credential{
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
				},
			}),
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
					"last_name":  "Travis",
				},
			}),
		}, lddl)

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, 2, len(vp.Credentials()))

		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})

	t.Run("Matches two credentials", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
				}},
			}},
		}

		vp, err := pd.CreateVP([]*verifiable.Credential{
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
			}),
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
			}),
		}, lddl)

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, 2, len(vp.Credentials()))

		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})

	t.Run("Matches one credentials (one ignored)", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: "https://example.org/examples#UniversityDegreeCredential",
				}},
			}},
		}

		vp, err := pd.CreateVP([]*verifiable.Credential{
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
			}),
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.ContextURI, "https://www.w3.org/2018/credentials/examples/v1"},
				Types:   []string{verifiable.VCType, "UniversityDegreeCredential"},
				ID:      uuid.New().String(),
			}),
		}, lddl)

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, 1, len(vp.Credentials()))

		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})

	t.Run("No matches", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: "https://www.w3.org/TR/vc-data-model/1.0/#types",
				}},
			}},
		}

		vp, err := pd.CreateVP([]*verifiable.Credential{
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Schemas: []verifiable.TypedID{{
					ID:   "https://www.w3.org/TR/vc-data-model/2.0/#types",
					Type: "JsonSchemaValidator2018",
				}},
			}),
			createTestCredential(t, credentialProto{
				ID: uuid.New().String(),
				Schemas: []verifiable.TypedID{{
					ID:   "https://www.w3.org/TR/vc-data-model/3.0/#types",
					Type: "JsonSchemaValidator2018",
				}},
			}),
		}, lddl)

		require.EqualError(t, err, errMsgSchema)
		require.Nil(t, vp)
	})

	t.Run("Matches two descriptors", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: "https://example.org/examples#UniversityDegreeCredential",
				}},
			}, {
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: "https://example.org/examples#DocumentVerification",
				}},
			}},
		}

		vp, err := pd.CreateVP([]*verifiable.Credential{
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.ContextURI, "https://www.w3.org/2018/credentials/examples/v1"},
				Types:   []string{verifiable.VCType, "UniversityDegreeCredential"},
				ID:      uuid.New().String(),
			}),
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.ContextURI, "https://trustbloc.github.io/context/vc/examples-v1.jsonld"},
				Types:   []string{verifiable.VCType, "DocumentVerification"},
				ID:      uuid.New().String(),
			}),
		}, lddl)

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, 2, len(vp.Credentials()))

		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})

	t.Run("Does not match one of descriptors", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: "https://www.w3.org/TR/vc-data-model/1.0/#types",
				}},
			}, {
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: "https://www.w3.org/TR/vc-data-model/2.0/#types",
				}},
			}},
		}

		vp, err := pd.CreateVP([]*verifiable.Credential{
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Schemas: []verifiable.TypedID{{
					ID:   "https://www.w3.org/TR/vc-data-model/1.0/#types",
					Type: "JsonSchemaValidator2018",
				}},
			}),
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Schemas: []verifiable.TypedID{{
					ID:   "https://www.w3.org/TR/vc-data-model/3.0/#types",
					Type: "JsonSchemaValidator2018",
				}},
			}),
		}, lddl)

		require.EqualError(t, err, errMsgSchema)
		require.Nil(t, vp)
	})

	t.Run("Does not match one of descriptors (required)", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: "https://www.w3.org/TR/vc-data-model/1.0/#types",
				}},
			}, {
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: "https://www.w3.org/TR/vc-data-model/2.0/#types",
				}, {
					URI:      "https://www.w3.org/TR/vc-data-model/3.0/#types",
					Required: true,
				}},
			}},
		}
		vp, err := pd.CreateVP([]*verifiable.Credential{
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Schemas: []verifiable.TypedID{{
					ID:   "https://www.w3.org/TR/vc-data-model/1.0/#types",
					Type: "JsonSchemaValidator2018",
				}},
			}),
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Schemas: []verifiable.TypedID{{
					ID: "https://www.w3.org/TR/vc-data-model/2.0/#types",
				}},
			}),
		}, lddl)

		require.EqualError(t, err, errMsgSchema)
		require.Nil(t, vp)
	})

	t.Run("Validates schema that only has type", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI:      verifiable.VCType,
					Required: true,
				}},
			}},
		}
		vp, err := pd.CreateVP([]*verifiable.Credential{
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
			}),
		}, lddl)

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, 1, len(vp.Credentials()))

		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})

	t.Run("Ignores schema that is not required", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: "https://example.org/examples#DocumentVerification",
				}},
			}, {
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: "https://www.w3.org/TR/vc-data-model/2.0/#types",
				}, {
					URI:      fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
					Required: true,
				}},
			}},
		}
		vp, err := pd.CreateVP([]*verifiable.Credential{
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
			}),
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.ContextURI, "https://trustbloc.github.io/context/vc/examples-v1.jsonld"},
				Types:   []string{verifiable.VCType, "DocumentVerification"},
				ID:      uuid.New().String(),
			}),
		}, lddl)

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, 2, len(vp.Credentials()))

		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})

	t.Run("Requires two schemas", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
				}},
			}, {
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI:      "https://example.org/examples#UniversityDegreeCredential",
					Required: true,
				}, {
					URI:      "https://example.org/examples#DocumentVerification",
					Required: true,
				}},
			}},
		}
		vp, err := pd.CreateVP([]*verifiable.Credential{
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Schemas: []verifiable.TypedID{{
					ID:   "https://www.w3.org/TR/vc-data-model/1.0/#types",
					Type: "JsonSchemaValidator2018",
				}},
			}),
			createTestCredential(t, credentialProto{
				Context: []string{
					verifiable.ContextURI,
					"https://www.w3.org/2018/credentials/examples/v1",
					"https://trustbloc.github.io/context/vc/examples-v1.jsonld",
				},
				Types: []string{verifiable.VCType, "UniversityDegreeCredential", "DocumentVerification"},
				ID:    uuid.New().String(),
			}),
		}, lddl)

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, 2, len(vp.Credentials()))

		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})
}

func TestPresentationDefinition_CreateVPArray(t *testing.T) {
	lddl := createTestJSONLDDocumentLoader(t)

	t.Run("Matches two descriptors", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: "https://example.org/examples#UniversityDegreeCredential",
				}},
			}, {
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: "https://example.org/examples#DocumentVerification",
				}},
			}},
		}

		vpList, ps, err := pd.CreateVPArray([]*verifiable.Credential{
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.ContextURI, "https://www.w3.org/2018/credentials/examples/v1"},
				Types:   []string{verifiable.VCType, "UniversityDegreeCredential"},
				ID:      uuid.New().String(),
			}),
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.ContextURI, "https://trustbloc.github.io/context/vc/examples-v1.jsonld"},
				Types:   []string{verifiable.VCType, "DocumentVerification"},
				ID:      uuid.New().String(),
			}),
		}, lddl)

		require.NoError(t, err)
		require.NotNil(t, vpList)
		require.Len(t, vpList, 2)

		checkExternalSubmission(t, vpList, ps, pd)

		for _, vp := range vpList {
			checkVP(t, vp)
		}
	})
}

func getTestVCWithContext(t *testing.T, issuerID string, ctx []string) *verifiable.Credential {
	subjectJSON := map[string]interface{}{
		"id":           uuid.New().String(),
		"sub":          "john_doe_42",
		"given_name":   "John",
		"family_name":  "Doe",
		"email":        "johndoe@example.com",
		"phone_number": "+1-202-555-0101",
		"birthdate":    "1940-01-01",
		"address": map[string]interface{}{
			"street_address": "123 Main St",
			"locality":       "Anytown",
			"region":         "Anystate",
			"country":        "US",
		},
	}

	subject, err := verifiable.SubjectFromJSON(subjectJSON)
	require.NoError(t, err)

	context := []string{verifiable.ContextURI}

	if ctx != nil {
		context = append(context, ctx...)
	}

	vc := createTestCredential(t, credentialProto{
		Context: context,
		Types:   []string{verifiable.VCType},
		ID:      "http://example.edu/credentials/1872",
		Issued: &utiltime.TimeWrapper{
			Time: time.Now(),
		},
		Issuer: &verifiable.Issuer{
			ID: issuerID,
		},
		Schemas: []verifiable.TypedID{{
			ID:   "https://www.w3.org/TR/vc-data-model/2.0/#types",
			Type: "JsonSchemaValidator2018",
		}},
		Subject: []verifiable.Subject{subject},
	})

	return vc
}

func newSdJwtVC(
	t *testing.T,
	signer jwt.ProofCreator,
	checker jwt.ProofChecker,
) *verifiable.Credential {
	t.Helper()

	issuer, verMethod := "did:test:1234567", "did:test:1234567#key-1"

	vc := getTestVCWithContext(t, issuer, nil)

	jwsAlgo, err := verifiable.KeyTypeToJWSAlgo(kms.ED25519Type)
	require.NoError(t, err)

	algName, err := jwsAlgo.Name()
	require.NoError(t, err)

	joseSig, err := jwt.NewJOSESigner(jwt.SignParameters{
		KeyID:  verMethod,
		JWTAlg: algName,
	}, signer)
	require.NoError(t, err)

	combinedFormatForIssuance, err := vc.MakeSDJWT(
		joseSig, verMethod)
	require.NoError(t, err)

	parsed, err := verifiable.ParseCredential([]byte(combinedFormatForIssuance),
		verifiable.WithJWTProofChecker(checker))
	require.NoError(t, err)

	return parsed
}

func checkSubmission(t *testing.T, vp *verifiable.Presentation, pd *PresentationDefinition) {
	t.Helper()

	ps, ok := vp.CustomFields["presentation_submission"].(*PresentationSubmission)
	require.True(t, ok)
	require.NotEmpty(t, ps.ID)
	require.Equal(t, ps.DefinitionID, pd.ID)

	src, err := json.Marshal(vp)
	require.NoError(t, err)

	vpAsMap := map[string]interface{}{}
	require.NoError(t, json.Unmarshal(src, &vpAsMap))

	builder := gval.Full(jsonpath.PlaceholderExtension())

	for _, descriptor := range ps.DescriptorMap {
		require.NotEmpty(t, descriptor.ID)
		require.NotEmpty(t, descriptor.Path)
		require.NotEmpty(t, descriptor.Format)

		path, err := builder.NewEvaluable(descriptor.Path)
		require.NoError(t, err)
		_, err = path(context.TODO(), vpAsMap)
		require.NoError(t, err)
	}
}

func checkExternalSubmission(
	t *testing.T,
	vpList []*verifiable.Presentation,
	ps *PresentationSubmission,
	pd *PresentationDefinition,
) {
	t.Helper()

	require.NotEmpty(t, ps.ID)
	require.Equal(t, ps.DefinitionID, pd.ID)

	src, err := json.Marshal(vpList)
	require.NoError(t, err)

	rawVPList := []interface{}{}
	require.NoError(t, json.Unmarshal(src, &rawVPList))

	builder := gval.Full(jsonpath.PlaceholderExtension())

	for _, descriptor := range ps.DescriptorMap {
		require.NotEmpty(t, descriptor.ID)
		require.NotEmpty(t, descriptor.Path)
		require.NotEmpty(t, descriptor.Format)

		path, err := builder.NewEvaluable(descriptor.Path)
		require.NoError(t, err)
		_, err = path(context.TODO(), rawVPList)
		require.NoError(t, err)
	}
}

func checkVP(t *testing.T, vp *verifiable.Presentation) {
	t.Helper()

	src, err := json.Marshal(vp)
	require.NoError(t, err)

	println(string(src))

	_, err = verifiable.ParsePresentation(src,
		verifiable.WithPresDisabledProofCheck(),
		verifiable.WithPresJSONLDDocumentLoader(createTestJSONLDDocumentLoader(t)))
	require.NoError(t, err)
}

func parseJSONFile(t *testing.T, name string, v interface{}) {
	t.Helper()

	jf, err := os.Open(name) // nolint: gosec
	if err != nil {
		t.Error(err)
	}

	defer func() {
		if err = jf.Close(); err != nil {
			t.Error(err)
		}
	}()

	byteValue, err := ioutil.ReadAll(jf)
	if err != nil {
		t.Error(err)
	}

	if err = json.Unmarshal(byteValue, &v); err != nil {
		t.Error(err)
	}
}

type bbsSigner struct {
	privateKey []byte
}

func newBBSSigner(key *bbs12381g2pub.PrivateKey) (*bbsSigner, error) {
	src, err := key.Marshal()
	if err != nil {
		return nil, err
	}

	return &bbsSigner{privateKey: src}, nil
}

func (s *bbsSigner) Sign(data []byte, _ kms.KeyType) ([]byte, error) {
	return bbs12381g2pub.New().Sign(s.textToLines(string(data)), s.privateKey)
}

func (s *bbsSigner) Alg() string {
	return ""
}

func (s *bbsSigner) textToLines(txt string) [][]byte {
	lines := strings.Split(txt, "\n")
	linesBytes := make([][]byte, 0, len(lines))

	for i := range lines {
		if strings.TrimSpace(lines[i]) != "" {
			linesBytes = append(linesBytes, []byte(lines[i]))
		}
	}

	return linesBytes
}

type credentialProto struct {
	Context        []string
	CustomContext  []interface{}
	ID             string
	Types          []string
	Subject        []verifiable.Subject
	Issuer         *verifiable.Issuer
	Issued         *utiltime.TimeWrapper
	Expired        *utiltime.TimeWrapper
	Status         *verifiable.TypedID
	Schemas        []verifiable.TypedID
	Evidence       verifiable.Evidence
	TermsOfUse     []verifiable.TypedID
	RefreshService []verifiable.TypedID
	SDJWTHashAlg   *crypto.Hash

	CustomFields verifiable.CustomFields
	Proofs       []verifiable.Proof
}

func createTestCredential(t *testing.T, proto credentialProto) *verifiable.Credential {
	vc, err := createCredential(proto)
	require.NoError(t, err)

	return vc
}

func createCredential(proto credentialProto) (*verifiable.Credential, error) {
	contents := verifiable.CredentialContents{
		Context:        proto.Context,
		CustomContext:  proto.CustomContext,
		ID:             proto.ID,
		Types:          proto.Types,
		Subject:        proto.Subject,
		Issuer:         proto.Issuer,
		Issued:         proto.Issued,
		Expired:        proto.Expired,
		Status:         proto.Status,
		Schemas:        proto.Schemas,
		Evidence:       proto.Evidence,
		TermsOfUse:     proto.TermsOfUse,
		RefreshService: proto.RefreshService,
		SDJWTHashAlg:   proto.SDJWTHashAlg,
	}

	return verifiable.CreateCredentialWithProofs(contents, proto.CustomFields, proto.Proofs)
}

func createTestJSONLDDocumentLoader(t *testing.T) *lddocloader.DocumentLoader {
	t.Helper()

	loader, err := ldtestutil.DocumentLoader()
	require.NoError(t, err)

	return loader
}

func prettyPrint(msg []byte) (string, error) {
	var prettyJSON bytes.Buffer

	err := json.Indent(&prettyJSON, msg, "", "\t")
	if err != nil {
		return "", err
	}

	return prettyJSON.String(), nil
}

func printObject(t *testing.T, name string, obj interface{}) {
	t.Helper()

	objBytes, err := json.Marshal(obj)
	require.NoError(t, err)

	prettyJSON, err := prettyPrint(objBytes)
	require.NoError(t, err)

	fmt.Println(name + ":")
	fmt.Println(prettyJSON)
}
