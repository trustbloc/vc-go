/*
Copyright Gen Digital Inc. All Rights Reserved.

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
	"github.com/samber/lo"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/bbs-signature-go/bbs12381g2pub"
	ldcontext "github.com/trustbloc/did-go/doc/ld/context"
	lddocloader "github.com/trustbloc/did-go/doc/ld/documentloader"
	ldprocessor "github.com/trustbloc/did-go/doc/ld/processor"
	ldtestutil "github.com/trustbloc/did-go/doc/ld/testutil"
	utiltime "github.com/trustbloc/did-go/doc/util/time"
	"github.com/trustbloc/kms-go/spi/kms"
	"github.com/veraison/go-cose"

	"github.com/trustbloc/vc-go/crypto-ext/testutil"
	"github.com/trustbloc/vc-go/jwt"
	. "github.com/trustbloc/vc-go/presexch"
	"github.com/trustbloc/vc-go/proof/creator"
	"github.com/trustbloc/vc-go/proof/defaults"
	"github.com/trustbloc/vc-go/proof/ldproofs/bbsblssignature2020"
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

func TestPresentationDefinition_CreateVP_V1Credential(t *testing.T) {
	lddl := createTestJSONLDDocumentLoader(t)

	t.Run("Checks schema", func(t *testing.T) {
		pd := &PresentationDefinition{ID: uuid.New().String()}

		vp, err := pd.CreateVP(nil, nil)

		require.EqualError(t, err, "presentation_definition: input_descriptors is required")
		require.Nil(t, vp)
	})

	t.Run("Checks credentials V1 submission requirements", func(t *testing.T) {
		issuerID := "did:example:76e12ec712ebc6f1c221ebfeb1f"

		vc1 := createTestCredential(t, credentialProto{
			Issued:  utiltime.NewTime(time.Now()),
			Context: []string{verifiable.V1ContextURI},
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
				Context: []string{verifiable.V1ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      "http://example.edu/credentials/1872",
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
				},
				Proofs: []verifiable.Proof{{"type": "JsonWebSignature2020"}},
			}),
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.V1ContextURI},
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
				Context: []string{verifiable.V1ContextURI},
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
							URI: fmt.Sprintf("%s#%s", verifiable.V1ContextID, verifiable.VCType),
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
							URI: fmt.Sprintf("%s#%s", verifiable.V1ContextID, verifiable.VCType),
						}},
						Constraints: &Constraints{
							SubjectIsIssuer: &subIsIssuerRequired,
							Fields: []*Field{{
								Path: []string{"$.age"},
								Filter: &Filter{
									FilterItem: FilterItem{
										Type:    &intFilterType,
										Minimum: 3,
										Maximum: 12,
									},
								},
							}},
						},
					}, {
						ID:    uuid.New().String(),
						Group: []string{"teenager"},
						Schema: []*Schema{{
							URI: fmt.Sprintf("%s#%s", verifiable.V1ContextID, verifiable.VCType),
						}},
						Constraints: &Constraints{
							SubjectIsIssuer: &subIsIssuerRequired,
							Fields: []*Field{{
								Path: []string{"$.age"},
								Filter: &Filter{
									FilterItem: FilterItem{
										Type:    &intFilterType,
										Minimum: 13,
										Maximum: 17,
									},
								},
							}},
						},
					}, {
						ID:    uuid.New().String(),
						Group: []string{"adult"},
						Schema: []*Schema{{
							URI: fmt.Sprintf("%s#%s", verifiable.V1ContextID, verifiable.VCType),
						}},
						Constraints: &Constraints{
							SubjectIsIssuer: &subIsIssuerRequired,
							Fields: []*Field{{
								Path: []string{"$.age"},
								Filter: &Filter{
									FilterItem: FilterItem{
										Type:    &intFilterType,
										Minimum: 18,
										Maximum: 23,
									},
								},
							}},
						},
					}},
					Format: tc.vFormat,
				}

				vp, err := pd.CreateVP(candidateVCs, lddl)

				if tc.format == FormatJWTVP {
					claims, jwtErr := vp.JWTClaims([]string{""}, false)
					require.NoError(t, jwtErr)
					require.NotNil(t, claims)

					unsecuredJWT, marshalErr := claims.MarshalUnsecuredJWT()
					require.NoError(t, marshalErr)
					require.NotEmpty(t, unsecuredJWT)

					vp.JWT = unsecuredJWT
				}

				require.NoError(t, err)
				require.NotNil(t, vp)
				require.Equal(t, 1, len(vp.Credentials()))

				checkSubmission(t, vp, pd)
				checkVP(t, vp, tc.format)
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
					URI: verifiable.V1ContextURI,
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
				Context: []string{verifiable.V1ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
				},
			}), createTestCredential(t, credentialProto{
				Context: []string{verifiable.V1ContextURI},
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
					URI: fmt.Sprintf("%s#%s", verifiable.V1ContextID, verifiable.VCType),
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
				Context: []string{verifiable.V1ContextURI},
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
		checkVP(t, vp, FormatLDPVP)
	})

	t.Run("Predicate", func(t *testing.T) {
		predicate := Required

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.V1ContextID, verifiable.VCType),
				}},
				Constraints: &Constraints{
					Fields: []*Field{{
						Path:      []string{"$.first_name", "$.last_name"},
						Predicate: &predicate,
						Filter: &Filter{
							FilterItem: FilterItem{
								Type: &strFilterType,
							},
						},
					}},
				},
			}},
		}

		vp, err := pd.CreateVP([]*verifiable.Credential{
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.V1ContextURI},
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
		checkVP(t, vp, FormatLDPVP)
	})

	t.Run("All of", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.V1ContextID, verifiable.VCType),
				}},
				Constraints: &Constraints{
					Fields: []*Field{
						{
							Path: []string{"$['@context']"},
							Filter: &Filter{
								FilterItem: FilterItem{
									Type: lo.ToPtr("array"),
								},
								AllOf: []*FilterItem{
									{
										Contains: map[string]interface{}{
											"type":  "string",
											"const": verifiable.V1ContextURI,
										},
									},
									{
										Contains: map[string]interface{}{
											"type":  "string",
											"const": "https://www.w3.org/2018/credentials/examples/v1",
										},
									},
								},
							},
						},
						{
							Path: []string{"$['type']"},
							Filter: &Filter{
								FilterItem: FilterItem{
									Type: lo.ToPtr("array"),
								},
								AllOf: []*FilterItem{
									{
										Contains: map[string]interface{}{
											"type":  "string",
											"const": "SuperType",
										},
									},
								},
							},
						},
						{
							Path: []string{"$.first_name"},
							Filter: &Filter{
								FilterItem: FilterItem{
									Type: lo.ToPtr("array"),
								},
								AllOf: []*FilterItem{
									{
										Type:  lo.ToPtr("string"),
										Const: "First name",
									},
								},
							},
						},
						{
							Path: []string{"$.last_name"},
							Filter: &Filter{
								FilterItem: FilterItem{
									Type: lo.ToPtr("array"),
								},
								AllOf: []*FilterItem{
									{
										Type:  lo.ToPtr("string"),
										Const: "Last name",
									},
								},
							},
						},
					},
				},
			}},
		}

		vp, err := pd.CreateVP([]*verifiable.Credential{
			createTestCredential(t, credentialProto{
				Context: []string{
					verifiable.V1ContextURI,
					"https://www.w3.org/2018/credentials/examples/v1",
				},
				Types:   []string{verifiable.VCType, "SuperType"},
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

		require.EqualValues(t, "First name", vc.CustomField("first_name"))
		require.EqualValues(t, "Last name", vc.CustomField("last_name"))
		require.EqualValues(t, "Info", vc.CustomField("info"))

		checkSubmission(t, vp, pd)
		checkVP(t, vp, FormatLDPVP)
	})

	t.Run("All of fail", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.V1ContextID, verifiable.VCType),
				}},
				Constraints: &Constraints{
					Fields: []*Field{
						{
							Path: []string{"$['@context']"},
							Filter: &Filter{
								FilterItem: FilterItem{
									Type: lo.ToPtr("array"),
								},
								AllOf: []*FilterItem{
									{
										Contains: map[string]interface{}{
											"type":  "string",
											"const": verifiable.V1ContextURI,
										},
									},
									{
										Contains: map[string]interface{}{
											"type":  "string",
											"const": "https://404",
										},
									},
								},
							},
						},
						{
							Path: []string{"$.first_name"},
							Filter: &Filter{
								FilterItem: FilterItem{
									Type: lo.ToPtr("array"),
								},
								AllOf: []*FilterItem{
									{
										Type:  lo.ToPtr("string"),
										Const: "First name",
									},
								},
							},
						},
						{
							Path: []string{"$.last_name"},
							Filter: &Filter{
								FilterItem: FilterItem{
									Type: lo.ToPtr("array"),
								},
								AllOf: []*FilterItem{
									{
										Type:  lo.ToPtr("string"),
										Const: "Last name",
									},
								},
							},
						},
					},
				},
			}},
		}

		vp, err := pd.CreateVP([]*verifiable.Credential{
			createTestCredential(t, credentialProto{
				Context: []string{
					verifiable.V1ContextURI,
					"https://www.w3.org/2018/credentials/examples/v1",
				},
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

		require.ErrorContains(t, err, "credentials do not satisfy requirements")
		require.Nil(t, vp)
	})

	t.Run("Get By Context", func(t *testing.T) {
		const queryByCredType = `{
				   "id": "69ddc987-55c2-4f1f-acea-f2838be10607",
				   "input_descriptors": [
					   {
						   "id": "26b00531-caa1-49f3-a5a1-4a0eae8c0925",
						   "constraints": {
							   "fields": [
								   {
									   "path": [
										   "$[\"@context\"]"
									   ],
								 "filter": {
									"type": "array",
									"contains": {
											"type": "string",
											"const": "https://www.w3.org/2018/credentials/v1"
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
				Context: []string{verifiable.V1ContextURI},
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
		checkVP(t, vp, FormatLDPVP)
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
				Context: []string{verifiable.V1ContextURI},
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
		checkVP(t, vp, FormatLDPVP)
	})

	t.Run("Predicate (limit disclosure) LDP", func(t *testing.T) {
		required := Required

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.V1ContextID, verifiable.VCType),
				}},
				Constraints: &Constraints{
					LimitDisclosure: &required,
					Fields: []*Field{{
						Path:      []string{"$.first_name", "$.last_name"},
						Predicate: &required,
						Filter: &Filter{
							FilterItem: FilterItem{
								Type: &strFilterType,
							},
						},
					}},
				},
			}},
		}

		vp, err := pd.CreateVP([]*verifiable.Credential{
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.V1ContextURI},
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
		checkVP(t, vp, FormatLDPVP)
	})

	t.Run("Predicate (limit disclosure) JWT", func(t *testing.T) {
		required := Required

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.V1ContextID, verifiable.VCType),
				}},
				Constraints: &Constraints{
					LimitDisclosure: &required,
					Fields: []*Field{{
						Path:      []string{"$.first_name", "$.last_name"},
						Predicate: &required,
						Filter: &Filter{
							FilterItem: FilterItem{
								Type: &strFilterType,
							},
						},
					}},
				},
			}},
		}

		credProto := createTestCredential(t, credentialProto{
			Context: []string{verifiable.V1ContextURI},
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
		checkVP(t, vp, FormatLDPVP)
	})

	t.Run("SD-JWT: Limit Disclosure + SD Claim paths", func(t *testing.T) {
		required := Required

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.V1ContextID, verifiable.VCType),
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
		checkVP(t, vp, FormatLDPVP)
	})

	t.Run("SD-JWT: Limit Disclosure + SD Claim paths + additional filter", func(t *testing.T) {
		required := Required

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.V1ContextID, verifiable.VCType),
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
								FilterItem: FilterItem{
									Type:  &strFilterType,
									Const: "https://www.w3.org/TR/vc-data-model/2.0/#types",
								},
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
		checkVP(t, vp, FormatLDPVP)
	})

	t.Run("SD-JWT: Limit Disclosure + non-SD claim path", func(t *testing.T) {
		required := Required

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.V1ContextID, verifiable.VCType),
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
		checkVP(t, vp, FormatLDPVP)
	})

	t.Run("SD-JWT: No Limit Disclosure + Predicate Satisfied", func(t *testing.T) {
		required := Required

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.V1ContextID, verifiable.VCType),
				}},
				Constraints: &Constraints{
					Fields: []*Field{{
						Path: []string{
							"$.credentialSubject.family_name",
						},
						Predicate: &required,
						Filter: &Filter{
							FilterItem: FilterItem{
								Type: &strFilterType,
							},
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
		checkVP(t, vp, FormatLDPVP)
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
					URI: fmt.Sprintf("%s#%s", verifiable.V1ContextID, verifiable.VCType),
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
		require.Contains(t, err.Error(), "expected $ or @ at start of path")
	})

	t.Run("SD-JWT: Limit Disclosure (credentials don't meet requirement)", func(t *testing.T) {
		required := Required

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.V1ContextID, verifiable.VCType),
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
						Filter: &Filter{
							FilterItem: FilterItem{
								Type: &arrFilterType,
							},
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

	t.Run("SD-JWT: No Limit Disclosure (credentials don't meet requirement)", func(t *testing.T) {
		required := Required

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.V1ContextID, verifiable.VCType),
				}},
				Constraints: &Constraints{
					Fields: []*Field{{
						Path: []string{
							"$.credentialSubject.family_name",
							"$.credentialSubject.given_name",
							"$.credentialSubject.address.country",
						},
						Predicate: &required,
						Filter: &Filter{
							FilterItem: FilterItem{
								Type: &arrFilterType,
							},
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

	t.Run("SD-JWT: Limit Disclosure with invalid field (credentials don't meet requirement)", func(t *testing.T) {
		required := Required

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.V1ContextID, verifiable.VCType),
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
					URI: fmt.Sprintf("%s#%s", verifiable.V1ContextID, verifiable.VCType),
				}},
				ID: uuid.New().String(),
				Constraints: &Constraints{
					LimitDisclosure: &required,
					Fields: []*Field{{
						Path: []string{"$.credentialSubject.degree.degreeSchool"},
						Filter: &Filter{
							FilterItem: FilterItem{
								Type: &strFilterType,
							},
						},
					}},
				},
			}},
		}

		vc := createTestCredential(t, credentialProto{
			ID: "https://issuer.oidp.uscis.gov/credentials/83627465",
			Context: []string{
				verifiable.V1ContextURI,
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

		signer, err := testutil.NewBBSSigner(privateKey)
		require.NoError(t, err)

		require.NoError(t, vc.AddLinkedDataProof(&verifiable.LinkedDataProofContext{
			SignatureType:           "BbsBlsSignature2020",
			KeyType:                 kms.BLS12381G2Type,
			SignatureRepresentation: verifiable.SignatureProofValue,
			ProofCreator:            creator.New(creator.WithLDProofType(bbsblssignature2020.New(), signer)),
			VerificationMethod:      "did:example:123456#key1",
		}, ldprocessor.WithDocumentLoader(createTestJSONLDDocumentLoader(t))))

		vp, err := pd.CreateVP([]*verifiable.Credential{vc}, lddl,
			WithSDBBSProofCreator(&verifiable.BBSProofCreator{
				ProofDerivation:            bbs12381g2pub.New(),
				VerificationMethodResolver: testsupport.NewSingleKeyResolver("did:example:123456#key1", srcPublicKey, "Bls12381G2Key2020", ""),
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
		checkVP(t, vp, FormatLDPVP)
	})

	t.Run("Predicate and limit disclosure BBS+ (no proof)", func(t *testing.T) {
		required := Required

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.V1ContextID, verifiable.VCType),
				}},
				ID: uuid.New().String(),
				Constraints: &Constraints{
					LimitDisclosure: &required,
					Fields: []*Field{{
						Path: []string{"$.credentialSubject.givenName", "$.credentialSubject.familyName"},
						Filter: &Filter{
							FilterItem: FilterItem{
								Type: &strFilterType,
							},
						},
						Predicate: &required,
					}, {
						Path: []string{"$.credentialSubject.type"},
						Filter: &Filter{
							FilterItem: FilterItem{
								Type: &arrFilterType,
							},
						},
					}},
				},
			}},
		}

		vc := createTestCredential(t, credentialProto{
			ID: "https://issuer.oidp.uscis.gov/credentials/83627465",
			Context: []string{
				verifiable.V1ContextURI,
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

		signer, err := testutil.NewBBSSigner(privateKey)
		require.NoError(t, err)

		require.NoError(t, vc.AddLinkedDataProof(&verifiable.LinkedDataProofContext{
			SignatureType:           "BbsBlsSignature2020",
			KeyType:                 kms.BLS12381G2Type,
			SignatureRepresentation: verifiable.SignatureProofValue,
			ProofCreator:            creator.New(creator.WithLDProofType(bbsblssignature2020.New(), signer)),
			VerificationMethod:      "did:example:123456#key1",
		}, ldprocessor.WithDocumentLoader(createTestJSONLDDocumentLoader(t))))

		vp, err := pd.CreateVP([]*verifiable.Credential{vc}, lddl,
			WithSDCredentialOptions(
				verifiable.WithJSONLDDocumentLoader(createTestJSONLDDocumentLoader(t)),
				verifiable.WithProofChecker(defaults.NewDefaultProofChecker(testsupport.NewSingleKeyResolver("did:example:123456#key1", srcPublicKey, "Bls12381G2Key2020", ""))),
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
		checkVP(t, vp, FormatLDPVP)
	})

	t.Run("Predicate (marshal error)", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: verifiable.V1ContextID,
				}},
				Constraints: &Constraints{
					Fields: []*Field{{
						Path: []string{"$.last_name"},
						Filter: &Filter{
							FilterItem: FilterItem{
								Type: &strFilterType,
							},
						},
					}},
				},
			}},
		}

		vp, err := pd.CreateVP([]*verifiable.Credential{
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.V1ContextURI},
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
					URI: verifiable.V1ContextID,
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
				Context: []string{verifiable.V1ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
				},
			}),
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.V1ContextURI},
				ID:      uuid.New().String(),
				CustomFields: map[string]interface{}{
					"last_name": "Travis",
				},
			}),
		}, lddl)

		require.EqualError(t, err, errMsgSchema)
		require.Nil(t, vp, FormatLDPVP)
	})

	t.Run("No matches (one field path)", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: verifiable.V1ContextID,
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
				Context: []string{verifiable.V1ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
				},
			}),
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.V1ContextURI},
				ID:      uuid.New().String(),
				CustomFields: map[string]interface{}{
					"last_name": "Travis",
				},
			}),
		}, lddl)

		require.EqualError(t, err, errMsgSchema)
		require.Nil(t, vp, FormatLDPVP)
	})

	t.Run("Matches one credentials (two fields)", func(t *testing.T) {
		issuerID := uuid.New().String()

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.V1ContextID, verifiable.VCType),
				}},
				Constraints: &Constraints{
					SubjectIsIssuer: &subIsIssuerRequired,
					Fields: []*Field{{
						Path: []string{"$.first_name"},
						Filter: &Filter{
							FilterItem: FilterItem{
								Type: &strFilterType,
							},
						},
					}, {
						Path: []string{"$.last_name"},
						Filter: &Filter{
							FilterItem: FilterItem{
								Type: &strFilterType,
							},
						},
					}},
				},
			}},
		}

		vp, err := pd.CreateVP([]*verifiable.Credential{
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.V1ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Subject: []verifiable.Subject{},
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
				},
			}), createTestCredential(t, credentialProto{
				Context: []string{verifiable.V1ContextURI},
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
		checkVP(t, vp, FormatLDPVP)
	})

	t.Run("Matches one credentials (three fields - disclosure)", func(t *testing.T) {
		issuerID := "did:example:76e12ec712ebc6f1c221ebfeb1f"
		required := Required

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.V1ContextID, verifiable.VCType),
				}},
				Constraints: &Constraints{
					SubjectIsIssuer: &subIsIssuerRequired,
					LimitDisclosure: &required,
					Fields: []*Field{{
						Path: []string{"$.first_name"},
						Filter: &Filter{
							FilterItem: FilterItem{
								Type: &strFilterType,
							},
						},
					}, {
						Path: []string{"$.issuer"},
						Filter: &Filter{
							FilterItem: FilterItem{
								Type: &strFilterType,
							},
						},
					}, {
						Path: []string{"$.all[*].authors[*].name"},
						Filter: &Filter{
							FilterItem: FilterItem{
								Type: &arrFilterType,
							},
						},
					}},
				},
			}},
		}

		vp, err := pd.CreateVP([]*verifiable.Credential{
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.V1ContextURI},
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
				Context: []string{verifiable.V1ContextURI},
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
		checkVP(t, vp, FormatLDPVP)
	})

	t.Run("Create new credential (error)", func(t *testing.T) {
		required := Required

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.V1ContextID, verifiable.VCType),
				}},
				Constraints: &Constraints{
					LimitDisclosure: &required,
					Fields: []*Field{{
						Path: []string{"$.first_name"},
						Filter: &Filter{
							FilterItem: FilterItem{
								Type:    &strFilterType,
								Pattern: "^Jesse",
							},
						},
						Predicate: &required,
					}},
				},
			}},
		}

		vp, err := pd.CreateVP([]*verifiable.Credential{
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.V1ContextURI},
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
					URI: fmt.Sprintf("%s#%s", verifiable.V1ContextID, verifiable.VCType),
				}},
				Constraints: &Constraints{
					SubjectIsIssuer: &subIsIssuerRequired,
					Fields: []*Field{{
						Path: []string{"$.first_name"},
						Filter: &Filter{
							FilterItem: FilterItem{
								Type:    &strFilterType,
								Pattern: "^Jesse",
							},
						},
					}},
				},
			}},
		}

		vp, err := pd.CreateVP([]*verifiable.Credential{
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.V1ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Subject: []verifiable.Subject{{ID: issuerID}},
				Issuer:  &verifiable.Issuer{ID: issuerID},
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
				},
			}),
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.V1ContextURI},
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
		checkVP(t, vp, FormatLDPVP)
	})

	t.Run("Matches one credentials", func(t *testing.T) {
		issuerID := uuid.New().String()

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.V1ContextID, verifiable.VCType),
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
				Context: []string{verifiable.V1ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
				},
			}),
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.V1ContextURI},
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
		checkVP(t, vp, FormatLDPVP)
	})

	t.Run("Matches one credentials (two descriptors)", func(t *testing.T) {
		issuerID := uuid.New().String()

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.V1ContextID, verifiable.VCType),
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
					URI: fmt.Sprintf("%s#%s", verifiable.V1ContextID, verifiable.VCType),
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
				Context: []string{verifiable.V1ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Subject: []verifiable.Subject{{ID: issuerID}},
				Issuer:  &verifiable.Issuer{ID: issuerID},
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
				},
			}),
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.V1ContextURI},
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
		checkVP(t, vp, FormatLDPVP)
	})

	t.Run("Matches two credentials (one descriptor)", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.V1ContextID, verifiable.VCType),
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
				Context: []string{verifiable.V1ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
				},
			}),
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.V1ContextURI},
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
		checkVP(t, vp, FormatLDPVP)
	})

	t.Run("Matches two credentials", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.V1ContextID, verifiable.VCType),
				}},
			}},
		}

		vp, err := pd.CreateVP([]*verifiable.Credential{
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.V1ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
			}),
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.V1ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
			}),
		}, lddl)

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, 2, len(vp.Credentials()))

		checkSubmission(t, vp, pd)
		checkVP(t, vp, FormatLDPVP)
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
				Context: []string{verifiable.V1ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
			}),
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.V1ContextURI, "https://www.w3.org/2018/credentials/examples/v1"},
				Types:   []string{verifiable.VCType, "UniversityDegreeCredential"},
				ID:      uuid.New().String(),
			}),
		}, lddl)

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, 1, len(vp.Credentials()))

		checkSubmission(t, vp, pd)
		checkVP(t, vp, FormatLDPVP)
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
				Context: []string{verifiable.V1ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Schemas: []verifiable.TypedID{{
					ID:   "https://www.w3.org/TR/vc-data-model/2.0/#types",
					Type: "JsonSchemaValidator2018",
				}},
			}),
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.V1ContextURI},
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
				Context: []string{verifiable.V1ContextURI, "https://www.w3.org/2018/credentials/examples/v1"},
				Types:   []string{verifiable.VCType, "UniversityDegreeCredential"},
				ID:      uuid.New().String(),
			}),
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.V1ContextURI, "https://trustbloc.github.io/context/vc/examples-v1.jsonld"},
				Types:   []string{verifiable.VCType, "DocumentVerification"},
				ID:      uuid.New().String(),
			}),
		}, lddl)

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, 2, len(vp.Credentials()))

		checkSubmission(t, vp, pd)
		checkVP(t, vp, FormatLDPVP)
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
				Context: []string{verifiable.V1ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Schemas: []verifiable.TypedID{{
					ID:   "https://www.w3.org/TR/vc-data-model/1.0/#types",
					Type: "JsonSchemaValidator2018",
				}},
			}),
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.V1ContextURI},
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
				Context: []string{verifiable.V1ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Schemas: []verifiable.TypedID{{
					ID:   "https://www.w3.org/TR/vc-data-model/1.0/#types",
					Type: "JsonSchemaValidator2018",
				}},
			}),
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.V1ContextURI},
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
				Context: []string{verifiable.V1ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
			}),
		}, lddl)

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, 1, len(vp.Credentials()))

		checkSubmission(t, vp, pd)
		checkVP(t, vp, FormatLDPVP)
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
					URI:      fmt.Sprintf("%s#%s", verifiable.V1ContextID, verifiable.VCType),
					Required: true,
				}},
			}},
		}
		vp, err := pd.CreateVP([]*verifiable.Credential{
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.V1ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
			}),
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.V1ContextURI, "https://trustbloc.github.io/context/vc/examples-v1.jsonld"},
				Types:   []string{verifiable.VCType, "DocumentVerification"},
				ID:      uuid.New().String(),
			}),
		}, lddl)

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, 2, len(vp.Credentials()))

		checkSubmission(t, vp, pd)
		checkVP(t, vp, FormatLDPVP)
	})

	t.Run("Requires two schemas", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.V1ContextID, verifiable.VCType),
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
				Context: []string{verifiable.V1ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Schemas: []verifiable.TypedID{{
					ID:   "https://www.w3.org/TR/vc-data-model/1.0/#types",
					Type: "JsonSchemaValidator2018",
				}},
			}),
			createTestCredential(t, credentialProto{
				Context: []string{
					verifiable.V1ContextURI,
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
		checkVP(t, vp, FormatLDPVP)
	})

	t.Run("Matches two descriptors (jwt_vp)", func(t *testing.T) {
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

		vp, err := pd.CreateVP(
			[]*verifiable.Credential{
				createTestCredential(t, credentialProto{
					Context: []string{verifiable.V1ContextURI, "https://www.w3.org/2018/credentials/examples/v1"},
					Types:   []string{verifiable.VCType, "UniversityDegreeCredential"},
					ID:      uuid.New().String(),
				}),
				createTestCredential(t, credentialProto{
					Context: []string{verifiable.V1ContextURI, "https://trustbloc.github.io/context/vc/examples-v1.jsonld"},
					Types:   []string{verifiable.VCType, "DocumentVerification"},
					ID:      uuid.New().String(),
				}),
			},
			lddl,
			WithDefaultPresentationFormat(FormatJWTVP),
		)

		require.NoError(t, err)
		require.NotNil(t, vp)

		claims, err := vp.JWTClaims([]string{""}, false)
		require.NoError(t, err)
		require.NotNil(t, claims)

		unsecuredJWT, err := claims.MarshalUnsecuredJWT()
		require.NoError(t, err)
		require.NotEmpty(t, unsecuredJWT)

		vp.JWT = unsecuredJWT

		checkSubmission(t, vp, pd)

		ps, ok := vp.CustomFields["presentation_submission"].(*PresentationSubmission)
		require.True(t, ok)
		require.Equal(t, "jwt_vp", ps.DescriptorMap[0].Format)

		checkVP(t, vp, FormatJWTVP)
	})

	t.Run("request two VCs that have different base contexts -> error", func(t *testing.T) {
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
					URI: fmt.Sprintf("%s#%s", verifiable.V1ContextID, verifiable.VCType),
				}},
				Constraints: &Constraints{
					Fields: []*Field{{
						Path: []string{"$." + claim},
					}},
				},
			}
		}

		makeCredential := func(baseContext string, claims ...string) *verifiable.Credential {
			selfIssuedID := uuid.NewString()

			customFields := map[string]interface{}{}

			for _, claim := range claims {
				customFields[claim] = "foo"
			}

			vc := createTestCredential(t, credentialProto{
				Context: []string{baseContext},
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
			makeCredential(verifiable.V1ContextURI, "A"),
			makeCredential(verifiable.V2ContextURI, "B"),
		}

		_, err := pd.CreateVP(credentials, lddl)
		require.ErrorContains(t, err, "credentials have different base contexts")
	})

	t.Run("Match credential in jwt_vc format with escaping", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Constraints: &Constraints{
					Fields: []*Field{
						{
							Path: []string{"$.vc.last_name"},
						},
						{
							Path: []string{"$.vc['hash-algo']"},
						},
					},
				},
			}},
		}

		issuerDID := "did:example:76e12ec712ebc6f1c221ebfeb1f"

		vc := createTestCredential(t, credentialProto{
			Issued:  utiltime.NewTime(time.Now()),
			Context: []string{verifiable.V1ContextURI},
			Types:   []string{verifiable.VCType},
			ID:      uuid.New().String(),
			Subject: []verifiable.Subject{{ID: issuerDID}},
			Issuer:  &verifiable.Issuer{ID: issuerDID},
			CustomFields: map[string]interface{}{
				"first_name": "Jesse",
				"last_name":  "Travis",
				"hash-algo":  "xx",
				"age":        17,
			},
		})

		jwtVC, err := vc.CreateUnsecuredJWTVC(false)
		require.NoError(t, err)

		vp, err := pd.CreateVP([]*verifiable.Credential{jwtVC}, lddl)
		require.NoError(t, err)
		require.Len(t, vp.Credentials(), 1)
	})

	t.Run("Match credential in jwt_vc format with filter containing $.vc path", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Constraints: &Constraints{
					Fields: []*Field{{
						Path: []string{"$.vc.last_name"},
					}},
				},
			}},
		}

		issuerDID := "did:example:76e12ec712ebc6f1c221ebfeb1f"

		vc := createTestCredential(t, credentialProto{
			Issued:  utiltime.NewTime(time.Now()),
			Context: []string{verifiable.V1ContextURI},
			Types:   []string{verifiable.VCType},
			ID:      uuid.New().String(),
			Subject: []verifiable.Subject{{ID: issuerDID}},
			Issuer:  &verifiable.Issuer{ID: issuerDID},
			CustomFields: map[string]interface{}{
				"first_name": "Jesse",
				"last_name":  "Travis",
				"age":        17,
			},
		})

		jwtVC, err := vc.CreateUnsecuredJWTVC(false)
		require.NoError(t, err)

		vp, err := pd.CreateVP([]*verifiable.Credential{jwtVC}, lddl)
		require.NoError(t, err)
		require.Len(t, vp.Credentials(), 1)
	})

	t.Run("Match credential in jwt_vc format with expirationDate minimum filter", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Constraints: &Constraints{
					Fields: []*Field{{
						Path: []string{"$.expirationDate", "$.exp"},
						Filter: &Filter{
							FilterItem: FilterItem{
								Type:    &intFilterType,
								Minimum: 1733214225,
							},
						},
					}},
				},
			}},
		}

		issuerDID := "did:example:76e12ec712ebc6f1c221ebfeb1f"

		vc := createTestCredential(t, credentialProto{
			Issued:  utiltime.NewTime(time.Now()),
			Expired: utiltime.NewTime(time.Now().Add(5 * time.Minute)),
			Context: []string{verifiable.V1ContextURI},
			Types:   []string{verifiable.VCType},
			ID:      uuid.New().String(),
			Subject: []verifiable.Subject{{ID: issuerDID}},
			Issuer:  &verifiable.Issuer{ID: issuerDID},
			CustomFields: map[string]interface{}{
				"first_name": "Jesse",
				"last_name":  "Travis",
				"age":        17,
			},
		})

		jwtVC, err := vc.CreateUnsecuredJWTVC(false)
		require.NoError(t, err)

		vp, err := pd.CreateVP([]*verifiable.Credential{jwtVC}, lddl)
		require.NoError(t, err)
		require.Len(t, vp.Credentials(), 1)
	})
}

func TestPresentationDefinition_CreateVP_V2Credential(t *testing.T) {
	lddl := createTestJSONLDDocumentLoader(t)

	t.Run("Checks credentials V2 submission requirements", func(t *testing.T) {
		issuerID := "did:example:76e12ec712ebc6f1c221ebfeb1f"

		vc1 := createTestCredential(t, credentialProto{
			Issued:  utiltime.NewTime(time.Now()),
			Context: []string{verifiable.V2ContextURI},
			Types:   []string{verifiable.VCType},
			ID:      "http://example.edu/credentials/1872",
			Subject: []verifiable.Subject{{ID: issuerID}},
			Issuer:  &verifiable.Issuer{ID: issuerID},
			CustomFields: map[string]interface{}{
				"first_name": "Jesse",
				"last_name":  "Travis",
				"age":        17,
			},
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
				Context: []string{verifiable.V2ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      "http://example.edu/credentials/1872",
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
				},
				Proofs: []verifiable.Proof{{"type": "JsonWebSignature2020"}},
			}),
			createTestCredential(t, credentialProto{
				Context: []string{verifiable.V2ContextURI},
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
				Context: []string{verifiable.V2ContextURI},
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

		type expect struct {
			baseContext string
			vpType      string
			mediaType   verifiable.MediaType
		}

		tests := []struct {
			name    string
			format  string
			vFormat *Format
			expect  expect
		}{
			{
				name:   "test LDP format",
				format: FormatLDP,
				vFormat: &Format{
					Ldp: &LdpType{ProofType: []string{"JsonWebSignature2020"}},
				},
				expect: expect{
					baseContext: verifiable.V2ContextURI,
					vpType:      verifiable.VPType,
				},
			},
			{
				name:   "test LDPVP format",
				format: FormatLDPVP,
				vFormat: &Format{
					LdpVP: &LdpType{ProofType: []string{"JsonWebSignature2020"}},
				},
				expect: expect{
					baseContext: verifiable.V2ContextURI,
					vpType:      verifiable.VPType,
				},
			},
			{
				name:   "test LDPVC format",
				format: FormatLDPVC,
				vFormat: &Format{
					LdpVC: &LdpType{ProofType: []string{"JsonWebSignature2020"}},
				},
				expect: expect{
					baseContext: verifiable.V2ContextURI,
					vpType:      verifiable.VPType,
				},
			},
			{
				name:   "test JWT format",
				format: FormatJWT,
				vFormat: &Format{
					Jwt: &JwtType{Alg: []string{"EdDSA"}},
				},
				expect: expect{
					baseContext: verifiable.V2ContextURI,
					vpType:      verifiable.VPType,
				},
			},
			{
				name:   "test JWTVC format",
				format: FormatJWTVC,
				vFormat: &Format{
					JwtVC: &JwtType{Alg: []string{"EdDSA"}},
				},
				expect: expect{
					baseContext: verifiable.V2ContextURI,
					vpType:      verifiable.VPType,
				},
			},
			{
				name:   "test JWTVP format",
				format: FormatJWTVP,
				vFormat: &Format{
					JwtVP: &JwtType{Alg: []string{"EdDSA"}},
				},
				expect: expect{
					baseContext: verifiable.V2ContextURI,
					vpType:      verifiable.VPEnvelopedType,
					mediaType:   verifiable.VPMediaTypeJWT,
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
							URI: fmt.Sprintf("%s#%s", verifiable.V1ContextID, verifiable.VCType),
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
							URI: fmt.Sprintf("%s#%s", verifiable.V1ContextID, verifiable.VCType),
						}},
						Constraints: &Constraints{
							SubjectIsIssuer: &subIsIssuerRequired,
							Fields: []*Field{{
								Path: []string{"$.age"},
								Filter: &Filter{
									FilterItem: FilterItem{
										Type:    &intFilterType,
										Minimum: 3,
										Maximum: 12,
									},
								},
							}},
						},
					}, {
						ID:    uuid.New().String(),
						Group: []string{"teenager"},
						Schema: []*Schema{{
							URI: fmt.Sprintf("%s#%s", verifiable.V1ContextID, verifiable.VCType),
						}},
						Constraints: &Constraints{
							SubjectIsIssuer: &subIsIssuerRequired,
							Fields: []*Field{{
								Path: []string{"$.age"},
								Filter: &Filter{
									FilterItem: FilterItem{
										Type:    &intFilterType,
										Minimum: 13,
										Maximum: 17,
									},
								},
							}},
						},
					}, {
						ID:    uuid.New().String(),
						Group: []string{"adult"},
						Schema: []*Schema{{
							URI: fmt.Sprintf("%s#%s", verifiable.V1ContextID, verifiable.VCType),
						}},
						Constraints: &Constraints{
							SubjectIsIssuer: &subIsIssuerRequired,
							Fields: []*Field{{
								Path: []string{"$.age"},
								Filter: &Filter{
									FilterItem: FilterItem{
										Type:    &intFilterType,
										Minimum: 18,
										Maximum: 23,
									},
								},
							}},
						},
					}},
					Format: tc.vFormat,
				}

				vp, err := pd.CreateVP(candidateVCs, lddl)

				if tc.format == FormatJWTVP {
					claims, jwtErr := vp.JWTClaims([]string{""}, false)
					require.NoError(t, jwtErr)
					require.NotNil(t, claims)

					unsecuredJWT, marshalErr := claims.MarshalUnsecuredJWT()
					require.NoError(t, marshalErr)
					require.NotEmpty(t, unsecuredJWT)

					vp.JWT = unsecuredJWT
				}

				require.NoError(t, err)
				require.NotNil(t, vp)
				require.Equal(t, 1, len(vp.Credentials()))

				checkSubmission(t, vp, pd)
				checkVPEx(t, vp, tc.format, tc.expect.baseContext, tc.expect.vpType, tc.expect.mediaType)
			})
		}
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

		vpList, ps, err := pd.CreateVPArray(
			[]*verifiable.Credential{
				createTestCredential(t, credentialProto{
					Context: []string{verifiable.V1ContextURI, "https://www.w3.org/2018/credentials/examples/v1"},
					Types:   []string{verifiable.VCType, "UniversityDegreeCredential"},
					ID:      uuid.New().String(),
				}),
				createTestCredential(t, credentialProto{
					Context: []string{verifiable.V1ContextURI, "https://trustbloc.github.io/context/vc/examples-v1.jsonld"},
					Types:   []string{verifiable.VCType, "DocumentVerification"},
					ID:      uuid.New().String(),
				}),
			},
			lddl,
		)

		require.NoError(t, err)
		require.NotNil(t, vpList)
		require.Len(t, vpList, 2)

		checkExternalSubmission(t, vpList, ps, pd)

		require.Equal(t, FormatLDPVP, ps.DescriptorMap[0].Format)

		for _, vp := range vpList {
			checkVP(t, vp, FormatLDPVP)
		}
	})

	t.Run("Matches two descriptors (jwt_vp)", func(t *testing.T) {
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

		vpList, ps, err := pd.CreateVPArray(
			[]*verifiable.Credential{
				createTestCredential(t, credentialProto{
					Context: []string{verifiable.V1ContextURI, "https://www.w3.org/2018/credentials/examples/v1"},
					Types:   []string{verifiable.VCType, "UniversityDegreeCredential"},
					ID:      uuid.New().String(),
				}),
				createTestCredential(t, credentialProto{
					Context: []string{verifiable.V1ContextURI, "https://trustbloc.github.io/context/vc/examples-v1.jsonld"},
					Types:   []string{verifiable.VCType, "DocumentVerification"},
					ID:      uuid.New().String(),
				}),
			},
			lddl,
			WithDefaultPresentationFormat(FormatJWTVP),
		)

		for _, vp := range vpList {
			claims, jwtErr := vp.JWTClaims([]string{""}, false)
			require.NoError(t, jwtErr)
			require.NotNil(t, claims)

			unsecuredJWT, marshalErr := claims.MarshalUnsecuredJWT()
			require.NoError(t, marshalErr)
			require.NotEmpty(t, unsecuredJWT)

			vp.JWT = unsecuredJWT
		}

		require.NoError(t, err)
		require.NotNil(t, vpList)
		require.Len(t, vpList, 2)

		checkExternalSubmission(t, vpList, ps, pd)

		require.Equal(t, FormatJWTVP, ps.DescriptorMap[0].Format)

		for _, vp := range vpList {
			checkVP(t, vp, FormatJWTVP)
		}
	})
}

func TestExtractExtraFields(t *testing.T) {
	results := ExtractArrayValuesForSDJWTV5(map[string]interface{}{
		"_sd": []interface{}{
			"k1NxQSAyCCHlGw-93hxPzOFqUY4Ye7gLqLiKMkSZfHLa48Sevxr5zGHS6Yrb3arK",
			"wu3GHwpa1pJaIv2U71-Y_9kdzjBxlZYRVOG03SIqrOMuytclBPOAU1FSlAnEgOzh",
		},
		"type": []interface{}{
			map[string]interface{}{
				"...": "mhV9Kt70m-8slbu1TgIpdr6_AWO-kG51Q2amF3w9qQyyxM-aXsTn77uxMBAnFM67",
			},
		},
		"someObject": map[string]interface{}{
			"nested": map[string]interface{}{
				"nested2": map[string]interface{}{
					"type": []interface{}{
						map[string]interface{}{
							"...": "xxx",
						},
					},
				},
			},
		},
	})

	require.Len(t, results, 2)
	require.Contains(t, results, "mhV9Kt70m-8slbu1TgIpdr6_AWO-kG51Q2amF3w9qQyyxM-aXsTn77uxMBAnFM67")
	require.Contains(t, results, "xxx")
}

func TestPresentationDefinition_Match_cwt(t *testing.T) {
	const pubKeyID = "did:123#issuer-key"

	verifierDefinitions := &PresentationDefinition{
		InputDescriptors: []*InputDescriptor{
			{
				ID: "banking",
				Schema: []*Schema{{
					URI: "https://example.org/examples#Customer",
				}},
			},
		},
	}

	issuerSigner, _ := testsupport.NewKMSSigVerPair(t, kms.RSARS256Type, pubKeyID)

	vc, err := createCredential(credentialProto{
		Context: append([]string{verifiable.V2ContextURI}, "https://example.context.jsonld/account"),
		Types:   append([]string{verifiable.VCType}, "Customer"),
		ID:      "http://test.credential.com/123",
		Issuer:  &verifiable.Issuer{ID: "http://test.issuer.com"},
		Issued: &utiltime.TimeWrapper{
			Time: time.Now(),
		},
		Subject: []verifiable.Subject{{
			ID: uuid.New().String(),
		}},
	})
	require.NoError(t, err)

	cwtVC, err := vc.CreateSignedCOSEVC(cose.AlgorithmRS256, issuerSigner, pubKeyID)
	require.NoError(t, err)

	vp, err := verifiable.NewPresentation(
		verifiable.WithCredentials(cwtVC),
		verifiable.WithBaseContext(verifiable.V2ContextURI),
	)
	require.NoError(t, err)

	vp.Context = append(vp.Context, "https://identity.foundation/presentation-exchange/submission/v1")
	vp.Type = append(vp.Type, "PresentationSubmission")

	vp.CustomFields = make(map[string]interface{})
	vp.CustomFields["presentation_submission"] = toExampleMap(&PresentationSubmission{DescriptorMap: []*InputDescriptorMapping{
		{
			ID:   "banking",
			Path: "$.verifiableCredential[0]", // use invalid path (missing .vp) to demonstrate the workaround
		},
	}})

	vp, err = vp.CreateCWTVP(
		[]string{"did:example:4a57546973436f6f6c4a4a57573"},
		cose.AlgorithmRS256,
		issuerSigner,
		pubKeyID,
		false,
	)
	require.NoError(t, err)

	vpBytes, err := json.Marshal(vp)
	require.NoError(t, err)

	loader, err := ldtestutil.DocumentLoader(
		ldcontext.Document{
			URL:     "https://example.context.jsonld/account",
			Content: []byte(exampleJSONLDContext),
		},
	)
	require.NoError(t, err)

	receivedVP, err := verifiable.ParsePresentation(vpBytes,
		verifiable.WithPresDisabledProofCheck(),
		verifiable.WithPresJSONLDDocumentLoader(loader),
	)
	require.NoError(t, err)

	matched, err := verifierDefinitions.Match(
		[]*verifiable.Presentation{receivedVP}, loader,
		WithCredentialOptions(
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(loader)),
	)
	require.NoError(t, err)

	var matchedContext string
	var matchedDescriptor string

	for _, descriptor := range verifierDefinitions.InputDescriptors {
		for _, match := range matched {
			if match.DescriptorID == descriptor.ID {
				matchedContext = match.Credential.Contents().Context[1]
				matchedDescriptor = descriptor.ID
			}
		}
	}

	require.Equal(t, "https://example.context.jsonld/account", matchedContext)
	require.Equal(t, "banking", matchedDescriptor)
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

	context := []string{verifiable.V1ContextURI}

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

	vpAsMap := vpToMap(t, vp)

	builder := gval.Full(jsonpath.PlaceholderExtension())
	eval := &pathEvaluator{builder: builder}

	for _, descriptor := range ps.DescriptorMap {
		require.NotEmpty(t, descriptor.ID)
		require.NotEmpty(t, descriptor.Path)
		require.NotEmpty(t, descriptor.Format)

		val := eval.Evaluate(t, vpAsMap, descriptor)
		require.NotNil(t, val)
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

	var rawVPList []interface{}

	for _, vp := range vpList {
		rawVPList = append(rawVPList, vpToMap(t, vp))
	}

	builder := gval.Full(jsonpath.PlaceholderExtension())
	eval := &pathEvaluator{builder: builder}

	for _, descriptor := range ps.DescriptorMap {
		require.NotEmpty(t, descriptor.ID)
		require.NotEmpty(t, descriptor.Path)
		require.NotEmpty(t, descriptor.Format)

		v := eval.Evaluate(t, rawVPList, descriptor)
		require.NotNil(t, v)
	}
}

func vpToMap(t *testing.T, vp *verifiable.Presentation) map[string]interface{} {
	t.Helper()

	var m map[string]interface{}

	if vp.JWT != "" {
		_, _, err := jwt.Parse(vp.JWT,
			jwt.DecodeClaimsTo(&m),
			jwt.WithIgnoreClaimsMapDecoding(true),
		)
		require.NoError(t, err)
	} else {
		b, err := json.Marshal(vp)
		require.NoError(t, err)

		require.NoError(t, json.Unmarshal(b, &m))
	}

	return m
}

type pathEvaluator struct {
	builder gval.Language
}

func (p *pathEvaluator) Evaluate(t *testing.T, data interface{}, descriptor *InputDescriptorMapping) interface{} {
	evaluable, err := p.builder.NewEvaluable(descriptor.Path)
	require.NoError(t, err)

	val, err := evaluable(context.Background(), data)
	require.NoError(t, err)
	require.NotNil(t, val)

	if descriptor.PathNested != nil {
		return p.Evaluate(t, val, descriptor.PathNested)
	}

	return val
}

func checkVP(t *testing.T, vp *verifiable.Presentation, format string) {
	t.Helper()

	checkVPEx(t, vp, format, verifiable.V1ContextURI, verifiable.VPType, "")
}

func checkVPEx(
	t *testing.T,
	vp *verifiable.Presentation,
	format, expectedBaseContext, expectedType string,
	expectedMediaType verifiable.MediaType,
) {
	t.Helper()

	b, err := json.Marshal(vp)
	require.NoError(t, err)

	if format != FormatJWTVP || expectedBaseContext == verifiable.V2ContextURI {
		var doc map[string]interface{}
		require.NoError(t, json.Unmarshal(b, &doc))
		require.True(t, verifiable.HasBaseContext(doc, expectedBaseContext))
		require.Contains(t, doc["type"].([]interface{}), expectedType)

		if expectedType == verifiable.VPEnvelopedType && expectedMediaType != "" {
			mediaType, _, data, parseErr := verifiable.ParseDataURL(doc["id"].(string))
			require.NoError(t, parseErr)
			require.Equal(t, expectedMediaType, mediaType)
			require.NotEmpty(t, data)
		}
	}

	_, err = verifiable.ParsePresentation(b,
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
	RefreshService *verifiable.TypedID
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
