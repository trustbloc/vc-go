/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presexch_test

import (
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/bbs-signature-go/bbs12381g2pub"
	ldprocessor "github.com/trustbloc/did-go/doc/ld/processor"
	"github.com/trustbloc/kms-go/spi/kms"

	utiltime "github.com/trustbloc/did-go/doc/util/time"

	"github.com/trustbloc/vc-go/crypto-ext/testutil"
	"github.com/trustbloc/vc-go/presexch"
	"github.com/trustbloc/vc-go/proof/creator"
	"github.com/trustbloc/vc-go/proof/ldproofs/bbsblssignature2020"
	"github.com/trustbloc/vc-go/proof/testsupport"
	"github.com/trustbloc/vc-go/verifiable"
)

var (
	//go:embed testdata/presentation_definition.json
	presentationDefinition []byte

	//go:embed testdata/submission_requirements_pd.json
	submissionRequirementsPD []byte

	//go:embed testdata/nested_submission_requirements_pd.json
	nestedSubmissionRequirementsPD []byte

	//go:embed testdata/university_degree.jwt
	universityDegreeVC []byte

	//go:embed testdata/permanent_resident_card.jwt
	permanentResidentCardVC []byte

	//go:embed testdata/drivers_license.jwt
	driverLicenseVC []byte

	//go:embed testdata/drivers_license2.jwt
	driverLicenseVC2 []byte

	//go:embed testdata/verified_employee.jwt
	verifiedEmployeeVC []byte
)

const (
	driversLicenseVCType = "DriversLicense"
)

func TestInstance_GetSubmissionRequirements(t *testing.T) {
	docLoader := createTestJSONLDDocumentLoader(t)

	contents := [][]byte{
		universityDegreeVC,
		permanentResidentCardVC,
		driverLicenseVC,
		driverLicenseVC2,
		verifiedEmployeeVC,
	}

	var credentials []*verifiable.Credential

	for _, credContent := range contents {
		cred, credErr := verifiable.ParseCredential(credContent, verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(docLoader))
		require.NoError(t, credErr)

		credentials = append(credentials, cred)
	}

	t.Run("Success", func(t *testing.T) {
		pdQuery := &presexch.PresentationDefinition{}
		err := json.Unmarshal(presentationDefinition, pdQuery)
		require.NoError(t, err)

		requirements, err := pdQuery.MatchSubmissionRequirement(
			credentials,
			docLoader,
		)

		require.NoError(t, err)
		require.Len(t, requirements, 1)

		require.Len(t, requirements[0].Descriptors, 3)
		require.NotNil(t, requirements[0].Descriptors[0].Constraints)
		require.NotNil(t, requirements[0].Descriptors[1].Constraints)
		require.NotNil(t, requirements[0].Descriptors[2].Constraints)
		require.Nil(t, requirements[0].Descriptors[0].Schemas)
		require.Nil(t, requirements[0].Descriptors[1].Schemas)
		require.Nil(t, requirements[0].Descriptors[2].Schemas)

		for _, desc := range requirements[0].Descriptors {
			if desc.ID == driversLicenseVCType {
				require.Len(t, desc.MatchedVCs, 2)
			}
		}
	})

	t.Run("Success with submission requirements", func(t *testing.T) {
		pdQuery := &presexch.PresentationDefinition{}
		err := json.Unmarshal(submissionRequirementsPD, pdQuery)
		require.NoError(t, err)

		requirements, err := pdQuery.MatchSubmissionRequirement(
			credentials,
			docLoader,
		)

		require.NoError(t, err)
		require.Len(t, requirements, 1)

		require.Len(t, requirements[0].Descriptors, 3)

		for _, desc := range requirements[0].Descriptors {
			if desc.ID == driversLicenseVCType {
				require.Len(t, desc.MatchedVCs, 2)
			}
		}
	})

	t.Run("Success with nested submission requirements", func(t *testing.T) {
		pdQuery := &presexch.PresentationDefinition{}
		err := json.Unmarshal(nestedSubmissionRequirementsPD, pdQuery)
		require.NoError(t, err)

		requirements, err := pdQuery.MatchSubmissionRequirement(
			credentials,
			docLoader,
		)

		require.NoError(t, err)
		require.Len(t, requirements, 1)

		require.Len(t, requirements[0].Descriptors, 0)
		require.Len(t, requirements[0].Nested, 2)

		for _, req := range requirements[0].Nested {
			if req.Name == "VerifiedEmployee or Degree" {
				require.Len(t, req.Descriptors, 2)
			}

			if req.Name == driversLicenseVCType {
				require.Len(t, req.Descriptors, 1)
				require.Len(t, req.Descriptors[0].MatchedVCs, 2)
			}
		}
	})

	t.Run("Limit disclosure BBS+", func(t *testing.T) {
		required := presexch.Required

		pd := &presexch.PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*presexch.InputDescriptor{{
				Schema: []*presexch.Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.V1ContextID, verifiable.VCType),
				}},
				ID: uuid.New().String(),
				Constraints: &presexch.Constraints{
					LimitDisclosure: &required,
					Fields: []*presexch.Field{{
						Path:   []string{"$.credentialSubject.degree.degreeSchool"},
						Filter: &presexch.Filter{Type: &strFilterType},
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

		lddl := createTestJSONLDDocumentLoader(t)

		require.NoError(t, vc.AddLinkedDataProof(&verifiable.LinkedDataProofContext{
			SignatureType:           "BbsBlsSignature2020",
			KeyType:                 kms.BLS12381G2Type,
			SignatureRepresentation: verifiable.SignatureProofValue,
			ProofCreator:            creator.New(creator.WithLDProofType(bbsblssignature2020.New(), signer)),
			VerificationMethod:      "did:example:123456#key1",
		}, ldprocessor.WithDocumentLoader(lddl)))

		matched, err := pd.MatchSubmissionRequirement([]*verifiable.Credential{vc}, lddl,
			presexch.WithSelectiveDisclosureApply(),
			presexch.WithSDBBSProofCreator(&verifiable.BBSProofCreator{
				ProofDerivation:            bbs12381g2pub.New(),
				VerificationMethodResolver: testsupport.NewSingleKeyResolver("did:example:123456#key1", srcPublicKey, "Bls12381G2Key2020", ""),
			}),
			presexch.WithSDCredentialOptions(verifiable.WithJSONLDDocumentLoader(lddl)))
		require.NoError(t, err)
		require.Len(t, matched, 1)
		require.Equal(t, 1, len(matched[0].Descriptors))
		require.Equal(t, 1, len(matched[0].Descriptors[0].MatchedVCs))
		require.Equal(t, "https://www.w3.org/2018/credentials#VerifiableCredential",
			matched[0].Descriptors[0].Schemas[0].URI)
		require.False(t, matched[0].Descriptors[0].Schemas[0].Required)

		matchedVC := matched[0].Descriptors[0].MatchedVCs[0]

		require.Equal(t, vc.Contents().ID, matchedVC.Contents().ID)

		subject := matchedVC.Contents().Subject[0]
		degree := subject.CustomFields["degree"]
		require.NotNil(t, degree)

		degreeMap, ok := degree.(map[string]interface{})
		require.True(t, ok)

		require.Equal(t, "MIT school", degreeMap["degreeSchool"])
		require.Equal(t, "BachelorDegree", degreeMap["type"])
		require.Empty(t, degreeMap["degree"])
		require.Equal(t, "did:example:b34ca6cd37bbf23", subject.ID)
		require.Empty(t, subject.CustomFields["spouse"])
		require.Empty(t, matchedVC.CustomField("name"))

		require.NotEmpty(t, matchedVC.Proofs)
	})

	t.Run("Checks schema", func(t *testing.T) {
		pd := &presexch.PresentationDefinition{ID: uuid.New().String()}

		vp, err := pd.MatchSubmissionRequirement(nil, nil)

		require.EqualError(t, err, "presentation_definition: input_descriptors is required")
		require.Nil(t, vp)
	})

	t.Run("Checks submission requirements (no descriptor)", func(t *testing.T) {
		issuerID := uuid.New().String()

		pd := &presexch.PresentationDefinition{
			ID: uuid.New().String(),
			SubmissionRequirements: []*presexch.SubmissionRequirement{
				{
					Rule: "all",
					From: "A",
				},
				{
					Rule:  "pick",
					Count: 1,
					FromNested: []*presexch.SubmissionRequirement{
						{
							Rule: "all",
							From: "teenager",
						},
					},
				},
			},
			InputDescriptors: []*presexch.InputDescriptor{{
				ID:    uuid.New().String(),
				Group: []string{"A"},
				Schema: []*presexch.Schema{{
					URI: verifiable.V1ContextURI,
				}},
				Constraints: &presexch.Constraints{
					SubjectIsIssuer: &subIsIssuerRequired,
					Fields: []*presexch.Field{{
						Path: []string{"$.first_name", "$.last_name"},
					}},
				},
			}},
		}

		result, err := pd.MatchSubmissionRequirement([]*verifiable.Credential{
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
		}, docLoader)

		require.EqualError(t, err, "no descriptors for from: teenager")
		require.Nil(t, result)
	})
}
