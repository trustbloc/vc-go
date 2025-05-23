/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presexch

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	jsonpathkeys "github.com/kawamuray/jsonpath"
	"github.com/piprate/json-gold/ld"
	"github.com/samber/lo"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"github.com/xeipuuv/gojsonschema"

	"github.com/trustbloc/vc-go/presexch/internal/requirementlogic"
	jsonutil "github.com/trustbloc/vc-go/util/json"

	"github.com/trustbloc/vc-go/sdjwt/common"
	"github.com/trustbloc/vc-go/verifiable"

	pathv2 "github.com/theory/jsonpath"
)

const (

	// All rule`s value.
	All Selection = "all"
	// Pick rule`s value.
	Pick Selection = "pick"

	// Required predicate`s value.
	Required Preference = "required"
	// Preferred predicate`s value.
	Preferred Preference = "preferred"

	tmpEnding = "tmp_unique_id_"

	credentialSchema = "credentialSchema"

	// FormatJWT presentation exchange format.
	FormatJWT = "jwt"
	// FormatJWTVC presentation exchange format.
	FormatJWTVC = "jwt_vc"
	// FormatJWTVP presentation exchange format.
	FormatJWTVP = "jwt_vp"
	// FormatLDP presentation exchange format.
	FormatLDP = "ldp"
	// FormatLDPVC presentation exchange format.
	FormatLDPVC = "ldp_vc"
	// FormatLDPVP presentation exchange format.
	FormatLDPVP = "ldp_vp"
)

var errPathNotApplicable = errors.New("path not applicable")

type (
	// Selection can be "all" or "pick".
	Selection string
	// Preference can be "required" or "preferred".
	Preference string
	// StrOrInt type that defines string or integer.
	StrOrInt interface{}
)

func (v *Preference) isRequired() bool {
	if v == nil {
		return false
	}

	return *v == Required
}

// Format describes PresentationDefinition`s Format field.
type Format struct {
	Jwt   *JwtType `json:"jwt,omitempty"`
	JwtVC *JwtType `json:"jwt_vc,omitempty"`
	JwtVP *JwtType `json:"jwt_vp,omitempty"`

	Ldp   *LdpType `json:"ldp,omitempty"`
	LdpVC *LdpType `json:"ldp_vc,omitempty"`
	LdpVP *LdpType `json:"ldp_vp,omitempty"`

	CwtVC *CwtType `json:"cwt_vc,omitempty"`
	CwtVP *CwtType `json:"cwt_vp,omitempty"`
}

func (f *Format) notNil() bool {
	return f != nil &&
		(f.Jwt != nil || f.JwtVC != nil || f.JwtVP != nil || f.Ldp != nil || f.LdpVC != nil || f.LdpVP != nil)
}

// CwtType contains alg.
type CwtType struct {
	Alg []string `json:"alg,omitempty"`
}

// JwtType contains alg.
type JwtType struct {
	Alg []string `json:"alg,omitempty"`
}

// LdpType contains proof_type.
type LdpType struct {
	ProofType []string `json:"proof_type,omitempty"`
}

// PresentationDefinition presentation definitions (https://identity.foundation/presentation-exchange/).
type PresentationDefinition struct {
	// ID unique resource identifier.
	ID string `json:"id,omitempty"`
	// Name human-friendly name that describes what the Presentation Definition pertains to.
	Name string `json:"name,omitempty"`
	// Purpose describes the purpose for which the Presentation Definition’s inputs are being requested.
	Purpose string `json:"purpose,omitempty"`
	Locale  string `json:"locale,omitempty"`
	// Format is an object with one or more properties matching the registered Claim Format Designations
	// (jwt, jwt_vc, jwt_vp, etc.) to inform the Holder of the claim format configurations the Verifier can process.
	Format *Format `json:"format,omitempty"`
	// Frame is used for JSON-LD document framing.
	Frame map[string]interface{} `json:"frame,omitempty"`
	// SubmissionRequirements must conform to the Submission Requirement Format.
	// If not present, all inputs listed in the InputDescriptors array are required for submission.
	SubmissionRequirements []*SubmissionRequirement `json:"submission_requirements,omitempty"`
	InputDescriptors       []*InputDescriptor       `json:"input_descriptors,omitempty"`
}

// SubmissionRequirement describes input that must be submitted via a Presentation Submission
// to satisfy Verifier demands.
type SubmissionRequirement struct {
	Name       string                   `json:"name,omitempty"`
	Purpose    string                   `json:"purpose,omitempty"`
	Rule       Selection                `json:"rule,omitempty"`
	Count      int                      `json:"count,omitempty"`
	Min        int                      `json:"min,omitempty"`
	Max        int                      `json:"max,omitempty"`
	From       string                   `json:"from,omitempty"`
	FromNested []*SubmissionRequirement `json:"from_nested,omitempty"`
}

// InputDescriptor input descriptors.
type InputDescriptor struct {
	ID          string                 `json:"id,omitempty"`
	Group       []string               `json:"group,omitempty"`
	Name        string                 `json:"name,omitempty"`
	Purpose     string                 `json:"purpose,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Schema      []*Schema              `json:"schema,omitempty"`
	Constraints *Constraints           `json:"constraints,omitempty"`
	Format      *Format                `json:"format,omitempty"`
}

// Schema input descriptor schema.
type Schema struct {
	URI      string `json:"uri,omitempty"`
	Required bool   `json:"required,omitempty"`
}

// Holder describes Constraints`s  holder object.
type Holder struct {
	FieldID   []string    `json:"field_id,omitempty"`
	Directive *Preference `json:"directive,omitempty"`
}

// Constraints describes InputDescriptor`s Constraints field.
type Constraints struct {
	LimitDisclosure *Preference `json:"limit_disclosure,omitempty"`
	SubjectIsIssuer *Preference `json:"subject_is_issuer,omitempty"`
	IsHolder        []*Holder   `json:"is_holder,omitempty"`
	Fields          []*Field    `json:"fields,omitempty"`
}

// Field describes Constraints`s Fields field.
type Field struct {
	Path           []string    `json:"path,omitempty"`
	ID             string      `json:"id,omitempty"`
	Purpose        string      `json:"purpose,omitempty"`
	Filter         *Filter     `json:"filter,omitempty"`
	Predicate      *Preference `json:"predicate,omitempty"`
	IntentToRetain bool        `json:"intent_to_retain,omitempty"`
	Optional       bool        `json:"optional,omitempty"`
}

// Filter describes filter.
type Filter struct {
	FilterItem
	AllOf []*FilterItem `json:"allOf,omitempty"`
}

// FilterItem describes filter item.
type FilterItem struct {
	Type             *string                `json:"type,omitempty"`
	Format           string                 `json:"format,omitempty"`
	Pattern          string                 `json:"pattern,omitempty"`
	Minimum          StrOrInt               `json:"minimum,omitempty"`
	Maximum          StrOrInt               `json:"maximum,omitempty"`
	MinLength        int                    `json:"minLength,omitempty"`
	MaxLength        int                    `json:"maxLength,omitempty"`
	ExclusiveMinimum StrOrInt               `json:"exclusiveMinimum,omitempty"`
	ExclusiveMaximum StrOrInt               `json:"exclusiveMaximum,omitempty"`
	Const            StrOrInt               `json:"const,omitempty"`
	Enum             []StrOrInt             `json:"enum,omitempty"`
	Not              map[string]interface{} `json:"not,omitempty"`
	Contains         map[string]interface{} `json:"contains,omitempty"`
}

// MatchedSubmissionRequirement contains information about VCs that matched a presentation definition.
type MatchedSubmissionRequirement struct {
	Name        string
	Purpose     string
	Rule        Selection
	Count       int
	Min         int
	Max         int
	Descriptors []*MatchedInputDescriptor
	Nested      []*MatchedSubmissionRequirement
}

// MatchedInputDescriptor contains information about VCs that matched an input descriptor of presentation definition.
type MatchedInputDescriptor struct {
	ID          string
	Name        string
	Purpose     string
	Constraints *Constraints
	Schemas     []*Schema
	MatchedVCs  []*verifiable.Credential
}

// matchRequirementsOpts holds options for the MatchSubmissionRequirement.
type matchRequirementsOpts struct {
	applySelectiveDisclosure bool
	sdBBSProofCreator        *verifiable.BBSProofCreator
	credOpts                 []verifiable.CredentialOpt
	defaultVPFormat          string
}

// MatchRequirementsOpt is the MatchSubmissionRequirement option.
type MatchRequirementsOpt func(opts *matchRequirementsOpts)

// WithSelectiveDisclosureApply enables selective disclosure apply on resulting VC.
func WithSelectiveDisclosureApply() MatchRequirementsOpt {
	return func(opts *matchRequirementsOpts) {
		opts.applySelectiveDisclosure = true
	}
}

// WithSDCredentialOptions used when applying selective disclosure.
func WithSDCredentialOptions(options ...verifiable.CredentialOpt) MatchRequirementsOpt {
	return func(opts *matchRequirementsOpts) {
		opts.credOpts = options
	}
}

// WithSDBBSProofCreator used when applying selective disclosure.
func WithSDBBSProofCreator(sdBBSProofCreator *verifiable.BBSProofCreator) MatchRequirementsOpt {
	return func(opts *matchRequirementsOpts) {
		opts.sdBBSProofCreator = sdBBSProofCreator
	}
}

// WithDefaultPresentationFormat sets the default presentation format.
func WithDefaultPresentationFormat(format string) MatchRequirementsOpt {
	return func(opts *matchRequirementsOpts) {
		opts.defaultVPFormat = format
	}
}

// ValidateSchema validates presentation definition.
func (pd *PresentationDefinition) ValidateSchema() error {
	result, err := gojsonschema.Validate(
		gojsonschema.NewStringLoader(DefinitionJSONSchemaV1),
		gojsonschema.NewGoLoader(struct {
			PD *PresentationDefinition `json:"presentation_definition"`
		}{PD: pd}),
	)

	if err != nil || !result.Valid() {
		result, err = gojsonschema.Validate(
			gojsonschema.NewStringLoader(DefinitionJSONSchemaV2),
			gojsonschema.NewGoLoader(struct {
				PD *PresentationDefinition `json:"presentation_definition"`
			}{PD: pd}),
		)
	}

	if err != nil {
		return err
	}

	if result.Valid() {
		return nil
	}

	resultErrors := result.Errors()

	errs := make([]string, len(resultErrors))
	for i := range resultErrors {
		errs[i] = resultErrors[i].String()
	}

	return errors.New(strings.Join(errs, ","))
}

type constraintsFilterResult struct {
	credential    *verifiable.Credential
	credentialSrc []byte
	constraints   *Constraints
}

type requirement struct {
	Name             string
	Purpose          string
	Rule             Selection
	Count            int
	Min              int
	Max              int
	InputDescriptors []*InputDescriptor
	Nested           []*requirement
}

func (r *requirement) toLogic() *requirementlogic.RequirementLogic {
	rl := &requirementlogic.RequirementLogic{
		InputDescriptorIDs: nil,
		Nested:             nil,
		Count:              r.Count,
		Min:                r.Min,
		Max:                r.Max,
	}

	total := 0

	if len(r.InputDescriptors) > 0 {
		total = len(r.InputDescriptors)

		for _, descriptor := range r.InputDescriptors {
			rl.InputDescriptorIDs = append(rl.InputDescriptorIDs, descriptor.ID)
		}
	}

	if len(r.Nested) > 0 {
		total = len(r.Nested)

		for _, nestedReq := range r.Nested {
			rl.Nested = append(rl.Nested, nestedReq.toLogic())
		}
	}

	if r.Count == 0 && r.Max == 0 {
		rl.Max = total
	}

	return rl
}

func (r *requirement) getAllDescriptors() map[string]*InputDescriptor {
	if len(r.InputDescriptors) > 0 {
		return descriptorIDMap(r.InputDescriptors)
	}

	out := map[string]*InputDescriptor{}

	for _, child := range r.Nested {
		childResult := child.getAllDescriptors()

		for s, descriptor := range childResult {
			if _, ok := out[s]; !ok {
				out[s] = descriptor
			}
		}
	}

	return out
}

func descriptorIDMap(descs []*InputDescriptor) map[string]*InputDescriptor {
	out := map[string]*InputDescriptor{}

	for _, desc := range descs {
		out[desc.ID] = desc
	}

	return out
}
func contains(data []string, e string) bool {
	for _, el := range data {
		if el == e {
			return true
		}
	}

	return false
}

func toRequirement(sr *SubmissionRequirement, descriptors []*InputDescriptor) (*requirement, error) {
	var (
		inputDescriptors []*InputDescriptor
		nested           []*requirement
	)

	var totalCount int

	if sr.From != "" {
		for _, descriptor := range descriptors {
			if contains(descriptor.Group, sr.From) {
				inputDescriptors = append(inputDescriptors, descriptor)
			}
		}

		totalCount = len(inputDescriptors)
		if totalCount == 0 {
			return nil, fmt.Errorf("no descriptors for from: %s", sr.From)
		}
	} else {
		for _, sReq := range sr.FromNested {
			req, err := toRequirement(sReq, descriptors)
			if err != nil {
				return nil, err
			}

			nested = append(nested, req)
		}

		totalCount = len(nested)
	}

	count := sr.Count

	if sr.Rule == All {
		count = totalCount
	}

	return &requirement{
		Name:             sr.Name,
		Purpose:          sr.Purpose,
		Rule:             sr.Rule,
		Count:            count,
		Min:              sr.Min,
		Max:              sr.Max,
		InputDescriptors: inputDescriptors,
		Nested:           nested,
	}, nil
}

func makeRequirement(requirements []*SubmissionRequirement, descriptors []*InputDescriptor) (*requirement, error) {
	if len(requirements) == 0 {
		return &requirement{
			Count:            len(descriptors),
			InputDescriptors: descriptors,
		}, nil
	}

	req := &requirement{
		Count: len(requirements),
	}

	for _, submissionRequirement := range requirements {
		r, err := toRequirement(submissionRequirement, descriptors)
		if err != nil {
			return nil, err
		}

		req.Nested = append(req.Nested, r)
	}

	return req, nil
}

// CreateVP creates verifiable presentation.
func (pd *PresentationDefinition) CreateVP(
	credentials []*verifiable.Credential,
	documentLoader ld.DocumentLoader,
	opts ...MatchRequirementsOpt,
) (*verifiable.Presentation, error) {
	matchOpts := &matchRequirementsOpts{defaultVPFormat: FormatLDPVP}
	for _, opt := range opts {
		opt(matchOpts)
	}

	applicableCredentials, submission, err := presentationData(pd, credentials, documentLoader, false,
		matchOpts.sdBBSProofCreator, matchOpts.defaultVPFormat, matchOpts.credOpts...)
	if err != nil {
		return nil, err
	}

	vp, err := presentation(applicableCredentials...)
	if err != nil {
		return nil, err
	}

	vp.CustomFields = verifiable.CustomFields{
		submissionProperty: submission,
	}

	return vp, nil
}

// CreateVPArray creates a list of verifiable presentations, with one presentation for each provided credential.
// A PresentationSubmission is returned alongside, which uses the presentation list as the root for json paths.
func (pd *PresentationDefinition) CreateVPArray(
	credentials []*verifiable.Credential,
	documentLoader ld.DocumentLoader,
	opts ...MatchRequirementsOpt,
) ([]*verifiable.Presentation, *PresentationSubmission, error) {
	matchOpts := &matchRequirementsOpts{defaultVPFormat: FormatLDPVP}
	for _, opt := range opts {
		opt(matchOpts)
	}

	applicableCredentials, submission, err := presentationData(pd, credentials, documentLoader, true,
		matchOpts.sdBBSProofCreator, matchOpts.defaultVPFormat, matchOpts.credOpts...)
	if err != nil {
		return nil, nil, err
	}

	var presentations []*verifiable.Presentation

	for _, credential := range applicableCredentials {
		vp, e := presentation(credential)
		if e != nil {
			return nil, nil, e
		}

		presentations = append(presentations, vp)
	}

	return presentations, submission, nil
}

func presentationData(
	pd *PresentationDefinition,
	credentials []*verifiable.Credential,
	documentLoader ld.DocumentLoader,
	separatePresentations bool,
	sdBBSProofCreator *verifiable.BBSProofCreator,
	defaultVPFormat string,
	opts ...verifiable.CredentialOpt,
) ([]*verifiable.Credential, *PresentationSubmission, error) {
	if err := pd.ValidateSchema(); err != nil {
		return nil, nil, err
	}

	req, err := makeRequirement(pd.SubmissionRequirements, pd.InputDescriptors)
	if err != nil {
		return nil, nil, err
	}

	format, result, err := pd.applyRequirement(
		req, credentials, documentLoader, sdBBSProofCreator, defaultVPFormat, opts...)
	if err != nil {
		return nil, nil, err
	}

	applicableCredentials, descriptors := merge(format, result, separatePresentations)

	submission := &PresentationSubmission{
		ID:            uuid.New().String(),
		DefinitionID:  pd.ID,
		DescriptorMap: descriptors,
	}

	return applicableCredentials, submission, nil
}

func presentation(credentials ...*verifiable.Credential) (*verifiable.Presentation, error) {
	baseContext, err := getBaseContext(credentials)
	if err != nil {
		return nil, fmt.Errorf("get base context: %w", err)
	}

	vp, e := verifiable.NewPresentation(
		verifiable.WithCredentials(credentials...),
		verifiable.WithBaseContext(baseContext),
	)
	if e != nil {
		return nil, e
	}

	if !lo.Contains(vp.Context, PresentationSubmissionJSONLDContextIRI) {
		vp.Context = append(vp.Context, PresentationSubmissionJSONLDContextIRI)
	}

	if !lo.Contains(vp.Type, PresentationSubmissionJSONLDType) {
		vp.Type = append(vp.Type, PresentationSubmissionJSONLDType)
	}

	vp.ID = uuid.NewString()

	return vp, nil
}

func makeRequirementsForMatch(requirements []*SubmissionRequirement,
	descriptors []*InputDescriptor) ([]*requirement, error) {
	if len(requirements) == 0 {
		return []*requirement{{
			Name:             "",
			Purpose:          "",
			Rule:             All,
			Count:            len(descriptors),
			InputDescriptors: descriptors,
			Nested:           nil,
		}}, nil
	}

	var reqs []*requirement

	for _, submissionRequirement := range requirements {
		r, err := toRequirement(submissionRequirement, descriptors)
		if err != nil {
			return nil, err
		}

		reqs = append(reqs, r)
	}

	return reqs, nil
}

// MatchSubmissionRequirement return information about matching VCs.
func (pd *PresentationDefinition) MatchSubmissionRequirement(credentials []*verifiable.Credential,
	documentLoader ld.DocumentLoader, opts ...MatchRequirementsOpt) ([]*MatchedSubmissionRequirement, error) {
	matchOpts := &matchRequirementsOpts{defaultVPFormat: FormatLDPVP}
	for _, opt := range opts {
		opt(matchOpts)
	}

	if err := pd.ValidateSchema(); err != nil {
		return nil, err
	}

	requirements, err := makeRequirementsForMatch(pd.SubmissionRequirements, pd.InputDescriptors)
	if err != nil {
		return nil, err
	}

	var matchedReqs []*MatchedSubmissionRequirement

	for _, req := range requirements {
		matched, err := pd.matchRequirement(req, credentials, documentLoader, matchOpts)
		if err != nil {
			return nil, err
		}

		matchedReqs = append(matchedReqs, matched)
	}

	return matchedReqs, nil
}

// ErrNoCredentials when any credentials do not satisfy requirements.
var ErrNoCredentials = errors.New("credentials do not satisfy requirements")

// nolint: funlen,gocyclo
func (pd *PresentationDefinition) matchRequirement(req *requirement, creds []*verifiable.Credential,
	documentLoader ld.DocumentLoader, opts *matchRequirementsOpts) (*MatchedSubmissionRequirement, error) {
	matchedReq := &MatchedSubmissionRequirement{
		Name:        req.Name,
		Purpose:     req.Purpose,
		Rule:        req.Rule,
		Count:       req.Count,
		Min:         req.Min,
		Max:         req.Max,
		Descriptors: nil,
		Nested:      nil,
	}

	for _, descriptor := range req.InputDescriptors {
		framedCreds := creds

		var err error

		if opts.applySelectiveDisclosure {
			framedCreds, err = frameCreds(pd.Frame, creds, opts.sdBBSProofCreator, opts.credOpts...)
			if err != nil {
				return nil, err
			}
		}

		_, filtered, err := pd.filterCredentialsThatMatchDescriptor(
			framedCreds, descriptor, documentLoader)
		if err != nil {
			return nil, err
		}

		var matchedVCs []*verifiable.Credential

		if opts.applySelectiveDisclosure {
			limitedVCs, err := limitDisclosure(filtered, opts.sdBBSProofCreator, opts.credOpts...)
			if err != nil {
				return nil, err
			}

			for _, cred := range limitedVCs {
				matchedVCs = append(matchedVCs, cred.vc)
			}
		} else {
			for _, credRes := range filtered {
				matchedVCs = append(matchedVCs, credRes.credential)
			}
		}

		matchedReq.Descriptors = append(matchedReq.Descriptors, &MatchedInputDescriptor{
			ID:          descriptor.ID,
			Name:        descriptor.Name,
			Purpose:     descriptor.Purpose,
			Constraints: descriptor.Constraints,
			Schemas:     descriptor.Schema,
			MatchedVCs:  matchedVCs,
		})
	}

	for _, nestedReq := range req.Nested {
		nestedMatch, err := pd.matchRequirement(nestedReq, creds, documentLoader, opts)
		if err != nil {
			return nil, err
		}

		matchedReq.Nested = append(matchedReq.Nested, nestedMatch)
	}

	return matchedReq, nil
}

type credWrapper struct {
	uniqueID string
	vc       *verifiable.Credential
}

func (pd *PresentationDefinition) applyRequirement( // nolint:funlen,gocyclo
	req *requirement,
	creds []*verifiable.Credential,
	documentLoader ld.DocumentLoader,
	sdBBSProofCreator *verifiable.BBSProofCreator,
	defaultVPFormat string,
	opts ...verifiable.CredentialOpt,
) (string, map[string][]*credWrapper, error) {
	reqLogic := req.toLogic()

	var descIDs []string

	for _, descriptor := range pd.InputDescriptors {
		descIDs = append(descIDs, descriptor.ID)
	}

	iterator := reqLogic.Iterator(descIDs)

	descs := req.getAllDescriptors()

	framedCreds, e := frameCreds(pd.Frame, creds, sdBBSProofCreator, opts...)
	if e != nil {
		return "", nil, e
	}

	descriptorMatches := make(map[string]*descriptorMatch)

	evaluated := requirementlogic.DescriptorIDSet{}

	var excludeDescriptors []string

	for sol := iterator.Next(excludeDescriptors); sol != nil; sol = iterator.Next(excludeDescriptors) {
		solved := true
		excludeDescriptors = nil

		for _, descID := range sol {
			if evaluated.Has(descID) {
				if _, ok := descriptorMatches[descID]; !ok {
					solved = false
					break
				}

				continue
			}

			evaluated.Add(descID)

			descriptor := descs[descID]

			descFormat, filtered, err := pd.filterCredentialsThatMatchDescriptor(
				framedCreds, descriptor, documentLoader)
			if err != nil {
				return "", nil, err
			}

			filteredCreds, err := limitDisclosure(filtered, sdBBSProofCreator, opts...)
			if err != nil {
				return "", nil, err
			}

			if len(filteredCreds) != 0 {
				descriptorMatches[descriptor.ID] = &descriptorMatch{
					format: descFormat,
					creds:  filteredCreds,
				}
			} else {
				solved = false

				excludeDescriptors = append(excludeDescriptors, descID)

				break
			}
		}

		if solved {
			result := make(map[string][]*credWrapper)

			// use defaultVPFormat format if pd.Format is not set.
			// Usually pd.Format will be set when creds include a non-empty Proofs field since they represent the designated
			// format.
			vpFormat := defaultVPFormat

			for _, descID := range sol {
				result[descID] = descriptorMatches[descID].creds

				if format := descriptorMatches[descID].format; format != "" {
					vpFormat = format
				}
			}

			return vpFormat, result, nil
		}
	}

	return "", nil, ErrNoCredentials
}

type descriptorMatch struct {
	format string
	creds  []*credWrapper
}

func (pd *PresentationDefinition) filterCredentialsThatMatchDescriptor(
	creds []*verifiable.Credential,
	descriptor *InputDescriptor,
	documentLoader ld.DocumentLoader,
) (string, []constraintsFilterResult, error) {
	format := pd.Format
	if descriptor.Format.notNil() {
		format = descriptor.Format
	}

	vpFormat := ""
	filtered := creds

	if format.notNil() {
		vpFormat, filtered = filterFormat(format, filtered)
	}

	var err error
	// Validate schema only for v1
	if descriptor.Schema != nil {
		filtered, err = filterSchema(descriptor.Schema, filtered, documentLoader)
		if err != nil {
			return "", nil, err
		}
	}

	filteredByConstraints, _, err := filterConstraints(descriptor.Constraints, filtered)
	if err != nil {
		return "", nil, err
	}

	return vpFormat, filteredByConstraints, nil
}

func getSubjectIDs(subject interface{}) []string { // nolint: gocyclo
	switch s := subject.(type) {
	case string:
		return []string{s}
	case []map[string]interface{}:
		var res []string

		for i := range s {
			v, ok := s[i]["id"]
			if !ok {
				continue
			}

			sID, ok := v.(string)
			if !ok {
				continue
			}

			res = append(res, sID)
		}

		return res
	case map[string]interface{}:
		v, ok := s["id"]
		if !ok {
			return nil
		}

		sID, ok := v.(string)
		if !ok {
			return nil
		}

		return []string{sID}
	case verifiable.Subject:
		return []string{s.ID}

	case []verifiable.Subject:
		var res []string
		for i := range s {
			res = append(res, s[i].ID)
		}

		return res
	}

	return nil
}

func subjectIsIssuer(contents *verifiable.CredentialContents) bool {
	if contents.Issuer == nil {
		return false
	}

	for _, ID := range getSubjectIDs(contents.Subject) {
		if ID != "" && ID == contents.Issuer.ID {
			return true
		}
	}

	return false
}

// nolint: gocyclo,funlen,gocognit,unparam
func filterConstraints(constraints *Constraints, creds []*verifiable.Credential) (
	[]constraintsFilterResult,
	[]map[string]interface{},
	error,
) {
	var result []constraintsFilterResult

	var debugCred []map[string]interface{}

	if constraints == nil {
		for _, credential := range creds {
			result = append(result, constraintsFilterResult{
				credential: credential,
			})
		}

		return result, debugCred, nil
	}

	for _, credential := range creds {
		credentialContents := credential.Contents()

		if constraints.SubjectIsIssuer.isRequired() && !subjectIsIssuer(&credentialContents) {
			continue
		}

		var applicable bool

		var err error

		credentialWithFieldValues := credential

		if isSDJWTCredential(&credentialContents) {
			credentialWithFieldValues, err = credential.CreateDisplayCredential(verifiable.DisplayAllDisclosures())
			if err != nil {
				continue
			}
		}

		credentialSrc, err := credentialWithFieldValues.MarshalAsJSONLD()
		if err != nil {
			continue
		}

		var credentialMap map[string]interface{}

		err = json.Unmarshal(credentialSrc, &credentialMap)
		if err != nil {
			return nil, debugCred, err
		}

		debugCred = append(debugCred, credentialMap)

		for i, field := range constraints.Fields {
			err = filterField(field, credentialMap, credential.IsJWT())
			if errors.Is(err, errPathNotApplicable) {
				applicable = false

				break
			}

			if err != nil {
				return nil, debugCred, fmt.Errorf("filter field.%d: %w", i, err)
			}

			applicable = true
		}

		if !applicable {
			continue
		}

		filterRes := constraintsFilterResult{
			credential:    credential,
			credentialSrc: credentialSrc,
			constraints:   constraints,
		}

		result = append(result, filterRes)
	}

	return result, debugCred, nil
}

// nolint: gocyclo, funlen
func limitDisclosure(filterResults []constraintsFilterResult,
	sdBBSProofCreator *verifiable.BBSProofCreator, opts ...verifiable.CredentialOpt) ([]*credWrapper, error) {
	var result []*credWrapper

	for _, filtered := range filterResults {
		credential := filtered.credential
		credentialContents := credential.Contents()

		constraints := filtered.constraints
		credentialSrc := filtered.credentialSrc

		if constraints == nil {
			result = append(result, &credWrapper{uniqueID: credentialContents.ID, vc: credential})
			continue
		}

		var predicate bool

		for _, field := range constraints.Fields {
			if field.Predicate.isRequired() {
				predicate = true
			}
		}

		if constraints.LimitDisclosure.isRequired() &&
			!(predicate || supportsSelectiveDisclosure(credential) || subjectIsIssuer(&credentialContents)) {
			continue
		}

		uniqueCredID := credentialContents.ID

		// Non-SDJWT case.
		//nolint:nestif
		if (constraints.LimitDisclosure.isRequired() || predicate) &&
			!isSDJWTCredential(&credentialContents) {
			template := credentialSrc

			if constraints.LimitDisclosure.isRequired() {
				var (
					contexts []interface{}
					err      error
				)

				for _, ctx := range credentialContents.Context {
					contexts = append(contexts, ctx)
				}

				contexts = append(contexts, credentialContents.CustomContext...)

				templateObj := jsonutil.Select(credential.ToRawJSON(),
					"id",
					"type",
					"@context",
					"issuer",
					"issuanceDate")

				templateObj["credentialSubject"] = copyOnlySubjectIDs(credentialContents.Subject)

				template, err = json.Marshal(templateObj)
				if err != nil {
					return nil, err
				}
			}

			var err error

			isJWTVC := credential.IsJWT()

			credential, err = createNewCredential(constraints,
				credentialSrc, template, credential, sdBBSProofCreator, opts...)
			if err != nil {
				return nil, fmt.Errorf("create new credential: %w", err)
			}

			if isJWTVC {
				var unsecuredJWTVC *verifiable.Credential

				unsecuredJWTVC, err = credential.CreateUnsecuredJWTVC(false)
				if err != nil {
					return nil, fmt.Errorf("limitDisclosure create unsecured jwt vc: %w", err)
				}

				credential = unsecuredJWTVC
			}

			uniqueCredID = tmpID(credentialContents.ID)
		}

		// SDJWT case.
		if constraints.LimitDisclosure.isRequired() && isSDJWTCredential(&credentialContents) {
			limitedDisclosures, err := getLimitedDisclosures(constraints, credentialSrc, credential)
			if err != nil {
				return nil, err
			}

			err = credential.SetSDJWTDisclosures(limitedDisclosures)
			if err != nil {
				return nil, err
			}
		}

		result = append(result, &credWrapper{uniqueID: uniqueCredID, vc: credential})
	}

	return result, nil
}

// nolint: gocyclo,funlen,gocognit
func getLimitedDisclosures(constraints *Constraints, displaySrc []byte, credential *verifiable.Credential) ([]*common.DisclosureClaim, error) { // nolint:lll
	credentialContents := credential.Contents()

	credentialSrc, err := credential.MarshalAsJSONLD()
	if err != nil {
		return nil, err
	}

	var limitedDisclosures []*common.DisclosureClaim

	for _, f := range constraints.Fields {
		jPaths, err := compactArrayPaths(f.Path, displaySrc)
		if err != nil {
			return nil, err
		}

		for _, path := range jPaths {
			if strings.Contains(path.newPath, credentialSchema) {
				continue
			}

			parentPath, key := splitLast(path.oldPath, ".")

			parentObj, ok := gjson.GetBytes(credentialSrc, parentPath).Value().(map[string]interface{})
			if !ok {
				// no selective disclosures at this level, so nothing to add to limited disclosures
				continue
			}

			digests, err := common.GetDisclosureDigests(parentObj)
			if err != nil {
				return nil, err
			}

			disclosures := credential.SDJWTDisclosures()
			disclosuresMap := map[string]*common.DisclosureClaim{}

			for _, dc := range disclosures {
				disclosuresMap[dc.Digest] = dc
			}

			arrayElements := ExtractArrayValuesForSDJWTV5(parentObj)
			for _, elem := range arrayElements {
				dis, disOk := disclosuresMap[elem]
				if disOk {
					limitedDisclosures = append(limitedDisclosures, dis)
				}
			}

			for _, dc := range disclosures {
				if dc.Name == key {
					digest, err := common.GetHash(*credentialContents.SDJWTHashAlg, dc.Disclosure)
					if err != nil {
						return nil, err
					}

					if _, ok := digests[digest]; ok {
						limitedDisclosures = append(limitedDisclosures, dc)
					}
				}
			}
		}
	}

	return limitedDisclosures, nil
}

// ExtractArrayValuesForSDJWTV5 extracts array values for SD JWT V5.
func ExtractArrayValuesForSDJWTV5(obj map[string]interface{}) []string {
	var extractedValues []string

	for key, v := range obj {
		switch val := v.(type) {
		case string:
			if key == "..." {
				extractedValues = append(extractedValues, val)
			}
		case map[string]interface{}:
			extractedValues = append(extractedValues, ExtractArrayValuesForSDJWTV5(val)...)
		case []interface{}:
			for _, valData := range val {
				if d1, ok1 := valData.(map[string]interface{}); ok1 {
					extractedValues = append(extractedValues, ExtractArrayValuesForSDJWTV5(d1)...)
				}
			}
		}
	}

	return extractedValues
}

func frameCreds(frame map[string]interface{}, creds []*verifiable.Credential,
	sdBBSProofCreator *verifiable.BBSProofCreator,
	opts ...verifiable.CredentialOpt) ([]*verifiable.Credential, error) {
	if frame == nil {
		return creds, nil
	}

	var result []*verifiable.Credential

	for _, credential := range creds {
		bbsVC, err := credential.GenerateBBSSelectiveDisclosure(frame, nil, sdBBSProofCreator, opts...)
		if err != nil {
			return nil, err
		}

		result = append(result, bbsVC)
	}

	return result, nil
}

func copyOnlySubjectIDs(subject []verifiable.Subject) interface{} {
	if len(subject) == 1 {
		if len(subject[0].CustomFields) == 0 {
			return subject[0].ID
		}

		return verifiable.SubjectToJSON(verifiable.Subject{ID: subject[0].ID})
	}

	var withOnlyIDs []interface{}

	for _, s := range subject {
		withOnlyIDs = append(withOnlyIDs, verifiable.SubjectToJSON(verifiable.Subject{ID: s.ID}))
	}

	return withOnlyIDs
}

func tmpID(id string) string {
	return id + tmpEnding + uuid.New().String()
}

// nolint: funlen,gocognit,gocyclo
func createNewCredential(constraints *Constraints, src, limitedCred []byte,
	credential *verifiable.Credential, sdBBSProofCreator *verifiable.BBSProofCreator,
	opts ...verifiable.CredentialOpt) (*verifiable.Credential, error) {
	var (
		doBBS               = hasBBS(credential) && constraints.LimitDisclosure.isRequired()
		modifiedByPredicate bool
		explicitPaths       = make(map[string]bool)
	)

	for _, f := range constraints.Fields {
		jPaths, err := compactArrayPaths(f.Path, src)
		if err != nil {
			return nil, err
		}

		for _, path := range jPaths {
			if strings.Contains(path.newPath, credentialSchema) {
				continue
			}

			var val interface{} = true

			if f.Predicate.isRequired() {
				modifiedByPredicate = true
			} else {
				val = gjson.GetBytes(src, path.oldPath).Value()
			}

			if doBBS {
				explicitPath, _ := splitLast(path.newPath, ".")
				explicitPaths[explicitPath] = true
			}

			limitedCred, err = sjson.SetBytes(limitedCred, path.newPath, val)
			if err != nil {
				return nil, err
			}
		}
	}

	if !doBBS || modifiedByPredicate {
		opts = append(opts, verifiable.WithDisabledProofCheck())
		return verifiable.ParseCredential(limitedCred, opts...)
	}

	revealDoc, err := enhanceRevealDoc(explicitPaths, limitedCred, src)
	if err != nil {
		return nil, err
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(revealDoc, &doc); err != nil {
		return nil, err
	}

	return credential.GenerateBBSSelectiveDisclosure(doc, []byte(uuid.New().String()), sdBBSProofCreator, opts...)
}

// splitLast finds the final occurrence of split in text, and returns (everything before, everything after).
// If split is not found in text, then splitLast returns ("", text).
func splitLast(text, split string) (string, string) {
	lastIndex := strings.LastIndex(text, split)
	if lastIndex < 0 {
		return "", text
	}

	return text[:lastIndex], text[lastIndex+len(split):]
}

// compactArrayPaths adjusts array indices in the given JSON paths, as if the corresponding JSON object has all
// unmentioned array elements removed. Input paths are in JSONPath syntax, while output paths are in dot-separated
// syntax, eg, `foo.1.bar.3`.
func compactArrayPaths(keys []string, src []byte) ([]*pathTransform, error) {
	paths, err := jsonpathkeys.ParsePaths(keys...)
	if err != nil {
		return nil, err
	}

	eval, err := jsonpathkeys.EvalPathsInReader(bytes.NewReader(src), paths)
	if err != nil {
		return nil, err
	}

	var jPaths []*pathTransform

	set := map[string]int{}

	for {
		result, ok := eval.Next()
		if !ok {
			break
		}

		jPaths = append(jPaths, getPath(result.Keys, set))
	}

	return jPaths, nil
}

func enhanceRevealDoc(explicitPaths map[string]bool, revealDoc, vcBytes []byte) ([]byte, error) {
	var err error

	revealDoc, err = sjson.SetBytes(revealDoc, "@explicit", true)
	if err != nil {
		return nil, err
	}

	intermPaths := make(map[string]bool)

	for path := range explicitPaths {
		revealDoc, err = enhanceRevealField(path, revealDoc, vcBytes)
		if err != nil {
			return nil, err
		}

		pathParts := strings.Split(path, ".")
		combinedPath := ""

		for i := range len(pathParts) - 1 {
			if i == 0 {
				combinedPath = pathParts[0]
			} else {
				combinedPath += "." + pathParts[i]
			}

			if _, ok := explicitPaths[combinedPath]; !ok {
				intermPaths[combinedPath] = false
			}
		}
	}

	for path := range intermPaths {
		revealDoc, err = enhanceRevealField(path, revealDoc, vcBytes)
		if err != nil {
			return nil, err
		}
	}

	return revealDoc, nil
}

func enhanceRevealField(path string, revealDoc, vcBytes []byte) ([]byte, error) {
	var err error

	revealDoc, err = sjson.SetBytes(revealDoc, path+".@explicit", true)
	if err != nil {
		return nil, err
	}

	for _, cf := range [...]string{"type", "@context"} {
		specialFieldPath := path + "." + cf

		specialFieldValue := gjson.GetBytes(vcBytes, specialFieldPath)
		if specialFieldValue.Type == gjson.Null {
			continue
		}

		revealDoc, err = sjson.SetBytes(revealDoc, specialFieldPath, specialFieldValue.Value())
		if err != nil {
			return nil, err
		}
	}

	return revealDoc, nil
}

func hasBBS(vc *verifiable.Credential) bool {
	return hasProofWithType(vc, "BbsBlsSignature2020")
}

func hasProofWithType(vc *verifiable.Credential, proofType string) bool {
	for _, proof := range vc.Proofs() {
		if proof["type"] == proofType {
			return true
		}
	}

	return false
}

func isSDJWTCredential(contents *verifiable.CredentialContents) bool {
	return contents.SDJWTHashAlg != nil
}

func supportsSelectiveDisclosure(credential *verifiable.Credential) bool {
	cc := credential.Contents()
	return isSDJWTCredential(&cc) || hasBBS(credential)
}

//nolint:gocyclo,nestif
func filterField(f *Field, credential map[string]interface{}, isJWTCredential bool) error {
	var schema gojsonschema.JSONLoader

	if f.Filter != nil {
		filter := *f.Filter
		if *filter.Type == "string" && filter.Format == "date-time" {
			if val, ok := filter.Minimum.(string); ok && val != "" {
				if t, err := time.Parse(time.RFC3339, val); err == nil {
					numFilterType := "number"
					filter.Type = &numFilterType
					filter.Format = ""
					filter.Minimum = t.Unix()
				}
			}
		}

		schema = gojsonschema.NewGoLoader(filter)
	}

	var lastErr error

	for _, path := range f.Path {
		err := checkPathValue(isJWTCredential, path, credential, f, schema)
		if err == nil { // if at least 1 path is valid, we are good
			return nil
		}

		lastErr = errors.Join(lastErr, checkPathValue(isJWTCredential, path, credential, f, schema))
	}

	return lastErr
}

// deprecated: convertToRFC9535Format converts path to RFC 9535 format.
func convertToRFC9535Format(path string) string {
	var builder strings.Builder

	segments := strings.Split(path, ".")

	for i, segment := range segments {
		if strings.Contains(segment, "-") && !strings.Contains(segment, "['") {
			builder.WriteString(fmt.Sprintf("['%s']", segment))
			continue
		}

		if i != 0 {
			builder.WriteString(".")
		}

		builder.WriteString(segment)
	}

	return builder.String()
}

//nolint:gocyclo,funlen
func checkPathValue(
	isJWTCredential bool,
	path string,
	credential map[string]any,
	field *Field,
	schema gojsonschema.JSONLoader,
) error {
	if isJWTCredential { // compatibility
		replacements := map[string]string{
			"$.vc.":   "$.",
			"$.vc[":   "$[",
			"$['vc']": "$",
		}

		for old, newVal := range replacements {
			path = strings.Replace(path, old, newVal, 1)
		}

		if strings.EqualFold(path, "$.issuer") {
			switch issuerFld := credential["issuer"].(type) {
			case map[string]interface{}:
				if _, ok := issuerFld["id"]; ok {
					path = "$.issuer.id"
				}
			}
		}
	}

	if !strings.HasPrefix(path, "$") && !strings.HasPrefix("@", path) {
		return errors.New("expected $ or @ at start of path")
	}

	var pathParsed *pathv2.Path

	var pathErr error

	for _, p := range []string{
		path,
		// nolint:lll
		convertToRFC9535Format(path), // Remove in 6months and update profiles presentations to use RFC 9535 format
	} {
		parsed, parseErr := pathv2.Parse(p)

		pathParsed = parsed

		if parseErr == nil {
			pathErr = nil
			break
		}

		pathErr = errors.Join(pathErr, fmt.Errorf("path %s: %w", p, parseErr))
	}

	if pathErr != nil {
		return pathErr
	}

	selected := pathParsed.Select(credential)
	if len(selected) == 0 {
		if field.Optional { // we are good
			return nil
		}

		return errors.Join(errPathNotApplicable, fmt.Errorf("no value found for path %s", path))
	}

	var raw any

	if len(selected) == 1 {
		raw = selected[0]
	} else {
		var arr []any
		for _, s := range selected {
			arr = append(arr, s)
		}

		raw = arr
	}

	return validatePath(schema, raw, field, isJWTCredential)
}

//nolint:gocyclo
func validatePath(schema gojsonschema.JSONLoader, patch interface{}, field *Field, isJWTCredential bool) error {
	if schema == nil {
		return nil
	}

	// convert date string to Unix timestamp for JWT credential
	if isJWTCredential && field.Path != nil && isDateField(field.Path) {
		if val, ok := patch.(string); ok {
			if t, err := time.Parse(time.RFC3339, val); err == nil {
				patch = t.Unix()
			}
		}
	}

	raw, err := json.Marshal(patch)
	if err != nil {
		return err
	}

	var schemasToExecute []gojsonschema.JSONLoader

	for _, all := range field.Filter.AllOf {
		schemasToExecute = append(schemasToExecute, gojsonschema.NewGoLoader(all))
	}

	if len(schemasToExecute) == 0 {
		schemasToExecute = append(schemasToExecute, schema) // fallback
	}

	for _, sh := range schemasToExecute {
		result, err := gojsonschema.Validate(sh, gojsonschema.NewBytesLoader(raw))
		if err != nil || !result.Valid() {
			return errors.Join(errPathNotApplicable)
		}
	}

	return nil
}

func isDateField(paths []string) bool {
	// date fields that are refined from JWT claims
	dateKeywords := []string{".expirationDate", ".issuanceDate", ".validFrom", ".validUntil"}
	for _, path := range paths {
		for _, keyword := range dateKeywords {
			if strings.Contains(path, keyword) {
				return true
			}
		}
	}

	return false
}

type pathTransform struct {
	newPath string
	oldPath string
}

func getPath(keys []interface{}, set map[string]int) *pathTransform {
	var (
		newPath      []string
		originalPath []string
	)

	for _, k := range keys {
		switch v := k.(type) {
		case int:
			counterKey := strings.Join(originalPath, ".")
			originalPath = append(originalPath, strconv.Itoa(v))
			mapperKey := strings.Join(originalPath, ".")

			if _, ok := set[mapperKey]; !ok {
				set[mapperKey] = set[counterKey]
				set[counterKey]++
			}

			newPath = append(newPath, strconv.Itoa(set[mapperKey]))
		default:
			originalPath = append(originalPath, fmt.Sprintf("%s", v))
			newPath = append(newPath, fmt.Sprintf("%s", v))
		}
	}

	return &pathTransform{newPath: strings.Join(newPath, "."), oldPath: strings.Join(originalPath, ".")}
}

//nolint:funlen
func merge(
	presentationFormat string,
	setOfCredentials map[string][]*credWrapper,
	separatePresentations bool,
) ([]*verifiable.Credential, []*InputDescriptorMapping) {
	setOfCreds := make(map[string]int)

	var (
		result      []*verifiable.Credential
		descriptors []*InputDescriptorMapping
	)

	keys := make([]string, 0, len(setOfCredentials))
	for k := range setOfCredentials {
		keys = append(keys, k)
	}

	var jwtVPPath string

	if presentationFormat == FormatJWTVP {
		jwtVPPath = ".vp"
	}

	sort.Strings(keys)

	for _, descriptorID := range keys {
		credentials := setOfCredentials[descriptorID]

		for _, credWrap := range credentials {
			credential := credWrap.vc

			if _, ok := setOfCreds[credWrap.uniqueID]; !ok {
				result = append(result, credential)

				setOfCreds[credWrap.uniqueID] = len(result) - 1
			}

			vcFormat := FormatLDPVC
			if credential.IsJWT() {
				vcFormat = FormatJWTVC
			}

			desc := &InputDescriptorMapping{
				ID:     descriptorID,
				Format: presentationFormat,
				PathNested: &InputDescriptorMapping{
					ID:     descriptorID,
					Format: vcFormat,
				},
			}

			if separatePresentations {
				desc.Path = fmt.Sprintf("$[%d]", setOfCreds[credWrap.uniqueID])
				desc.PathNested.Path = fmt.Sprintf("$%s.verifiableCredential[0]", jwtVPPath)
			} else {
				desc.Path = "$"
				desc.PathNested.Path = fmt.Sprintf("$%s.verifiableCredential[%d]", jwtVPPath, setOfCreds[credWrap.uniqueID])
			}

			descriptors = append(descriptors, desc)
		}
	}

	sort.Sort(byID(descriptors))

	return result, descriptors
}

type byID []*InputDescriptorMapping

func (a byID) Len() int           { return len(a) }
func (a byID) Less(i, j int) bool { return a[i].ID < a[j].ID }
func (a byID) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

//nolint:funlen,gocyclo
func filterFormat(format *Format, credentials []*verifiable.Credential) (string, []*verifiable.Credential) {
	var ldpCreds, ldpvcCreds, ldpvpCreds, jwtCreds, jwtvcCreds, jwtvpCreds []*verifiable.Credential

	for _, credential := range credentials {
		if credByProof(credential, format.Ldp) {
			ldpCreds = append(ldpCreds, credential)
		}

		if credByProof(credential, format.LdpVC) {
			ldpvcCreds = append(ldpvcCreds, credential)
		}

		if credByProof(credential, format.LdpVP) {
			ldpvpCreds = append(ldpvpCreds, credential)
		}

		var (
			alg    string
			hasAlg bool
		)

		if credential.IsJWT() {
			alg, hasAlg = credential.JWTHeaders().Algorithm()
		}

		if hasAlg && algMatch(alg, format.Jwt) {
			jwtCreds = append(jwtCreds, credential)
		}

		if hasAlg && algMatch(alg, format.JwtVC) {
			jwtvcCreds = append(jwtvcCreds, credential)
		}

		if hasAlg && algMatch(alg, format.JwtVP) {
			jwtvpCreds = append(jwtvpCreds, credential)
		}
	}

	if len(ldpCreds) > 0 {
		return FormatLDP, ldpCreds
	}

	if len(ldpvcCreds) > 0 {
		return FormatLDPVC, ldpvcCreds
	}

	if len(ldpvpCreds) > 0 {
		return FormatLDPVP, ldpvpCreds
	}

	if len(jwtCreds) > 0 {
		return FormatJWT, jwtCreds
	}

	if len(jwtvcCreds) > 0 {
		return FormatJWTVC, jwtvcCreds
	}

	if len(jwtvpCreds) > 0 {
		return FormatJWTVP, jwtvpCreds
	}

	return "", nil
}

func algMatch(credAlg string, jwtType *JwtType) bool {
	if jwtType == nil {
		return false
	}

	for _, b := range jwtType.Alg {
		if strings.EqualFold(credAlg, b) {
			return true
		}
	}

	return false
}

func credByProof(c *verifiable.Credential, ldp *LdpType) bool {
	if ldp == nil {
		return false
	}

	for _, proofType := range ldp.ProofType {
		if hasProofWithType(c, proofType) {
			return true
		}
	}

	return false
}

// nolint: gocyclo
func filterSchema(schemas []*Schema, credentials []*verifiable.Credential,
	documentLoader ld.DocumentLoader) ([]*verifiable.Credential, error) {
	var result []*verifiable.Credential

	contexts := map[string]*ld.Context{}

	for _, credential := range credentials {
		schemaSatisfied := map[string]struct{}{}
		credentialContents := credential.Contents()

		for _, ctx := range credentialContents.Context {
			ctxObj, ok := contexts[ctx]
			if !ok {
				context, err := getContext(ctx, documentLoader)
				if err != nil {
					return nil, fmt.Errorf("failed to load context '%s': %w", ctx, err)
				}

				contexts[ctx] = context
				ctxObj = context
			}

			for _, typ := range credentialContents.Types {
				ids, err := typeFoundInContext(typ, ctxObj)
				if err != nil {
					continue
				}

				for _, id := range ids {
					schemaSatisfied[id] = struct{}{}
				}
			}
		}

		var applicable bool

		for _, schema := range schemas {
			_, ok := schemaSatisfied[schema.URI]
			if ok {
				applicable = true
			} else if schema.Required {
				applicable = false
				break
			}
		}

		if applicable {
			result = append(result, credential)
		}
	}

	return result, nil
}

func typeFoundInContext(typ string, ctxObj *ld.Context) ([]string, error) {
	out := []string{typ}

	td := ctxObj.GetTermDefinition(typ)
	if td == nil {
		return nil, nil
	}

	id, ok := td["@id"].(string)
	if ok {
		out = append(out, id)
	}

	tdCtx, ok := td["@context"].(map[string]interface{})
	if !ok {
		return out, nil
	}

	extendedCtx, err := ctxObj.Parse(tdCtx)
	if err != nil {
		return nil, err
	}

	iri, err := extendedCtx.ExpandIri(id, false, false, nil, nil)
	if err != nil {
		return nil, err
	}

	out = append(out, iri)

	return out, nil
}

func getContext(contextURI string, documentLoader ld.DocumentLoader) (*ld.Context, error) {
	contextURI = strings.SplitN(contextURI, "#", 2)[0]

	remoteDoc, err := documentLoader.LoadDocument(contextURI)
	if err != nil {
		return nil, fmt.Errorf("loading document: %w", err)
	}

	doc, ok := remoteDoc.Document.(map[string]interface{})
	if !ok {
		return nil, errors.New("expects jsonld document to be unmarshaled into map[string]interface{}")
	}

	ctx, ok := doc["@context"]
	if !ok {
		return nil, fmt.Errorf("@context field not found in context %s", contextURI)
	}

	var opt *ld.JsonLdOptions
	if documentLoader != nil {
		opt = ld.NewJsonLdOptions("")
		opt.DocumentLoader = documentLoader
	}

	activeCtx, err := ld.NewContext(nil, opt).Parse(ctx)
	if err != nil {
		return nil, err
	}

	return activeCtx, nil
}

func getBaseContext(credentials []*verifiable.Credential) (string, error) {
	var baseContext string

	for _, cred := range credentials {
		baseCtx, err := verifiable.GetBaseContext(cred.Contents().Context)
		if err != nil {
			return "", err
		}

		if baseContext == "" {
			baseContext = baseCtx
		} else if baseContext != baseCtx {
			return "", errors.New("credentials have different base contexts")
		}
	}

	if baseContext == "" {
		return "", errors.New("base context is required")
	}

	return baseContext, nil
}
