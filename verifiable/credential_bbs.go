/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"errors"
	"fmt"

	jsonutil "github.com/trustbloc/vc-go/util/json"
)

// GenerateBBSSelectiveDisclosure generate BBS+ selective disclosure from one BBS+ signature.
func (vc *Credential) GenerateBBSSelectiveDisclosure(revealDoc map[string]interface{},
	nonce []byte, bbsProofCreator *BBSProofCreator, opts ...CredentialOpt) (*Credential, error) {
	if len(vc.ldProofs) == 0 {
		return nil, errors.New("expected at least one proof present")
	}

	vcOpts := getCredentialOpts(opts)
	jsonldProcessorOpts := mapJSONLDProcessorOpts(&vcOpts.jsonldCredentialOpts)

	if bbsProofCreator == nil {
		return nil, errors.New("bbs proof creator not defined")
	}

	vcDoc, err := jsonutil.ToMap(vc)
	if err != nil {
		return nil, err
	}

	vcWithSelectiveDisclosureDoc, err := BBSSelectiveDisclosure(vcDoc, revealDoc, nonce,
		bbsProofCreator, jsonldProcessorOpts...)
	if err != nil {
		return nil, fmt.Errorf("create VC selective disclosure: %w", err)
	}

	vcWithSelectiveDisclosureBytes, err := json.Marshal(vcWithSelectiveDisclosureDoc)
	if err != nil {
		return nil, err
	}

	opts = append(opts, WithDisabledProofCheck())

	return ParseCredential(vcWithSelectiveDisclosureBytes, opts...)
}
