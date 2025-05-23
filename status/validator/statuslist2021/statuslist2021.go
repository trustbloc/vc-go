/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package statuslist2021 handles client-side validation and parsing for
// Credential Status fields of type StatusList2021Type, as per spec: https://w3c-ccg.github.io/vc-status-list-2021/
package statuslist2021

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/trustbloc/vc-go/verifiable"
)

const (
	// StatusList2021Type represents the implementation of VC Status List 2021.
	//  VC.Status.Type
	// 	Doc: https://w3c-ccg.github.io/vc-status-list-2021/
	StatusList2021Type = "StatusList2021Entry"

	// StatusListCredential stores the link to the status list VC.
	//  VC.Status.CustomFields key.
	StatusListCredential = "statusListCredential"

	// StatusListIndex identifies the bit position of the status value of the VC.
	//  VC.Status.CustomFields key.
	StatusListIndex = "statusListIndex"

	// StatusPurpose for StatusList2021.
	//  VC.Status.CustomFields key. Only "revocation" value is supported.
	StatusPurpose = "statusPurpose"
)

// Validator validates a Verifiable Credential's Status field against the VC Status List 2021 specification, and
// returns fields for status verification.
//
// Implements spec: https://w3c.github.io/vc-status-list-2021/#statuslist2021entry
type Validator struct{}

// ValidateStatus validates that a Verifiable Credential's Status field matches the VC Status List 2021 specification.
func (v *Validator) ValidateStatus(vcStatus *verifiable.TypedID) error {
	if vcStatus == nil {
		return errors.New("vc status does not exist")
	}

	if vcStatus.Type != StatusList2021Type {
		return fmt.Errorf("vc status %s not supported", vcStatus.Type)
	}

	for _, field := range []string{StatusListCredential, StatusListIndex, StatusPurpose} {
		if err := isMissingField(vcStatus, field); err != nil {
			return err
		}
	}

	return nil
}

func isMissingField(vcStatus *verifiable.TypedID, field string) error {
	if vcStatus.CustomFields[field] == nil {
		return fmt.Errorf("%s field does not exist in vc status", field)
	}

	return nil
}

// GetStatusVCURI returns the ID (URL) of status VC.
func (v *Validator) GetStatusVCURI(vcStatus *verifiable.TypedID) (string, error) {
	statusListVC, ok := vcStatus.CustomFields[StatusListCredential].(string)
	if !ok {
		return "", errors.New("failed to cast URI of statusListCredential")
	}

	return statusListVC, nil
}

// GetStatusListIndex returns the bit position of the status value of the VC.
func (v *Validator) GetStatusListIndex(vcStatus *verifiable.TypedID) (int, error) {
	statusListIndex, ok := vcStatus.CustomFields[StatusListIndex].(string)
	if !ok {
		return -1, fmt.Errorf("%s must be a string", StatusListIndex)
	}

	idx, err := strconv.Atoi(statusListIndex)
	if err != nil {
		return -1, fmt.Errorf("unable to get statusListIndex: %w", err)
	}

	return idx, nil
}

// GetStatusPurpose returns the purpose of the status list. For example, "revocation", "suspension".
func (v *Validator) GetStatusPurpose(vcStatus *verifiable.TypedID) (string, error) {
	statusPurpose, ok := vcStatus.CustomFields[StatusPurpose].(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string", StatusPurpose)
	}

	return statusPurpose, nil
}

// MultiBaseEncoding indicates that status uses MultiBase encoding.
func (v *Validator) MultiBaseEncoding() bool {
	return false
}
