/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package bitstringstatus handles client-side validation and parsing for
// Credential Status fields of type BitstringStatusList, as per spec: https://www.w3.org/TR/vc-bitstring-status-list/
package bitstringstatus

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/trustbloc/vc-go/verifiable"
)

const (
	// BitstringStatusList2021Type represents the implementation of Bitstring Status List.
	//  VC.Status.Type
	// 	Doc: https://www.w3.org/TR/vc-bitstring-status-list/#bitstringstatuslistentry
	BitstringStatusList2021Type = "BitstringStatusListEntry"

	// StatusListCredential stores the link to the status list VC.
	//  VC.Status.CustomFields key.
	StatusListCredential = "statusListCredential"

	// StatusListIndex identifies the bit position of the status value of the VC.
	//  VC.Status.CustomFields key.
	StatusListIndex = "statusListIndex"

	// StatusPurpose for BitstringStatusList.
	//  VC.Status.CustomFields key. Only "revocation" value is supported.
	// TODO: check if it's really only 'revocation'. Spec allows: refresh, revocation, suspension, message.
	StatusPurpose = "statusPurpose"
	// StatusSize indicates the size of the status entry in bits.
	StatusSize = "statusSize"
	// StatusMessage represents custom descriptive messages about the status of the verifiable credential.
	StatusMessage = "statusMessage"
)

// Validator validates a Verifiable Credential's Status field against the BitstringStatusList specification, and
// returns fields for status verification.
//
// Implements spec: https://www.w3.org/TR/vc-bitstring-status-list/#bitstringstatuslistentry
type Validator struct{}

// ValidateStatus validates that a Verifiable Credential's Status field matches the BitstringStatusList specification.
func (v *Validator) ValidateStatus(vcStatus *verifiable.TypedID) error {
	if vcStatus == nil {
		return errors.New("vc status does not exist")
	}

	if vcStatus.Type != BitstringStatusList2021Type {
		return fmt.Errorf("vc status %s not supported", vcStatus.Type)
	}

	for _, field := range []string{StatusListCredential, StatusListIndex, StatusPurpose} {
		if err := isMissingField(vcStatus, field); err != nil {
			return err
		}
	}

	err := checkStatusSize(vcStatus)
	if err != nil {
		return err
	}

	return nil
}

func isMissingField(vcStatus *verifiable.TypedID, field string) error {
	if vcStatus.CustomFields[field] == nil {
		return fmt.Errorf("%s field does not exist in vc status", field)
	}

	return nil
}

func checkStatusSize(vcStatus *verifiable.TypedID) error {
	statusSizeRaw := vcStatus.CustomFields[StatusSize]
	if statusSizeRaw == nil {
		return nil
	}

	statusSizeF, ok := statusSizeRaw.(float64)
	if !ok {
		return errors.New("statusSize must be an integer")
	}

	statusSize := int(statusSizeF)

	if statusSize <= 0 {
		return fmt.Errorf("statusSize must be greater than 0, but got %d", statusSize)
	}

	if statusSize == 1 {
		return nil
	}

	possibleStatusSizes := 1<<statusSize - 1

	statusMessages, ok := vcStatus.CustomFields[StatusMessage].([]any)
	if !ok {
		return fmt.Errorf("%s must be an array", StatusMessage)
	}

	if len(statusMessages) != possibleStatusSizes {
		return fmt.Errorf("the length of %s must be equal to %d", StatusMessage, possibleStatusSizes)
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
// See https://www.w3.org/TR/cid-1.0/#multibase-0 for more details.
func (v *Validator) MultiBaseEncoding() bool {
	return true
}
