/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package status implements a Verifiable Credential Status API Client.
package status

import (
	"errors"
	"fmt"

	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vc-go/status/api"
	"github.com/trustbloc/vc-go/status/internal/bitstring"
)

const (
	// StatusPurposeRevocation is the purpose of the status list entry for revocation.
	StatusPurposeRevocation = "revocation"
	// StatusPurposeSuspension is the purpose of the status list entry for suspension.
	StatusPurposeSuspension = "suspension"
)

var (
	// ErrRevoked is the Client.VerifyStatus error when the given verifiable.Credential is revoked.
	ErrRevoked = errors.New("revoked")
	// ErrSuspended is the Client.VerifyStatus error when the given verifiable.Credential is suspended.
	ErrSuspended = errors.New("suspended")
)

// Client verifies revocation status for Verifiable Credentials.
type Client struct {
	ValidatorGetter api.ValidatorGetter
	Resolver        api.StatusListVCURIResolver
}

// VerifyStatus verifies the revocation status on the given Verifiable Credential, returning the errorstring:
// - "revoked" if the given credential's status is revoked
// - "suspended" if the given credential's status is suspended
// - nil if the credential is not revoked or suspended, and a different error if verification fails.
func (c *Client) VerifyStatus(credential *verifiable.Credential) error { //nolint:gocyclo
	contents := credential.Contents()
	if len(contents.Status) == 0 {
		return errors.New("vc missing status list field")
	}

	for _, status := range contents.Status {
		if err := c.verifyStatus(credential, status); err != nil {
			return err
		}
	}

	return nil
}

func (c *Client) verifyStatus( //nolint:gocyclo,funlen
	credential *verifiable.Credential,
	status *verifiable.TypedID,
) error {
	validator, err := c.ValidatorGetter(status.Type)
	if err != nil {
		return err
	}

	err = validator.ValidateStatus(status)
	if err != nil {
		return err
	}

	statusListIndex, err := validator.GetStatusListIndex(status)
	if err != nil {
		return err
	}

	statusVCURL, err := validator.GetStatusVCURI(status)
	if err != nil {
		return err
	}

	statusListVC, err := c.Resolver.Resolve(statusVCURL)
	if err != nil {
		return err
	}

	statusListVCC := statusListVC.Contents()
	if statusListVCC.Issuer == nil || credential.Contents().Issuer == nil ||
		statusListVCC.Issuer.ID != credential.Contents().Issuer.ID {
		return errors.New("issuer of the credential does not match status list vc issuer")
	}

	credSubject := statusListVCC.Subject

	encodedList, ok := credSubject[0].CustomFields["encodedList"].(string)
	if !ok {
		return errors.New("encodedList must be a string")
	}

	bitString, err := bitstring.Decode(encodedList)
	if err != nil {
		return fmt.Errorf("failed to decode bits: %w", err)
	}

	bitSet, err := bitstring.BitAt(bitString, statusListIndex)
	if err != nil {
		return err
	}

	if bitSet {
		purpose, err := validator.GetStatusPurpose(status)
		if err != nil {
			return err
		}

		switch purpose {
		case StatusPurposeRevocation:
			return ErrRevoked
		case StatusPurposeSuspension:
			return ErrSuspended
		default:
			return fmt.Errorf("unsupported status purpose: %s", purpose)
		}
	}

	return nil
}
