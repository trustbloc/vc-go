/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package status implements a Verifiable Credential Status API Client.
package status

import (
	"fmt"

	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vc-go/status/api"
	"github.com/trustbloc/vc-go/status/internal/bitstring"
)

const (
	// RevokedMessage is the Client.VerifyStatus error message when the given verifiable.Credential is revoked.
	RevokedMessage = "revoked"
)

// Client verifies revocation status for Verifiable Credentials.
type Client struct {
	ValidatorGetter api.ValidatorGetter
	Resolver        api.StatusListVCURIResolver
}

// VerifyStatus verifies the revocation status on the given Verifiable Credential, returning the errorstring "revoked"
// if the given credential's status is revoked, nil if the credential is not revoked, and a different error if
// verification fails.
func (c *Client) VerifyStatus(credential *verifiable.Credential) error { //nolint:gocyclo
	if credential.Status == nil {
		return fmt.Errorf("vc missing status list field")
	}

	validator, err := c.ValidatorGetter(credential.Status.Type)
	if err != nil {
		return err
	}

	err = validator.ValidateStatus(credential.Status)
	if err != nil {
		return err
	}

	statusListIndex, err := validator.GetStatusListIndex(credential.Status)
	if err != nil {
		return err
	}

	statusVCURL, err := validator.GetStatusVCURI(credential.Status)
	if err != nil {
		return err
	}

	statusListVC, err := c.Resolver.Resolve(statusVCURL)
	if err != nil {
		return err
	}

	if statusListVC.Issuer.ID != credential.Issuer.ID {
		return fmt.Errorf("issuer of the credential does not match status list vc issuer")
	}

	credSubject, ok := statusListVC.Subject.([]verifiable.Subject)
	if !ok {
		return fmt.Errorf("invalid subject field structure")
	}

	bitString, err := bitstring.Decode(credSubject[0].CustomFields["encodedList"].(string))
	if err != nil {
		return fmt.Errorf("failed to decode bits: %w", err)
	}

	bitSet, err := bitstring.BitAt(bitString, statusListIndex)
	if err != nil {
		return err
	}

	if bitSet {
		return fmt.Errorf(RevokedMessage)
	}

	return nil
}
