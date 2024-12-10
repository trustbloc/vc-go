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
	contents := credential.Contents()
	if contents.Status == nil {
		return errors.New("vc missing status list field")
	}

	validator, err := c.ValidatorGetter(contents.Status.Type)
	if err != nil {
		return err
	}

	err = validator.ValidateStatus(contents.Status)
	if err != nil {
		return err
	}

	statusListIndex, err := validator.GetStatusListIndex(contents.Status)
	if err != nil {
		return err
	}

	statusVCURL, err := validator.GetStatusVCURI(contents.Status)
	if err != nil {
		return err
	}

	statusListVC, err := c.Resolver.Resolve(statusVCURL)
	if err != nil {
		return err
	}

	statusListVCC := statusListVC.Contents()
	if statusListVCC.Issuer == nil || contents.Issuer == nil || statusListVCC.Issuer.ID != contents.Issuer.ID {
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
		return errors.New(RevokedMessage)
	}

	return nil
}
