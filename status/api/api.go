/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package api contains dependency-injection interfaces for Credential Status validation clients.
package api

import (
	"github.com/trustbloc/vc-go/verifiable"
)

// Validator holds handlers for validating a particular format of Status(Revocation) List VC.
type Validator interface {
	ValidateStatus(vcStatus *verifiable.TypedID) error
	GetStatusVCURI(vcStatus *verifiable.TypedID) (string, error)
	GetStatusListIndex(vcStatus *verifiable.TypedID) (int, error)
	GetStatusPurpose(vcStatus *verifiable.TypedID) (string, error)
}

// ValidatorGetter provides the matching Validator for a given credential status type.
type ValidatorGetter func(statusType string) (Validator, error)

// StatusListVCURIResolver resolves a VC StatusList Credential.
type StatusListVCURIResolver interface {
	Resolve(statusListVCURL string) (*verifiable.Credential, error)
}
