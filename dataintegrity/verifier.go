/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dataintegrity

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"

	"github.com/trustbloc/vc-go/dataintegrity/models"
	"github.com/trustbloc/vc-go/dataintegrity/suite"
)

const (
	proofPath = "proof"
)

// Verifier implements the CheckJWTProof Proof algorithm of the verifiable credential
// data integrity specification, using a set of provided cryptographic suites.
type Verifier struct {
	suites   map[string]suite.Verifier
	resolver didResolver
}

// NewVerifier initializes a Verifier that supports using the provided
// cryptographic suites to perform data integrity verification.
func NewVerifier(opts *Options, suites ...suite.VerifierInitializer) (*Verifier, error) {
	if opts == nil {
		opts = &Options{}
	}

	verifier := &Verifier{
		suites:   map[string]suite.Verifier{},
		resolver: opts.DIDResolver,
	}

	for _, initializer := range suites {
		for _, suiteType := range initializer.Type() {
			if _, ok := verifier.suites[suiteType]; ok {
				continue
			}

			verifierSuite, err := initializer.Verifier()
			if err != nil {
				return nil, err
			}

			verifier.suites[suiteType] = verifierSuite
		}
	}

	return verifier, nil
}

var (
	// ErrMissingProof is returned when Verifier.VerifyProof() is given a document
	// without a data integrity proof field.
	ErrMissingProof = errors.New("missing data integrity proof")
	// ErrMalformedProof is returned when Verifier.VerifyProof() is given a document
	// with a proof that isn't a JSON object or is missing necessary standard
	// fields.
	ErrMalformedProof = errors.New("malformed data integrity proof")
	// ErrWrongProofType is returned when Verifier.VerifyProof() is given a document
	// with a proof that isn't a Data Integrity proof.
	ErrWrongProofType = errors.New("proof provided is not a data integrity proof")
	// ErrMismatchedPurpose is returned when Verifier.VerifyProof() is given a
	// document with a proof whose Purpose does not match the expected purpose
	// provided in the proof options.
	ErrMismatchedPurpose = errors.New("data integrity proof does not match expected purpose")
	// ErrOutOfDate is returned when Verifier.VerifyProof() is given a document with
	// a proof that was created more than models.ProofOptions.MaxAge seconds ago.
	ErrOutOfDate = errors.New("data integrity proof out of date")
	// ErrInvalidDomain is returned when Verifier.VerifyProof() is given a document
	// with a proof without the expected domain.
	ErrInvalidDomain = errors.New("data integrity proof has invalid domain")
	// ErrInvalidChallenge is returned when Verifier.VerifyProof() is given a
	// document with a proof without the expected challenge.
	ErrInvalidChallenge = errors.New("data integrity proof has invalid challenge")
)

// VerifyProof verifies the data integrity proof on the given JSON document,
// returning an error if proof verification fails, and nil if verification
// succeeds.
func (v *Verifier) VerifyProof(doc []byte, opts *models.ProofOptions) error {
	proofRaw := gjson.GetBytes(doc, proofPath)

	if !proofRaw.Exists() {
		return ErrMissingProof
	}

	unsecuredDoc, err := sjson.DeleteBytes(doc, proofPath)
	if err != nil {
		return ErrMalformedProof
	}

	for _, proof := range proofRaw.Array() {
		if err = v.verifyProof([]byte(proof.Raw), unsecuredDoc, opts); err != nil {
			return err
		}
	}

	return nil
}

func (v *Verifier) verifyProof( // nolint:funlen,gocyclo
	proofRaw, unsecuredDoc []byte,
	opts *models.ProofOptions,
) error {
	proof := &models.Proof{}

	err := json.Unmarshal(proofRaw, proof)
	if err != nil {
		return ErrMalformedProof
	}

	if proof.Type == "" || proof.VerificationMethod == "" || proof.ProofPurpose == "" {
		return ErrMalformedProof
	}

	if proof.Type != models.DataIntegrityProof {
		return ErrWrongProofType
	}

	verifierSuite, ok := v.suites[proof.CryptoSuite]
	if !ok {
		return ErrUnsupportedSuite
	}

	if opts.SuiteType == "" {
		opts.SuiteType = proof.CryptoSuite
	}

	if verifierSuite.RequiresCreated() && proof.Created == "" {
		return ErrMalformedProof
	}

	if opts.Created.IsZero() && proof.Created != "" {
		var parsedCreatedTime time.Time

		parsedCreatedTime, err = time.Parse(models.DateTimeFormat, proof.Created)
		if err != nil {
			return ErrMalformedProof
		}

		opts.Created = parsedCreatedTime
	}

	if proof.Expires != "" {
		var parsedExpiresTime time.Time

		parsedExpiresTime, err = time.Parse(models.DateTimeFormat, proof.Expires)
		if err != nil {
			return ErrMalformedProof
		}

		if time.Now().After(parsedExpiresTime) {
			return ErrOutOfDate
		}

		opts.Expires = parsedExpiresTime
	}

	if proof.ProofPurpose != opts.Purpose {
		return ErrMismatchedPurpose
	}

	err = resolveVM(opts, v.resolver, proof.VerificationMethod)
	if err != nil {
		return err
	}

	verifyResult := verifierSuite.VerifyProof(unsecuredDoc, proof, opts)

	if opts.Domain != "" && opts.Domain != proof.Domain {
		return ErrInvalidDomain
	}

	if opts.Challenge != "" && opts.Challenge != proof.Challenge {
		return ErrInvalidChallenge
	}

	return verifyResult
}
