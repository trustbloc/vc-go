/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"errors"
	"fmt"

	jsonld "github.com/trustbloc/did-go/doc/ld/processor"

	"github.com/trustbloc/vc-go/dataintegrity/models"
	"github.com/trustbloc/vc-go/verifiable/lddocument"
)

const (
	ed25519Signature2018        = "Ed25519Signature2018"
	ed25519Signature2020        = "Ed25519Signature2020"
	jsonWebSignature2020        = "JsonWebSignature2020"
	ecdsaSecp256k1Signature2019 = "EcdsaSecp256k1Signature2019"
	bbsBlsSignature2020         = "BbsBlsSignature2020"
	bbsBlsSignatureProof2020    = "BbsBlsSignatureProof2020"
)

type embeddedProofCheckOpts struct {
	proofChecker       lddocument.ProofChecker
	disabledProofCheck bool

	dataIntegrityOpts *verifyDataIntegrityOpts

	jsonldCredentialOpts
}

func checkEmbeddedProofBytes(docBytes []byte, opts *embeddedProofCheckOpts) error { // nolint:gocyclo
	if opts.disabledProofCheck {
		return nil
	}

	var jsonldDoc map[string]interface{}

	if err := json.Unmarshal(docBytes, &jsonldDoc); err != nil {
		return fmt.Errorf("embedded proof is not JSON: %w", err)
	}

	delete(jsonldDoc, "jwt")

	return checkEmbeddedProof(jsonldDoc, opts)
}

func checkEmbeddedProof(jsonldDoc map[string]interface{}, opts *embeddedProofCheckOpts) error { // nolint:gocyclo
	proofElement, ok := jsonldDoc["proof"]
	if !ok || proofElement == nil {
		return fmt.Errorf("check embedded proof: proof is missed")
	}

	proofs, err := getProofs(proofElement)
	if err != nil {
		return fmt.Errorf("check embedded proof: %w", err)
	}

	if len(opts.externalContext) > 0 {
		// Use external contexts for check of the linked data proofs to enrich JSON-LD context vocabulary.
		jsonldDoc["@context"] = jsonld.AppendExternalContexts(jsonldDoc["@context"], opts.externalContext...)
	}

	if len(proofs) > 0 {
		typeStr, ok := proofs[0]["type"]
		if ok && typeStr == models.DataIntegrityProof {
			var docBytes []byte

			docBytes, err = json.Marshal(jsonldDoc)
			if err != nil {
				return err
			}

			return checkDataIntegrityProof(docBytes, opts.dataIntegrityOpts)
		}
	}

	if opts.proofChecker == nil {
		return errors.New("proofChecker is not defined")
	}

	err = checkLinkedDataProof(jsonldDoc, opts.proofChecker, &opts.jsonldCredentialOpts)
	if err != nil {
		return fmt.Errorf("check embedded proof: %w", err)
	}

	return nil
}

func getProofs(proofElement interface{}) ([]map[string]interface{}, error) {
	switch p := proofElement.(type) {
	case map[string]interface{}:
		return []map[string]interface{}{p}, nil

	case []interface{}:
		proofs := make([]map[string]interface{}, len(p))

		for i := range p {
			proofMap, ok := p[i].(map[string]interface{})
			if !ok {
				return nil, errors.New("invalid proof type")
			}

			proofs[i] = proofMap
		}

		return proofs, nil
	}

	return nil, errors.New("invalid proof type")
}
