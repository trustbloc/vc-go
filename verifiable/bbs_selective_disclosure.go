/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/trustbloc/did-go/doc/ld/processor"
	"github.com/trustbloc/did-go/doc/ld/proof"

	"github.com/trustbloc/vc-go/proof/ldproofs/bbsblssignatureproof2020"
	"github.com/trustbloc/vc-go/vermethod"
)

const (
	securityContext     = "https://w3id.org/security/v2"
	bbsBlsSignature2020 = "BbsBlsSignature2020"
)

type bbsProofDerivation interface {
	DeriveProof(messages [][]byte, sigBytes, nonce, pubKeyBytes []byte,
		revealedIndexes []int) ([]byte, error)
}

type verificationMethodResolver interface {
	ResolveVerificationMethod(
		verificationMethod string,
		expectedKeyController string,
	) (*vermethod.VerificationMethod, error)
}

// BBSProofCreator used to create bbs proof during selective disclosure.
type BBSProofCreator struct {
	ProofDerivation            bbsProofDerivation
	VerificationMethodResolver verificationMethodResolver
}

// BBSSelectiveDisclosure creates selective disclosure from the input doc which must have a BBS+ proof
// (with BbsBlsSignature2020 type).
func BBSSelectiveDisclosure(doc map[string]interface{}, revealDoc map[string]interface{},
	nonce []byte, bbsProofCreator *BBSProofCreator, opts ...processor.Opts) (map[string]interface{}, error) {
	docWithoutProof, rawProofs, err := prepareDocAndProof(doc, opts...)
	if err != nil {
		return nil, fmt.Errorf("preparing doc failed: %w", err)
	}

	blsSignatures, err := getBlsProofs(rawProofs)
	if err != nil {
		return nil, fmt.Errorf("get BLS proofs: %w", err)
	}

	if len(blsSignatures) == 0 {
		return nil, errors.New("no BbsBlsSignature2020 proof present")
	}

	docVerData, pErr := buildDocVerificationData(docWithoutProof, revealDoc, opts...)
	if pErr != nil {
		return nil, fmt.Errorf("build document verification data: %w", pErr)
	}

	proofs := make([]map[string]interface{}, len(blsSignatures))

	for i, blsSignature := range blsSignatures {
		verData, dErr := buildVerificationData(blsSignature, docVerData, opts...)
		if dErr != nil {
			return nil, fmt.Errorf("build verification data: %w", dErr)
		}

		derivedProof, dErr := generateSignatureProof(blsSignature, bbsProofCreator, nonce, verData)
		if dErr != nil {
			return nil, fmt.Errorf("generate signature proof: %w", dErr)
		}

		proofs[i] = derivedProof
	}

	revealDocumentResult := docVerData.revealDocumentResult
	revealDocumentResult["proof"] = proofs

	return revealDocumentResult, nil
}

func prepareDocAndProof(doc map[string]interface{},
	opts ...processor.Opts) (map[string]interface{}, interface{}, error) {
	docCompacted, err := getCompactedWithSecuritySchema(doc, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("compact doc with security schema: %w", err)
	}

	rawProofs := docCompacted["proof"]
	if rawProofs == nil {
		return nil, nil, errors.New("document does not have a proof")
	}

	delete(docCompacted, "proof")

	return docCompacted, rawProofs, nil
}

func generateSignatureProof(blsSignature map[string]interface{}, creator *BBSProofCreator, nonce []byte,
	verData *verificationData) (map[string]interface{}, error) {
	pubKeyBytes, signatureBytes, pErr := getPublicKeyAndSignature(blsSignature, creator.VerificationMethodResolver)
	if pErr != nil {
		return nil, fmt.Errorf("get public key and signature: %w", pErr)
	}

	signatureProofBytes, err := creator.ProofDerivation.DeriveProof(verData.blsMessages, signatureBytes,
		nonce, pubKeyBytes, verData.revealIndexes)
	if err != nil {
		return nil, fmt.Errorf("derive BBS+ proof: %w", err)
	}

	derivedProof := map[string]interface{}{
		"type":               bbsblssignatureproof2020.ProofType,
		"nonce":              base64.StdEncoding.EncodeToString(nonce),
		"verificationMethod": blsSignature["verificationMethod"],
		"proofPurpose":       blsSignature["proofPurpose"],
		"created":            blsSignature["created"],
		"proofValue":         base64.StdEncoding.EncodeToString(signatureProofBytes),
	}

	return derivedProof, nil
}

func getPublicKeyAndSignature(blsSignatureMap map[string]interface{},
	resolver verificationMethodResolver) ([]byte, []byte, error) {
	blsSignature, err := proof.NewProof(blsSignatureMap)
	if err != nil {
		return nil, nil, fmt.Errorf("parse BBS+ signature: %w", err)
	}

	publicKeyID, err := blsSignature.PublicKeyID()
	if err != nil {
		return nil, nil, fmt.Errorf("get public KID from BBS+ signature: %w", err)
	}

	vm, err := resolver.ResolveVerificationMethod(publicKeyID, strings.Split(publicKeyID, "#")[0])
	if err != nil {
		return nil, nil, fmt.Errorf("resolve public key of BBS+ signature: %w", err)
	}

	return vm.Value, blsSignature.ProofValue, nil
}

func getBlsProofs(rawProofs interface{}) ([]map[string]interface{}, error) {
	allProofs, err := getProofs(rawProofs)
	if err != nil {
		return nil, fmt.Errorf("read document proofs: %w", err)
	}

	blsProofs := make([]map[string]interface{}, 0)

	for _, p := range allProofs {
		proofType, ok := p["type"].(string)
		if ok && strings.HasSuffix(proofType, bbsBlsSignature2020) {
			p["@context"] = securityContext
			blsProofs = append(blsProofs, p)
		}
	}

	return blsProofs, nil
}

type docVerificationData struct {
	revealIndexes        []int
	revealDocumentResult map[string]interface{}
	documentStatements   []string
}

type verificationData struct {
	blsMessages   [][]byte
	revealIndexes []int
}

func buildVerificationData(blsProof map[string]interface{}, docVerData *docVerificationData,
	opts ...processor.Opts) (*verificationData, error) {
	proofStatements, err := createVerifyProofData(blsProof, opts...)
	if err != nil {
		return nil, fmt.Errorf("create verify proof data: %w", err)
	}

	numberOfProofStatements := len(proofStatements)
	revealIndexes := make([]int, numberOfProofStatements+len(docVerData.revealIndexes))

	for i := range numberOfProofStatements {
		revealIndexes[i] = i
	}

	for i := range docVerData.revealIndexes {
		revealIndexes[i+numberOfProofStatements] = numberOfProofStatements + docVerData.revealIndexes[i]
	}

	allInputStatements := append(proofStatements, docVerData.documentStatements...)
	blsMessages := toArrayOfBytes(allInputStatements)

	return &verificationData{
		blsMessages:   blsMessages,
		revealIndexes: revealIndexes,
	}, nil
}

func buildDocVerificationData(docCompacted, revealDoc map[string]interface{},
	opts ...processor.Opts) (*docVerificationData, error) {
	documentStatements, transformedStatements, err := createVerifyDocumentData(docCompacted, opts...)
	if err != nil {
		return nil, fmt.Errorf("create verify document data: %w", err)
	}

	optionsWithBlankFrames := append(opts, processor.WithFrameBlankNodes())

	revealDocumentResult, err := processor.Default().Frame(docCompacted, revealDoc, optionsWithBlankFrames...)
	if err != nil {
		return nil, fmt.Errorf("frame doc with reveal doc: %w", err)
	}

	revealDocumentStatements, err := createVerifyRevealData(revealDocumentResult, opts...)
	if err != nil {
		return nil, fmt.Errorf("create verify reveal document data: %w", err)
	}

	revealIndexes := make([]int, len(revealDocumentStatements))

	documentStatementsMap := make(map[string]int)
	for i, statement := range transformedStatements {
		documentStatementsMap[statement] = i
	}

	for i := range revealDocumentStatements {
		statement := revealDocumentStatements[i]
		statementInd := documentStatementsMap[statement]
		revealIndexes[i] = statementInd
	}

	return &docVerificationData{
		documentStatements:   documentStatements,
		revealIndexes:        revealIndexes,
		revealDocumentResult: revealDocumentResult,
	}, nil
}

func getCompactedWithSecuritySchema(docMap map[string]interface{},
	opts ...processor.Opts) (map[string]interface{}, error) {
	contextMap := map[string]interface{}{
		"@context": securityContext,
	}

	return processor.Default().Compact(docMap, contextMap, opts...)
}

func createVerifyDocumentData(doc map[string]interface{},
	opts ...processor.Opts) ([]string, []string, error) {
	docBytes, err := processor.Default().GetCanonicalDocument(doc, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("canonicalizing document failed: %w", err)
	}

	documentStatements := splitMessageIntoLines(string(docBytes))
	transformedStatements := make([]string, len(documentStatements))

	for i, row := range documentStatements {
		transformedStatements[i] = processor.TransformBlankNode(row)
	}

	return documentStatements, transformedStatements, nil
}

func createVerifyRevealData(doc map[string]interface{}, opts ...processor.Opts) ([]string, error) {
	docBytes, err := processor.Default().GetCanonicalDocument(doc, opts...)
	if err != nil {
		return nil, err
	}

	return splitMessageIntoLines(string(docBytes)), nil
}

func splitMessageIntoLines(msg string) []string {
	rows := strings.Split(msg, "\n")

	msgs := make([]string, 0, len(rows))

	for i := range rows {
		if strings.TrimSpace(rows[i]) != "" {
			msgs = append(msgs, rows[i])
		}
	}

	return msgs
}

func createVerifyProofData(proofMap map[string]interface{}, opts ...processor.Opts) ([]string, error) {
	proofMapCopy := make(map[string]interface{}, len(proofMap)-1)

	for k, v := range proofMap {
		if k != "proofValue" {
			proofMapCopy[k] = v
		}
	}

	proofBytes, err := processor.Default().GetCanonicalDocument(proofMapCopy, opts...)
	if err != nil {
		return nil, err
	}

	return splitMessageIntoLines(string(proofBytes)), nil
}

func toArrayOfBytes(messages []string) [][]byte {
	res := make([][]byte, len(messages))

	for i := range messages {
		res[i] = []byte(messages[i])
	}

	return res
}
