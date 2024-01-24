package cwt

import (
	"strings"

	"github.com/veraison/go-cose"

	"github.com/trustbloc/vc-go/proof/checker"
)

type cwtVerifier struct {
	proofChecker        ProofChecker
	expectedProofIssuer *string
}

func (v *cwtVerifier) Verify(
	proof *cose.Sign1Message,
	keyID string,
	algo cose.Algorithm,
) error {
	var expectedProofIssuer string

	if v.expectedProofIssuer != nil {
		expectedProofIssuer = *v.expectedProofIssuer
	} else {
		// if expectedProofIssuer not set, we get issuer DID from first part of key id.
		expectedProofIssuer = strings.Split(keyID, "#")[0]
	}

	return v.proofChecker.CheckCWTProof(checker.CheckCWTProofRequest{
		KeyID: keyID,
		Algo:  algo,
	}, proof, expectedProofIssuer)
}
