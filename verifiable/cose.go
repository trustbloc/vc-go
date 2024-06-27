/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"

	"github.com/trustbloc/vc-go/cwt"
	cwt2 "github.com/trustbloc/vc-go/verifiable/cwt"
)

const (
	HeaderLabelTyp = 16
)

// MarshalJWS serializes JWT presentation claims into signed form (JWS).
func marshalCOSE(
	claims *CWTCredClaims,
	signatureAlg cose.Algorithm,
	signer cwt.ProofCreator,
	keyID string,
) ([]byte, error) {
	payload, err := cbor.Marshal(claims)
	if err != nil {
		return nil, err
	}

	msg := &cose.Sign1Message{
		Headers: cose.Headers{
			Protected: cose.ProtectedHeader{
				cose.HeaderLabelAlgorithm: signatureAlg,
				cose.HeaderLabelKeyID:     []byte(keyID),
			},
			Unprotected: cose.UnprotectedHeader{
				HeaderLabelTyp: "application/vc+ld+json+cose",
			},
		},
		Payload: payload,
	}

	signData, err := cwt2.GetProofValue(msg)
	if err != nil {
		return nil, err
	}

	signed, err := signer.SignCWT(cwt.SignParameters{
		KeyID:  keyID,
		CWTAlg: signatureAlg,
	}, signData)
	if err != nil {
		return nil, err
	}

	msg.Signature = signed

	final, err := cbor.Marshal(msg)
	if err != nil {
		return nil, err
	}

	return final, nil
}
