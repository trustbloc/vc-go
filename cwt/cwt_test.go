/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cwt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	_ "crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/veraison/go-cose"

	"github.com/trustbloc/vc-go/cwt"
	"github.com/trustbloc/vc-go/proof/checker"
)

const (
	exampleCWT = "d2845828a3012703746f70656e6964347663692d70726f6f662b63777468434f53455f4b657945616e794944a10445616e7949445842a4016b746573742d636c69656e740376687474703a2f2f3132372e302e302e313a3630343133061a65ba47ef0a746b596362437876656c6531706e393459704b6a44584009b11da68d72fc5e3fbf6aedd2c2dd81d99f69d93c5b063e7d714feae8b7b4e54b3d3780c1f7e43cc6a31405f3b67d81e1ca0a50423a8af34662022b70cd160c" //nolint:lll
)

func TestParse(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		input, decodeErr := hex.DecodeString(exampleCWT)
		assert.NoError(t, decodeErr)

		proofChecker := NewMockProofChecker(gomock.NewController(t))
		proofChecker.EXPECT().CheckCWTProof(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(request checker.CheckCWTProofRequest, expectedIssuer string, message, sign []byte) error {
				assert.Equal(t, "anyID", request.KeyID)
				assert.Equal(t, cose.AlgorithmEd25519, request.Algo)
				assert.NotNil(t, message)
				assert.Equal(t, "test-client", expectedIssuer)
				assert.NotNil(t, sign)
				assert.NotNil(t, message)

				return nil
			})

		resp, _, err := cwt.ParseAndCheckProof(input, proofChecker, true)
		assert.NoError(t, err)
		assert.NotNil(t, resp)
	})

	t.Run("invalid proof", func(t *testing.T) {
		input, decodeErr := hex.DecodeString(exampleCWT)
		assert.NoError(t, decodeErr)

		proofChecker := NewMockProofChecker(gomock.NewController(t))
		proofChecker.EXPECT().CheckCWTProof(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(request checker.CheckCWTProofRequest, expectedIssuer string, message []byte, sign []byte) error {
				return errors.New("invalid proof")
			})

		resp, _, err := cwt.ParseAndCheckProof(input, proofChecker, true)
		assert.ErrorContains(t, err, "invalid proof")
		assert.Nil(t, resp)
	})

	t.Run("invalid cwt", func(t *testing.T) {
		resp, _, err := cwt.ParseAndCheckProof([]byte(exampleCWT), nil, true)
		assert.ErrorContains(t, err, "invalid COSE_Sign1_Tagged object")
		assert.Nil(t, resp)
	})

	t.Run("missing issuer", func(t *testing.T) {
		data := map[int]interface{}{
			100500: "1234567890",
		}

		encoded, err := cbor.Marshal(data)
		assert.NoError(t, err)

		signature, err := SignP256(encoded)
		assert.NoError(t, err)

		resp, _, err := cwt.ParseAndCheckProof(signature, nil, true)
		assert.ErrorContains(t, err, "check cwt failure: iss claim is required")
		assert.Nil(t, resp)
	})

	t.Run("issuer invalid type", func(t *testing.T) {
		data := map[int]interface{}{
			1: 100500,
		}

		encoded, err := cbor.Marshal(data)
		assert.NoError(t, err)

		signature, err := SignP256(encoded)
		assert.NoError(t, err)

		resp, _, err := cwt.ParseAndCheckProof(signature, nil, true)
		assert.ErrorContains(t, err, "check cwt failure: iss claim is not a string")
		assert.Nil(t, resp)
	})

	t.Run("invalid data type", func(t *testing.T) {
		data := map[string]interface{}{
			"100500": "1234567890",
		}

		encoded, err := cbor.Marshal(data)
		assert.NoError(t, err)

		signature, err := SignP256(encoded)
		assert.NoError(t, err)

		resp, _, err := cwt.ParseAndCheckProof(signature, nil, true)
		assert.ErrorContains(t, err, "cbor: cannot unmarshal UTF-8 text string into Go value of type int")
		assert.Nil(t, resp)
	})

	t.Run("no algo", func(t *testing.T) {
		assert.ErrorContains(t, cwt.CheckProof(&cose.Sign1Message{}, nil, nil, nil, nil),
			"algorithm not found")
	})

	t.Run("no key", func(t *testing.T) {
		assert.ErrorContains(t, cwt.CheckProof(&cose.Sign1Message{
			Headers: cose.Headers{
				Protected: cose.ProtectedHeader{
					cose.HeaderLabelAlgorithm: cose.AlgorithmES256,
				},
			},
		}, nil, nil, nil, nil),
			"check cwt failure: kid header is required")
	})
}

func SignP256(data []byte) ([]byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	signer, err := cose.NewSigner(cose.AlgorithmES256, privateKey)
	if err != nil {
		return nil, err
	}

	// create message header
	headers := cose.Headers{
		Protected: cose.ProtectedHeader{
			cose.HeaderLabelAlgorithm: cose.AlgorithmES256,
		},
	}

	// sign and marshal message
	return cose.Sign1(rand.Reader, signer, headers, data, nil)
}
