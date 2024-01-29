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
	exampleCWT = "d28443a10126a104524173796d6d657472696345434453413235365850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b7158405427c1ff28d23fbad1f29c4c7c6a555e601d6fa29f9179bc3d7438bacaca5acd08c8d4d4f96131680c429a01f85951ecee743a52b9b63632c57209120e1c9e30" //nolint:lll
)

func TestParse(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		input, decodeErr := hex.DecodeString(exampleCWT)
		assert.NoError(t, decodeErr)

		proofChecker := NewMockProofChecker(gomock.NewController(t))
		proofChecker.EXPECT().CheckCWTProof(gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(request checker.CheckCWTProofRequest, message *cose.Sign1Message, expectedIssuer string) error {
				assert.Equal(t, "AsymmetricECDSA256", request.KeyID)
				assert.Equal(t, cose.AlgorithmES256, request.Algo)
				assert.NotNil(t, message)
				assert.Equal(t, "coap://as.example.com", expectedIssuer)
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
		proofChecker.EXPECT().CheckCWTProof(gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(request checker.CheckCWTProofRequest, message *cose.Sign1Message, expectedIssuer string) error {
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
		assert.ErrorContains(t, cwt.CheckProof(&cose.Sign1Message{}, nil, nil),
			"algorithm not found")
	})

	t.Run("no key", func(t *testing.T) {
		assert.ErrorContains(t, cwt.CheckProof(&cose.Sign1Message{
			Headers: cose.Headers{
				Protected: cose.ProtectedHeader{
					cose.HeaderLabelAlgorithm: cose.AlgorithmES256,
				},
			},
		}, nil, nil),
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
