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
	exampleCWT = "d2844aa201260445616e794944a05848a4066a313730363730363932370a746b596362437876656c6531706e393459704b6a44016b746573742d636c69656e740376687474703a2f2f3132372e302e302e313a3630343133589ad2844aa201260445616e794944a05848a4066a313730363730363932370a746b596362437876656c6531706e393459704b6a44016b746573742d636c69656e740376687474703a2f2f3132372e302e302e313a363034313358409d890356a79ebb3d53be14e98e875a870b4e3af426e0a847fd94013a378eae6376cbacb115a3296ba67622cc50dcae8de94c752f63afc7b7782c7ad45380b424" //nolint:lll
)

func TestCreateProof(t *testing.T) {
	data := map[int]interface{}{
		1:  "test-client",
		3:  "http://127.0.0.1:60413",
		6:  "1706706927",
		10: "kYcbCxvele1pn94YpKjD",
	}

	encoded, err := cbor.Marshal(data)
	assert.NoError(t, err)

	msg := &cose.Sign1Message{
		Headers: cose.Headers{
			Protected: cose.ProtectedHeader{
				cose.HeaderLabelAlgorithm: cose.AlgorithmES256,
				cose.HeaderLabelKeyID:     []byte("anyID"),
			},
		},
		Payload: encoded,
	}

	signature, err := SignP256(encoded, msg.Headers)
	assert.NoError(t, err)

	msg.Signature = signature

	final, err := cbor.Marshal(msg)
	assert.NoError(t, err)

	hexVal := hex.EncodeToString(final)
	assert.NotEmpty(t, hexVal)
}

func TestParse(t *testing.T) {
	headers := cose.Headers{
		Protected: cose.ProtectedHeader{
			cose.HeaderLabelAlgorithm: cose.AlgorithmES256,
			cose.HeaderLabelKeyID:     []byte("anyID"),
		},
		Unprotected: cose.UnprotectedHeader{},
	}

	t.Run("success", func(t *testing.T) {
		input, decodeErr := hex.DecodeString(exampleCWT)
		assert.NoError(t, decodeErr)

		proofChecker := NewMockProofChecker(gomock.NewController(t))
		proofChecker.EXPECT().CheckCWTProof(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(request checker.CheckCWTProofRequest, expectedIssuer string, message, sign []byte) error {
				assert.Equal(t, "anyID", request.KeyID)
				assert.Equal(t, cose.AlgorithmES256, request.Algo)
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

		signature, err := SignP256(encoded, headers)
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

		signature, err := SignP256(encoded, headers)
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

		signature, err := SignP256(encoded, headers)
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
			"check cwt failure: COSE_Key header is required")
	})
}

func SignP256(data []byte, headers cose.Headers) ([]byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	signer, err := cose.NewSigner(cose.AlgorithmES256, privateKey)
	if err != nil {
		return nil, err
	}

	// create message header

	// sign and marshal message
	return cose.Sign1(rand.Reader, signer, headers, data, nil)
}
