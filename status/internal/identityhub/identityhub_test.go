/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package identityhub_test

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/did-go/doc/did"
	model "github.com/trustbloc/did-go/doc/did/endpoint"

	. "github.com/trustbloc/vc-go/status/internal/identityhub"
)

const (
	methodKey              = "method"
	objectIDKey            = "objectId"
	serviceTypeIdentityHub = "IdentityHub"
)

func TestResponse_CheckStatus(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		resp := &Response{
			Status: &Status{
				Code: http.StatusOK,
			},
			Replies: []MessageResult{
				{
					Status: Status{
						Code: http.StatusOK,
					},
				},
			},
		}

		require.NoError(t, resp.CheckStatus())
	})

	t.Run("response status error", func(t *testing.T) {
		errMsg := "foo bar error"

		resp := &Response{
			Status: &Status{
				Code:    http.StatusInternalServerError,
				Message: errMsg,
			},
			Replies: []MessageResult{
				{
					Status: Status{
						Code: http.StatusOK,
					},
				},
			},
		}

		err := resp.CheckStatus()
		require.Error(t, err)
		require.Contains(t, err.Error(), "unexpected request level status code")
		require.Contains(t, err.Error(), errMsg)
	})

	t.Run("message status error", func(t *testing.T) {
		errMsg := "foo bar error"

		resp := &Response{
			Status: &Status{
				Code: http.StatusOK,
			},
			Replies: []MessageResult{
				{
					Status: Status{
						Code:    http.StatusInternalServerError,
						Message: errMsg,
					},
				},
			},
		}

		err := resp.CheckStatus()
		require.Error(t, err)
		require.Contains(t, err.Error(), "unexpected message level status code")
		require.Contains(t, err.Error(), errMsg)
	})
}

func TestResponse_GetMessageData(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		objectID := "object-id-value"

		data := []byte("foo bar baz")

		resp := &Response{
			Replies: []MessageResult{
				{
					Status: Status{
						Code: http.StatusOK,
					},
				},
				{
					Status: Status{
						Code: http.StatusOK,
					},
					Entries: []Message{
						{
							Descriptor: map[string]interface{}{},
						},
						{
							Descriptor: map[string]interface{}{
								objectIDKey: "different ID",
							},
						},
						{
							Descriptor: map[string]interface{}{
								objectIDKey: objectID,
							},
							Data: base64.StdEncoding.EncodeToString(data),
						},
					},
				},
			},
		}

		result, err := resp.GetMessageData(objectID)
		require.NoError(t, err)
		require.Equal(t, data, result)
	})

	t.Run("expected object ID not found", func(t *testing.T) {
		resp := &Response{
			Replies: []MessageResult{
				{
					Status: Status{
						Code: http.StatusOK,
					},
				},
				{
					Status: Status{
						Code: http.StatusOK,
					},
					Entries: []Message{
						{
							Descriptor: map[string]interface{}{},
						},
						{
							Descriptor: map[string]interface{}{
								objectIDKey: "different ID",
							},
						},
					},
				},
			},
		}

		result, err := resp.GetMessageData("expected object ID")
		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "unable to get message by object ID from Response")
	})

	t.Run("message data is not base64 encoded", func(t *testing.T) {
		objectID := "object-id-value"

		resp := &Response{
			Replies: []MessageResult{
				{
					Status: Status{
						Code: http.StatusOK,
					},
					Entries: []Message{
						{
							Descriptor: map[string]interface{}{
								objectIDKey: objectID,
							},
							Data: "!!! not base 64 !!!",
						},
					},
				},
			},
		}

		result, err := resp.GetMessageData(objectID)
		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "unable to decode message bytes")
	})
}

func TestMessage_GetObjectID(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		expectID := "foo"

		msg := &Message{
			Descriptor: map[string]interface{}{
				objectIDKey: expectID,
			},
		}

		gotID, hasID := msg.GetObjectID()
		require.True(t, hasID)
		require.Equal(t, expectID, gotID)
	})

	t.Run("no id", func(t *testing.T) {
		id, hasID := Message{}.GetObjectID()
		require.False(t, hasID)
		require.Empty(t, id)
	})
}

func TestGetRequest(t *testing.T) {
	const (
		targetDID       = "did:foo:bar"
		messageMethod   = "custom-method"
		expectObjID     = "expected object id"
		customFieldName = "custom-field-name"
		customFieldVal  = "custom-field-val"
	)

	t.Run("success", func(t *testing.T) {
		objID, req, err := GetRequest(targetDID, messageMethod, []map[string]interface{}{
			{
				methodKey: "wrong-method",
			},
			{
				// missing object ID
				methodKey: messageMethod,
			},
			{
				objectIDKey:     expectObjID,
				methodKey:       messageMethod,
				customFieldName: customFieldVal,
			},
		})
		require.NoError(t, err)
		require.Equal(t, expectObjID, objID)
		require.NotNil(t, req)
		require.NotEmpty(t, req.RequestID)
		require.Equal(t, targetDID, req.Target)
		require.Len(t, req.Messages, 1)
		require.Equal(t, customFieldVal, req.Messages[0].Descriptor[customFieldName])
	})

	t.Run("no valid matching message found", func(t *testing.T) {
		_, _, err := GetRequest(targetDID, messageMethod, []map[string]interface{}{
			{
				objectIDKey: expectObjID,
				methodKey:   "wrong-method",
			},
			{
				// missing object ID
				methodKey: messageMethod,
			},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "objectId is not defined")
	})
}

func TestServiceEndpoint(t *testing.T) {
	const (
		endpointURL = "example.net/server/url/endpoint"
	)

	t.Run("success", func(t *testing.T) {
		testCases := []struct {
			name string
			svc  did.Service
		}{
			{
				name: "didcomm v1",
				svc: did.Service{
					Type:            serviceTypeIdentityHub,
					ServiceEndpoint: model.NewDIDCommV1Endpoint(endpointURL),
				},
			},
			{
				name: "didcomm v2",
				svc: did.Service{
					Type: serviceTypeIdentityHub,
					ServiceEndpoint: model.NewDIDCommV2Endpoint([]model.DIDCommV2Endpoint{
						{
							URI: endpointURL,
						},
					}),
				},
			},
			{
				name: "did core",
				svc: did.Service{
					Type:            serviceTypeIdentityHub,
					ServiceEndpoint: model.NewDIDCoreEndpoint([]string{endpointURL}),
				},
			},
			{
				name: "did core object",
				svc: did.Service{
					Type: serviceTypeIdentityHub,
					ServiceEndpoint: model.NewDIDCoreEndpoint(map[string]interface{}{
						"0": []string{endpointURL},
					}),
				},
			},
		}

		for _, testCase := range testCases {
			t.Run(testCase.name, func(t *testing.T) {
				doc := &did.Doc{
					Context: []string{did.ContextV1},
					Service: []did.Service{
						testCase.svc,
					},
				}

				endpoint, err := ServiceEndpoint(doc)
				require.NoError(t, err)
				require.Equal(t, endpointURL, endpoint)
			})
		}
	})

	t.Run("fail: no identity hub service in doc", func(t *testing.T) {
		_, err := ServiceEndpoint(&did.Doc{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "no identity hub service supplied")
	})

	t.Run("fail: did core service endpoint", func(t *testing.T) {
		testCases := []struct {
			name string
			svc  did.Service
			err  string
		}{
			{
				name: "no contents",
				svc: did.Service{
					Type:            serviceTypeIdentityHub,
					ServiceEndpoint: model.NewDIDCoreEndpoint(map[string]interface{}{}),
				},
				err: "unable to extract DIDCore service endpoint",
			},
			{
				name: "cannot marshal",
				svc: did.Service{
					Type:            serviceTypeIdentityHub,
					ServiceEndpoint: model.NewDIDCoreEndpoint(new(chan int)),
				},
				err: "unable to marshal DIDCore service endpoint",
			},
		}

		for _, testCase := range testCases {
			t.Run(testCase.name, func(t *testing.T) {
				doc := &did.Doc{
					Context: []string{did.ContextV1},
					Service: []did.Service{
						testCase.svc,
					},
				}

				_, err := ServiceEndpoint(doc)
				require.Error(t, err)
				require.Contains(t, err.Error(), testCase.err)
			})
		}
	})
}
