/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resolver_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	mockvdr "github.com/trustbloc/did-go/vdr/mock"

	"github.com/trustbloc/vc-go/did"
	model "github.com/trustbloc/vc-go/did/endpoint"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vc-go/status/internal/identityhub"

	. "github.com/trustbloc/vc-go/status/resolver"
)

const (
	methodCollectionsQuery = "CollectionsQuery"
	methodKey              = "method"
	objectIDKey            = "objectId"
	serviceTypeIdentityHub = "IdentityHub"
)

func TestResolve(t *testing.T) { //nolint:maintidx
	srcVC := &verifiable.Credential{
		Context:      []string{verifiable.ContextURI},
		Types:        []string{verifiable.VCType},
		ID:           uuid.NewString(),
		Schemas:      []verifiable.TypedID{},
		CustomFields: verifiable.CustomFields{},
	}

	srcVCBytes, e := srcVC.MarshalJSON()
	require.NoError(t, e)

	const objectID = "object-id"

	t.Run("success: resolve http status VC URI", func(t *testing.T) {
		resolver := NewResolver(http.DefaultClient, &mockvdr.VDRegistry{}, "")

		statusServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			_, err := w.Write(srcVCBytes)
			require.NoError(t, err)
		}))

		defer func() {
			statusServer.Close()
		}()

		gotVC, err := resolver.Resolve(statusServer.URL)
		require.NoError(t, err)
		require.NotNil(t, gotVC)
		require.Equal(t, srcVC, gotVC)
	})

	t.Run("success: DID with Identity Hub service", func(t *testing.T) {
		resp := &identityhub.Response{
			Replies: []identityhub.MessageResult{
				{
					Entries: []identityhub.Message{
						{
							Descriptor: map[string]interface{}{
								objectIDKey: objectID,
							},
							Data: base64.StdEncoding.EncodeToString(srcVCBytes),
						},
					},
					Status: identityhub.Status{
						Code: http.StatusOK,
					},
				},
			},
		}

		respBytes, err := json.Marshal(resp)
		require.NoError(t, err)

		statusServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			_, e := w.Write(respBytes)
			require.NoError(t, e)
		}))

		defer func() {
			statusServer.Close()
		}()

		resolver := NewResolver(http.DefaultClient, &mockvdr.VDRegistry{
			ResolveValue: &did.Doc{
				Context: []string{did.ContextV1},
				Service: []did.Service{
					{
						Type:            serviceTypeIdentityHub,
						ServiceEndpoint: model.NewDIDCommV1Endpoint(statusServer.URL),
					},
				},
			},
		}, "")

		queryString := mockDIDQueryString(t, objectID)

		gotVC, err := resolver.Resolve("did:foo:bar" + queryString)
		require.NoError(t, err)
		require.NotNil(t, gotVC)
		require.Equal(t, srcVC, gotVC)
	})

	t.Run("fail: resolve DID", func(t *testing.T) {
		resolver := NewResolver(http.DefaultClient, &mockvdr.VDRegistry{}, "")

		_, err := resolver.Resolve("did:foo:bar")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to resolve DID")
	})

	t.Run("fail: no 'queries' query param", func(t *testing.T) {
		resolver := NewResolver(http.DefaultClient, &mockvdr.VDRegistry{
			ResolveValue: &did.Doc{
				Context: []string{did.ContextV1},
			},
		}, "")

		_, err := resolver.Resolve("did:foo:bar")
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing query")
	})

	t.Run("fail: no query params", func(t *testing.T) {
		resolver := NewResolver(http.DefaultClient, &mockvdr.VDRegistry{
			ResolveValue: &did.Doc{
				Context: []string{did.ContextV1},
			},
		}, "")

		_, err := resolver.Resolve("did:foo:bar")
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing query")
	})

	t.Run("fail: no 'queries' param", func(t *testing.T) {
		resolver := NewResolver(http.DefaultClient, &mockvdr.VDRegistry{
			ResolveValue: &did.Doc{
				Context: []string{did.ContextV1},
			},
		}, "")

		_, err := resolver.Resolve("did:foo:bar?foo=foo")
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing 'queries' parameter")
	})

	t.Run("fail: 'queries' param is not base 64 data", func(t *testing.T) {
		resolver := NewResolver(http.DefaultClient, &mockvdr.VDRegistry{
			ResolveValue: &did.Doc{
				Context: []string{did.ContextV1},
			},
		}, "")

		_, err := resolver.Resolve("did:foo:bar?queries=$-+_not-base64")
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to decode \"queries\" key")
	})

	t.Run("fail: 'queries' param is not encoded map list", func(t *testing.T) {
		resolver := NewResolver(http.DefaultClient, &mockvdr.VDRegistry{
			ResolveValue: &did.Doc{
				Context: []string{did.ContextV1},
			},
		}, "")

		queryData := base64.StdEncoding.EncodeToString([]byte("foo bar baz"))

		_, err := resolver.Resolve("did:foo:bar?queries=" + queryData)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to unmarshal queries")
	})

	t.Run("fail: 'queries' does not have valid data for constructing request", func(t *testing.T) {
		resolver := NewResolver(http.DefaultClient, &mockvdr.VDRegistry{
			ResolveValue: &did.Doc{
				Context: []string{did.ContextV1},
			},
		}, "")

		queryData := base64.StdEncoding.EncodeToString([]byte("[{\"foo\":\"bar\"}, {}]"))

		_, err := resolver.Resolve("did:foo:bar?queries=" + queryData)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to construct identity hub request object")
	})

	t.Run("fail: no identity hub did service", func(t *testing.T) {
		resolver := NewResolver(http.DefaultClient, &mockvdr.VDRegistry{
			ResolveValue: &did.Doc{
				Context: []string{did.ContextV1},
			},
		}, "")

		queryString := mockDIDQueryString(t, "foo")

		_, err := resolver.Resolve("did:foo:bar" + queryString)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to find identity hub service endpoint in did doc")
	})

	t.Run("fail: identity hub server error response", func(t *testing.T) {
		statusServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))

		defer func() {
			statusServer.Close()
		}()

		resolver := NewResolver(http.DefaultClient, &mockvdr.VDRegistry{
			ResolveValue: &did.Doc{
				Context: []string{did.ContextV1},
				Service: []did.Service{
					{
						Type:            serviceTypeIdentityHub,
						ServiceEndpoint: model.NewDIDCommV1Endpoint(statusServer.URL),
					},
				},
			},
		}, "")

		queryString := mockDIDQueryString(t, "zop")

		_, err := resolver.Resolve("did:foo:bar" + queryString)
		require.Error(t, err)
		require.Contains(t, err.Error(), "send identity hub request failed")
	})

	t.Run("fail: can't parse identity hub server response", func(t *testing.T) {
		statusServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			_, e := w.Write([]byte("abc def"))
			require.NoError(t, e)
		}))

		defer func() {
			statusServer.Close()
		}()

		resolver := NewResolver(http.DefaultClient, &mockvdr.VDRegistry{
			ResolveValue: &did.Doc{
				Context: []string{did.ContextV1},
				Service: []did.Service{
					{
						Type:            serviceTypeIdentityHub,
						ServiceEndpoint: model.NewDIDCommV1Endpoint(statusServer.URL),
					},
				},
			},
		}, "")

		queryString := mockDIDQueryString(t, "zip")

		_, err := resolver.Resolve("did:foo:bar" + queryString)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to unmarshal Response")
	})

	t.Run("fail: response status error", func(t *testing.T) {
		resp := &identityhub.Response{
			Status: &identityhub.Status{
				Code:    http.StatusInternalServerError,
				Message: "error",
			},
		}

		respBytes, err := json.Marshal(resp)
		require.NoError(t, err)

		statusServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			_, e := w.Write(respBytes)
			require.NoError(t, e)
		}))

		defer func() {
			statusServer.Close()
		}()

		resolver := NewResolver(http.DefaultClient, &mockvdr.VDRegistry{
			ResolveValue: &did.Doc{
				Context: []string{did.ContextV1},
				Service: []did.Service{
					{
						Type:            serviceTypeIdentityHub,
						ServiceEndpoint: model.NewDIDCommV1Endpoint(statusServer.URL),
					},
				},
			},
		}, "")

		queryString := mockDIDQueryString(t, objectID)

		_, err = resolver.Resolve("did:foo:bar" + queryString)
		require.Error(t, err)
		require.Contains(t, err.Error(), "identity hub server returned error response")
	})

	t.Run("fail: response has no message with expected ID", func(t *testing.T) {
		resp := &identityhub.Response{
			Replies: []identityhub.MessageResult{
				{
					Status: identityhub.Status{
						Code: http.StatusOK,
					},
				},
			},
		}

		respBytes, err := json.Marshal(resp)
		require.NoError(t, err)

		statusServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			_, e := w.Write(respBytes)
			require.NoError(t, e)
		}))

		defer func() {
			statusServer.Close()
		}()

		resolver := NewResolver(http.DefaultClient, &mockvdr.VDRegistry{
			ResolveValue: &did.Doc{
				Context: []string{did.ContextV1},
				Service: []did.Service{
					{
						Type:            serviceTypeIdentityHub,
						ServiceEndpoint: model.NewDIDCommV1Endpoint(statusServer.URL),
					},
				},
			},
		}, "")

		queryString := mockDIDQueryString(t, objectID)

		_, err = resolver.Resolve("did:foo:bar" + queryString)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to get message by object ID from Response")
	})

	t.Run("fail: response vc data in invalid format", func(t *testing.T) {
		resp := &identityhub.Response{
			Replies: []identityhub.MessageResult{
				{
					Entries: []identityhub.Message{
						{
							Descriptor: map[string]interface{}{
								objectIDKey: objectID,
							},
							Data: "$%^ not base64 data $%^",
						},
					},
					Status: identityhub.Status{
						Code: http.StatusOK,
					},
				},
			},
		}

		respBytes, err := json.Marshal(resp)
		require.NoError(t, err)

		statusServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			_, e := w.Write(respBytes)
			require.NoError(t, e)
		}))

		defer func() {
			statusServer.Close()
		}()

		resolver := NewResolver(http.DefaultClient, &mockvdr.VDRegistry{
			ResolveValue: &did.Doc{
				Context: []string{did.ContextV1},
				Service: []did.Service{
					{
						Type:            serviceTypeIdentityHub,
						ServiceEndpoint: model.NewDIDCommV1Endpoint(statusServer.URL),
					},
				},
			},
		}, "")

		queryString := mockDIDQueryString(t, objectID)

		_, err = resolver.Resolve("did:foo:bar" + queryString)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to decode message bytes")
	})

	t.Run("fail: can't parse status VC", func(t *testing.T) {
		resolver := NewResolver(http.DefaultClient, &mockvdr.VDRegistry{}, "")

		statusServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			_, e := w.Write([]byte("invalid data"))
			require.NoError(t, e)
		}))

		defer func() {
			statusServer.Close()
		}()

		_, err := resolver.Resolve(statusServer.URL)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse and verify status vc")
	})
}

func mockDIDQueryString(t *testing.T, objectID string) string {
	t.Helper()

	messageDescriptorList := []map[string]interface{}{
		{
			methodKey:   methodCollectionsQuery,
			objectIDKey: objectID,
		},
	}

	msgDescBytes, err := json.Marshal(messageDescriptorList)
	require.NoError(t, err)

	query := url.Values{
		"queries": []string{base64.StdEncoding.EncodeToString(msgDescBytes)},
	}

	return "?" + query.Encode()
}
