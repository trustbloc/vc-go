/*
Copyright Avast Software. All Rights Reserved.
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package resolver provides a resolver for remotely-stored credential status list VCs.
package resolver

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	vdrapi "github.com/trustbloc/did-go/vdr/api"

	"github.com/trustbloc/vc-go/status/internal/identityhub"
	"github.com/trustbloc/vc-go/verifiable"
)

// Resolver resolves credential status list VCs.
type Resolver struct {
	client      *http.Client
	bearerToken string
	didResolver vdrapi.Registry
}

// NewResolver creates a Resolver.
func NewResolver(client *http.Client, didResolver vdrapi.Registry, bearerToken string) *Resolver {
	return &Resolver{
		client:      client,
		bearerToken: bearerToken,
		didResolver: didResolver,
	}
}

// Resolve fetches the VC at the given URI.
func (r *Resolver) Resolve(statusListVCURI string) (*verifiable.Credential, error) {
	var (
		vcBytes []byte
		err     error
	)

	if strings.HasPrefix(statusListVCURI, "did:") {
		vcBytes, err = r.resolveDIDRelativeURL(statusListVCURI)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve status VC DID URI: %w", err)
		}
	} else {
		req, e := http.NewRequestWithContext(context.Background(), http.MethodGet, statusListVCURI, http.NoBody)
		if e != nil {
			return nil, e
		}

		vcBytes, err = r.sendHTTPRequest(req, http.StatusOK, r.bearerToken)

		if err != nil {
			return nil, fmt.Errorf("unable to resolve statusListVCURI: %w", err)
		}
	}

	// TODO: need to verify proof on vc - consider if validation also needs to be done (json-ld and json schema)
	cred, err := verifiable.ParseCredential(
		vcBytes,
		verifiable.WithDisabledProofCheck(),
		verifiable.WithCredDisableValidation(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to parse and verify status vc: %w", err)
	}

	return cred, nil
}

const (
	idHubQueryMethod = "CollectionsQuery"
)

func (r *Resolver) resolveDIDRelativeURL(didURL string) ([]byte, error) {
	docRes, err := r.didResolver.Resolve(strings.Split(didURL, "?")[0])
	if err != nil {
		return nil, fmt.Errorf("failed to resolve DID: %w", err)
	}

	didDoc := docRes.DIDDocument

	queries, err := getQueries(didURL)
	if err != nil {
		return nil, err
	}

	objectID, reqMessage, err := identityhub.GetRequest(didDoc.ID, idHubQueryMethod, queries)
	if err != nil {
		return nil, fmt.Errorf("unable to construct identity hub request object: %w", err)
	}

	payload, err := json.Marshal(reqMessage)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal identityHubRequest: %w", err)
	}

	svcEndpoint, err := identityhub.ServiceEndpoint(didDoc)
	if err != nil {
		return nil, fmt.Errorf("unable to find identity hub service endpoint in did doc: %w", err)
	}

	req, err := http.NewRequestWithContext(
		context.Background(), http.MethodPost, svcEndpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("unable to create request to identity hub: %w", err)
	}

	req.Header.Add("Content-Type", "application/json")

	resp, err := r.sendHTTPRequest(req, http.StatusOK, r.bearerToken)
	if err != nil {
		return nil, fmt.Errorf("send identity hub request failed: %w", err)
	}

	var identityHubResponse identityhub.Response

	err = json.Unmarshal(resp, &identityHubResponse)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal Response: %w", err)
	}

	err = identityHubResponse.CheckStatus()
	if err != nil {
		return nil, fmt.Errorf("identity hub server returned error response: %w", err)
	}

	return identityHubResponse.GetMessageData(objectID)
}

func (r *Resolver) sendHTTPRequest(req *http.Request, status int, token string) ([]byte, error) {
	if token != "" {
		req.Header.Add("Authorization", "Bearer "+token)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() {
		e := resp.Body.Close()
		if e != nil {
			fmt.Printf("failed to close message body: %v", e)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response, code=%d: %w", resp.StatusCode, err)
	}

	if resp.StatusCode != status {
		return nil, fmt.Errorf("expected response code %d, got %d", status, resp.StatusCode)
	}

	return body, nil
}

func getQueries(didRelativeURL string) ([]map[string]interface{}, error) {
	chunks := strings.Split(didRelativeURL, "?")
	if len(chunks) <= 1 {
		return nil, fmt.Errorf("missing query")
	}

	queryValues, err := url.ParseQuery(chunks[1])
	if err != nil {
		return nil, fmt.Errorf("unable to parse query from didURL: %w", err)
	}

	queries := queryValues.Get("queries")
	if queries == "" {
		return nil, fmt.Errorf("missing 'queries' parameter")
	}

	queriesVal, err := base64.StdEncoding.DecodeString(queries)
	if err != nil {
		return nil, fmt.Errorf("unable to decode \"queries\" key: %w", err)
	}

	queryMaps := []map[string]interface{}{}

	err = json.Unmarshal(queriesVal, &queryMaps)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal queries: %w", err)
	}

	return queryMaps, nil
}
