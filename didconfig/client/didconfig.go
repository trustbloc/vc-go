/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package client

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	jsonld "github.com/piprate/json-gold/ld"
	"github.com/trustbloc/did-go/doc/did"
	vdrapi "github.com/trustbloc/did-go/vdr/api"

	"github.com/trustbloc/vc-go/didconfig/verifier"
)

var errLogger = log.New(os.Stderr, " [did-go/did-config/client] ", log.Ldate|log.Ltime|log.LUTC)

const defaultTimeout = time.Minute

// Client is a JSON-LD SDK client.
type Client struct {
	httpClient    httpClient
	didConfigOpts []verifier.DIDConfigurationOpt
}

// New creates new did configuration client.
func New(opts ...Option) *Client {
	client := &Client{
		httpClient: &http.Client{Timeout: defaultTimeout},
	}

	for _, opt := range opts {
		opt(client)
	}

	return client
}

// httpClient represents an HTTP client.
type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Option configures the did configuration client.
type Option func(opts *Client)

// WithHTTPClient option is for custom http client.
func WithHTTPClient(httpClient httpClient) Option {
	return func(opts *Client) {
		opts.httpClient = httpClient
	}
}

// WithJSONLDDocumentLoader defines a JSON-LD document loader.
func WithJSONLDDocumentLoader(documentLoader jsonld.DocumentLoader) Option {
	return func(opts *Client) {
		opts.didConfigOpts = append(opts.didConfigOpts, verifier.WithJSONLDDocumentLoader(documentLoader))
	}
}

type didResolver interface {
	Resolve(did string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error)
}

// WithVDRegistry defines a vdr service.
func WithVDRegistry(didResolver didResolver) Option {
	return func(opts *Client) {
		opts.didConfigOpts = append(opts.didConfigOpts, verifier.WithVDRegistry(didResolver))
	}
}

// VerifyDIDAndDomain will verify that there is valid domain linkage credential in did configuration
// for specified did and domain.
func (c *Client) VerifyDIDAndDomain(did, domain string) error {
	endpoint := domain + "/.well-known/did-configuration.json"

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("new HTTP request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("httpClient.Do: %w", err)
	}

	defer closeResponseBody(resp.Body)

	responseBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("endpoint %s returned status '%d' and message '%s'",
			endpoint, resp.StatusCode, responseBytes)
	}

	return verifier.VerifyDIDAndDomain(responseBytes, did, domain, c.didConfigOpts...)
}

func closeResponseBody(respBody io.Closer) {
	e := respBody.Close()
	if e != nil {
		errLogger.Printf("failed to close response body: %v", e)
	}
}
