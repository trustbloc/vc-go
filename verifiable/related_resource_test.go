/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable_test

import (
	"bytes"
	_ "embed"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vc-go/verifiable"
)

//go:embed testdata/related_resources_1.json
var relatedResources1 []byte

//go:embed testdata/related_resources_2.json
var relatedResources2 []byte

//go:embed testdata/credential_with_resource.json
var credentialWithResource []byte

func TestParseCredentialWithResource(t *testing.T) {
	resp, err := verifiable.ParseCredential(
		credentialWithResource,
		verifiable.WithJSONLDDocumentLoader(ld.NewDefaultDocumentLoader(http.DefaultClient)),
		verifiable.WithDisabledProofCheck(),
		verifiable.WithDisabledRelatedResourceCheck(),
	)

	assert.NoError(t, err)
	assert.NotNil(t, resp)

	content := resp.Contents()
	assert.Len(t, content.RelatedResources, 1)

	assert.Equal(t, "https://w3c.github.io/vc-data-model/related-resource.json",
		content.RelatedResources[0].Id)

	data, err := resp.MarshalJSON()
	assert.NoError(t, err)
	assert.NotEmpty(t, data)

	resp, err = verifiable.ParseCredential(data,
		verifiable.WithJSONLDDocumentLoader(ld.NewDefaultDocumentLoader(http.DefaultClient)),
		verifiable.WithDisabledProofCheck(),
		verifiable.WithDisabledRelatedResourceCheck(),
	)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	content = resp.Contents()
	assert.Len(t, content.RelatedResources, 1)
}

func TestValidateRelatedResources(t *testing.T) {
	contentFn := func(request *http.Request) (*http.Response, error) {
		if request.URL.String() == "https://www.w3.org/ns/credentials/v2" {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(relatedResources1))}, nil
		} else if request.URL.String() == "https://www.w3.org/ns/credentials/examples/v2" {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(relatedResources2))}, nil
		}

		return nil, errors.New("unexpected url")
	}

	t.Run("success sri and multi-base", func(t *testing.T) {
		cred, err := verifiable.CreateCredential(verifiable.CredentialContents{
			RelatedResources: []verifiable.RelatedResource{
				{
					Id:        "https://www.w3.org/ns/credentials/v2",
					DigestSRI: "sha384-MNSOcNpmdIVUxIJGvGUoe22FjTWrXiaXlsZ8q6912LdnR3KraQO2n75Ica4wK4Qeg",
				},
				{
					Id:              "https://www.w3.org/ns/credentials/examples/v2",
					DigestMultiBase: "uEiBXOT-8adbvubm13Jy2uYgLCUQ2Cr_i6vRZyeWM8iedfA",
				},
			},
		}, nil)
		assert.NoError(t, err)

		cl := NewMockhttpClient(gomock.NewController(t))
		cl.EXPECT().Do(gomock.Any()).DoAndReturn(contentFn).Times(2)

		validator := verifiable.NewRelatedResourceValidator(
			verifiable.WithHTTPClient(cl),
		)
		err = validator.Validate([]*verifiable.Credential{cred})
		assert.NoError(t, err)
	})

	t.Run("invalid sri", func(t *testing.T) {
		cred, err := verifiable.CreateCredential(verifiable.CredentialContents{
			RelatedResources: []verifiable.RelatedResource{
				{
					Id:        "https://www.w3.org/ns/credentials/v2",
					DigestSRI: "sha512-MNSOcNpmdIVUxIJGvGUoe22FjTWrXiaXlsZ8q6912LdnR3KraQO2n75Ica4wK4Qeg",
				},
			},
		}, nil)
		assert.NoError(t, err)

		cl := NewMockhttpClient(gomock.NewController(t))
		cl.EXPECT().Do(gomock.Any()).DoAndReturn(contentFn).Times(1)

		validator := verifiable.NewRelatedResourceValidator(
			verifiable.WithHTTPClient(cl),
		)
		err = validator.Validate([]*verifiable.Credential{cred})
		assert.ErrorContains(t, err, "hash mismatch")
	})

	t.Run("invalid sri-format", func(t *testing.T) {
		cred, err := verifiable.CreateCredential(verifiable.CredentialContents{
			RelatedResources: []verifiable.RelatedResource{
				{
					Id:        "https://www.w3.org/ns/credentials/v2",
					DigestSRI: "sha512|MNSOcNpmdIVUxIJGvGUoe22FjTWrXiaXlsZ8q6912LdnR3KraQO2n75Ica4wK4Qeg",
				},
			},
		}, nil)
		assert.NoError(t, err)

		cl := NewMockhttpClient(gomock.NewController(t))
		cl.EXPECT().Do(gomock.Any()).DoAndReturn(contentFn).Times(2)

		validator := verifiable.NewRelatedResourceValidator(
			verifiable.WithHTTPClient(cl),
		)
		err = validator.Validate([]*verifiable.Credential{cred})
		assert.ErrorContains(t, err, "invalid digest SRI format")
	})

	t.Run("invalid multibase-format", func(t *testing.T) {
		cred, err := verifiable.CreateCredential(verifiable.CredentialContents{
			RelatedResources: []verifiable.RelatedResource{
				{
					Id:        "https://www.w3.org/ns/credentials/v2",
					DigestSRI: "sha512-xxyy",
				},
			},
		}, nil)
		assert.NoError(t, err)

		cl := NewMockhttpClient(gomock.NewController(t))
		cl.EXPECT().Do(gomock.Any()).DoAndReturn(contentFn).Times(2)

		validator := verifiable.NewRelatedResourceValidator(
			verifiable.WithHTTPClient(cl),
		)
		err = validator.Validate([]*verifiable.Credential{cred})
		assert.ErrorContains(t, err, "selected encoding not supported")
	})

	t.Run("invalid unsupported hash", func(t *testing.T) {
		cred, err := verifiable.CreateCredential(verifiable.CredentialContents{
			RelatedResources: []verifiable.RelatedResource{
				{
					Id:        "https://www.w3.org/ns/credentials/v2",
					DigestSRI: "MurmurHash-MNSOcNpmdIVUxIJGvGUoe22FjTWrXiaXlsZ8q6912LdnR3KraQO2n75Ica4wK4Qeg",
				},
			},
		}, nil)
		assert.NoError(t, err)

		cl := NewMockhttpClient(gomock.NewController(t))
		cl.EXPECT().Do(gomock.Any()).DoAndReturn(contentFn).Times(2)

		validator := verifiable.NewRelatedResourceValidator(
			verifiable.WithHTTPClient(cl),
		)
		err = validator.Validate([]*verifiable.Credential{cred})
		assert.ErrorContains(t, err, "unsupported hash algorithm")
	})

	t.Run("fetch from cache", func(t *testing.T) {
		cl := NewMockhttpClient(gomock.NewController(t))
		cl.EXPECT().Do(gomock.Any()).DoAndReturn(contentFn).Times(1)

		validator := verifiable.NewRelatedResourceValidator(
			verifiable.WithHTTPClient(cl),
			verifiable.WithCache(expirable.NewLRU[string, *verifiable.CachedResource](
				1,
				nil,
				10*time.Second,
			)),
		)

		cred, err := verifiable.CreateCredential(verifiable.CredentialContents{
			RelatedResources: []verifiable.RelatedResource{
				{
					Id:        "https://www.w3.org/ns/credentials/v2",
					DigestSRI: "sha384-MNSOcNpmdIVUxIJGvGUoe22FjTWrXiaXlsZ8q6912LdnR3KraQO2n75Ica4wK4Qeg",
				},
			},
		}, nil)
		assert.NoError(t, err)

		err = validator.Validate([]*verifiable.Credential{cred})
		assert.NoError(t, err)

		err = validator.Validate([]*verifiable.Credential{cred})
		assert.NoError(t, err)
	})

	t.Run("fetch with err", func(t *testing.T) {
		cred, err := verifiable.CreateCredential(verifiable.CredentialContents{
			RelatedResources: []verifiable.RelatedResource{
				{
					Id:        "https://www.w3.org/ns/credentials/v2",
					DigestSRI: "sha512-MNSOcNpmdIVUxIJGvGUoe22FjTWrXiaXlsZ8q6912LdnR3KraQO2n75Ica4wK4Qeg",
				},
			},
		}, nil)
		assert.NoError(t, err)

		cl := NewMockhttpClient(gomock.NewController(t))
		cl.EXPECT().Do(gomock.Any()).
			DoAndReturn(func(request *http.Request) (*http.Response, error) {
				return nil, errors.New("unexpected err")
			})

		validator := verifiable.NewRelatedResourceValidator(
			verifiable.WithHTTPClient(cl),
		)
		err = validator.Validate([]*verifiable.Credential{cred})
		assert.ErrorContains(t, err, "unexpected err")
	})

	t.Run("fetch with http err", func(t *testing.T) {
		cred, err := verifiable.CreateCredential(verifiable.CredentialContents{
			RelatedResources: []verifiable.RelatedResource{
				{
					Id:        "https://www.w3.org/ns/credentials/v2",
					DigestSRI: "sha512-MNSOcNpmdIVUxIJGvGUoe22FjTWrXiaXlsZ8q6912LdnR3KraQO2n75Ica4wK4Qeg",
				},
			},
		}, nil)
		assert.NoError(t, err)

		cl := NewMockhttpClient(gomock.NewController(t))
		cl.EXPECT().Do(gomock.Any()).
			DoAndReturn(func(request *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusInternalServerError,
				}, nil
			})

		validator := verifiable.NewRelatedResourceValidator(
			verifiable.WithHTTPClient(cl),
		)
		err = validator.Validate([]*verifiable.Credential{cred})
		assert.ErrorContains(t, err, "related resource fetch failed with status code: 500")
	})

	t.Run("no body", func(t *testing.T) {
		cred, err := verifiable.CreateCredential(verifiable.CredentialContents{
			RelatedResources: []verifiable.RelatedResource{
				{
					Id:        "https://www.w3.org/ns/credentials/v2",
					DigestSRI: "sha512-MNSOcNpmdIVUxIJGvGUoe22FjTWrXiaXlsZ8q6912LdnR3KraQO2n75Ica4wK4Qeg",
				},
			},
		}, nil)
		assert.NoError(t, err)

		cl := NewMockhttpClient(gomock.NewController(t))
		cl.EXPECT().Do(gomock.Any()).
			DoAndReturn(func(request *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
				}, nil
			})

		validator := verifiable.NewRelatedResourceValidator(
			verifiable.WithHTTPClient(cl),
		)
		err = validator.Validate([]*verifiable.Credential{cred})
		assert.ErrorContains(t, err, "empty related resource")
	})

	t.Run("no body", func(t *testing.T) {
		cred, err := verifiable.CreateCredential(verifiable.CredentialContents{
			RelatedResources: []verifiable.RelatedResource{
				{
					Id:        "https://www.w3.org/ns/credentials/v2",
					DigestSRI: "sha512-MNSOcNpmdIVUxIJGvGUoe22FjTWrXiaXlsZ8q6912LdnR3KraQO2n75Ica4wK4Qeg",
				},
			},
		}, nil)
		assert.NoError(t, err)

		cl := NewMockhttpClient(gomock.NewController(t))
		cl.EXPECT().Do(gomock.Any()).
			DoAndReturn(func(request *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewReader([]byte{})),
				}, nil
			})

		validator := verifiable.NewRelatedResourceValidator(
			verifiable.WithHTTPClient(cl),
		)
		err = validator.Validate([]*verifiable.Credential{cred})
		assert.ErrorContains(t, err, "empty related resource")
	})
}
