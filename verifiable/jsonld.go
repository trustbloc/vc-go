/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"errors"
	"fmt"
)

const (
	// V1ContextURI is the required JSON-LD context for VCs and VPs.
	V1ContextURI = "https://www.w3.org/2018/credentials/v1"
	// V1ContextID is the non-fragment part of the JSON-LD schema ID for VCs and VPs.
	V1ContextID = "https://www.w3.org/2018/credentials"

	V2ContextURI = "https://www.w3.org/ns/credentials/v2"
	V2ContextID  = "https://www.w3.org/ns/credentials"
)

// GetBaseContext gets the base context from the contexts.
// The base context is the first element in the array and must be one of:
// - https://www.w3.org/2018/credentials/v1
// - https://www.w3.org/ns/credentials/v2
func GetBaseContext(contexts []string) (string, error) {
	if len(contexts) == 0 {
		return "", errors.New("@context is required")
	}

	ctx := contexts[0]

	if ctx == V1ContextURI || ctx == V2ContextURI {
		return ctx, nil
	}

	return "", fmt.Errorf("unsupported @context: %s", ctx)
}

// GetBaseContextFromRawDocument gets the base context from the raw document.
// The @context is either a string or array of strings. If it's given as an array
// then the base context is the first element in the @context array and must be one of:
//
// - https://www.w3.org/2018/credentials/v1
// - https://www.w3.org/ns/credentials/v2
func GetBaseContextFromRawDocument(doc map[string]interface{}) (string, error) {
	ctx, ok := doc[jsonFldContext]
	if !ok {
		return "", fmt.Errorf("%s is required", jsonFldContext)
	}

	baseContext, _, err := decodeContext(ctx)
	if err != nil {
		return "", err
	}

	return GetBaseContext(baseContext)
}

// IsBaseContext returns true if the given context is the base context.
func IsBaseContext(contexts []string, ctx string) bool {
	if len(contexts) == 0 {
		return false
	}

	return contexts[0] == ctx
}

// HasBaseContext returns true if the given document has the given base context.
func HasBaseContext(doc map[string]interface{}, ctx string) bool {
	rawContext, ok := doc[jsonFldContext]
	if !ok {
		return false
	}

	contexts, _, err := decodeContext(rawContext)
	if err != nil {
		return false
	}

	return IsBaseContext(contexts, ctx)
}
