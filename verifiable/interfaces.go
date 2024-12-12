/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

//go:generate mockgen -destination interfaces_mocks_test.go -package verifiable_test -source=interfaces.go

import "net/http"

// nolint
type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}
