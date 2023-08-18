//go:build !ACAPyInterop
// +build !ACAPyInterop

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signer

import (
	"time"

	afgotime "github.com/trustbloc/vc-go/util/time"
)

func wrapTime(t time.Time) *afgotime.TimeWrapper {
	return &afgotime.TimeWrapper{Time: t}
}
