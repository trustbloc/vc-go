/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package creator

import (
	"errors"
	"io"

	"github.com/fxamacker/cbor/v2"
)

// Pre-configured modes for CBOR encoding and decoding.
var (
	encMode                  cbor.EncMode
	decMode                  cbor.DecMode
	decModeWithTagsForbidden cbor.DecMode
)

func init() {
	var err error

	// init encode mode
	encOpts := cbor.EncOptions{
		Sort:        cbor.SortCoreDeterministic, // sort map keys
		IndefLength: cbor.IndefLengthForbidden,  // no streaming
	}
	encMode, err = encOpts.EncMode()
	if err != nil {
		panic(err)
	}

	// init decode mode
	decOpts := cbor.DecOptions{
		DupMapKey:   cbor.DupMapKeyEnforcedAPF, // duplicated key not allowed
		IndefLength: cbor.IndefLengthForbidden, // no streaming
		IntDec:      cbor.IntDecConvertSigned,  // decode CBOR uint/int to Go int64
	}
	decMode, err = decOpts.DecMode()
	if err != nil {
		panic(err)
	}
	decOpts.TagsMd = cbor.TagsForbidden
	decModeWithTagsForbidden, err = decOpts.DecMode()
	if err != nil {
		panic(err)
	}
}

// deterministicBinaryString converts a bstr into the deterministic encoding.
//
// Reference: https://www.rfc-editor.org/rfc/rfc9052.html#section-9
func deterministicBinaryString(data cbor.RawMessage) (cbor.RawMessage, error) {
	if len(data) == 0 {
		return nil, io.EOF
	}
	if data[0]>>5 != 2 { // major type 2: bstr
		return nil, errors.New("cbor: require bstr type")
	}

	// fast path: return immediately if bstr is already deterministic
	if err := decModeWithTagsForbidden.Valid(data); err != nil {
		return nil, err
	}
	ai := data[0] & 0x1f
	if ai < 24 {
		return data, nil
	}
	switch ai {
	case 24:
		if data[1] >= 24 {
			return data, nil
		}
	case 25:
		if data[1] != 0 {
			return data, nil
		}
	case 26:
		if data[1] != 0 || data[2] != 0 {
			return data, nil
		}
	case 27:
		if data[1] != 0 || data[2] != 0 || data[3] != 0 || data[4] != 0 {
			return data, nil
		}
	}

	// slow path: convert by re-encoding
	// error checking is not required since `data` has been validataed
	var s []byte
	_ = decModeWithTagsForbidden.Unmarshal(data, &s)
	return encMode.Marshal(s)
}
