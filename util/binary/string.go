/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package binary

import (
	"fmt"
	"strconv"
)

// EncodeStringToBinaryString encodes a string to a binary string.
func EncodeStringToBinaryString(s string) string {
	var result string

	for _, c := range s {
		result += fmt.Sprintf("%08b", c)
	}

	return result
}

// DecodeBinaryStringToString decodes a binary string to a string.
func DecodeBinaryStringToString(binStr string) (string, error) {
	var result string

	for i := 0; i < len(binStr); i += 8 {
		byteStr := binStr[i : i+8]

		byteVal, err := strconv.ParseUint(byteStr, 2, 8)
		if err != nil {
			return "", err
		}

		result += string(byte(byteVal))
	}

	return result, nil
}
