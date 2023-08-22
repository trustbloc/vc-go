/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package bitstring provides functions for operating on byte slices as if they are 0-indexed arrays of bits,
// packed 8 bits to a byte, LSB-first.
package bitstring

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
)

const (
	bitsPerByte = 8
	one         = 0x1
)

// Decode decodes a compressed bitstring from a base64URL-encoded string.
func Decode(src string) ([]byte, error) {
	decodedBits, err := base64.RawURLEncoding.DecodeString(src)
	if err != nil {
		return nil, err
	}

	b := bytes.NewReader(decodedBits)

	zipReader, err := gzip.NewReader(b)
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(zipReader); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// BitAt returns the bit in the idx'th position (zero-indexed) in the given bitstring.
func BitAt(bitString []byte, idx int) (bool, error) {
	nByte := idx / bitsPerByte
	nBit := idx % bitsPerByte

	if idx < 0 || nByte >= len(bitString) {
		return false, fmt.Errorf("position is invalid")
	}

	bitValue := (bitString[nByte] & (one << nBit)) != 0

	return bitValue, nil
}

// Encode gzips a bitstring and encodes it as a raw urlsafe base-64 string.
func Encode(bitString []byte) (string, error) {
	var buf bytes.Buffer

	w := gzip.NewWriter(&buf)
	if _, err := w.Write(bitString); err != nil {
		return "", err
	}

	if err := w.Close(); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(buf.Bytes()), nil
}
