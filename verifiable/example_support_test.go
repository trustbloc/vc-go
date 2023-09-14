/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable_test

import (
	"encoding/base64"
	"strings"

	lddocloader "github.com/trustbloc/did-go/doc/ld/documentloader"
	ldtestutil "github.com/trustbloc/did-go/doc/ld/testutil"
	"github.com/trustbloc/kms-go/crypto/primitive/bbs12381g2pub"

	"github.com/trustbloc/vc-go/verifiable"
)

type UniversityDegree struct {
	Type       string `json:"type,omitempty"`
	University string `json:"university,omitempty"`
}

type UniversityDegreeSubject struct {
	ID     string           `json:"id,omitempty"`
	Name   string           `json:"name,omitempty"`
	Spouse string           `json:"spouse,omitempty"`
	Degree UniversityDegree `json:"degree,omitempty"`
}

type UniversityDegreeCredential struct {
	*verifiable.Credential

	ReferenceNumber int `json:"referenceNumber,omitempty"`
}

func (udc *UniversityDegreeCredential) MarshalJSON() ([]byte, error) {
	raw := udc.Credential.ToRawJSON()
	raw["referenceNumber"] = udc.ReferenceNumber

	vc, err := verifiable.ParseCredentialJSON(raw,
		verifiable.WithCredDisableValidation(),
		verifiable.WithDisabledProofCheck())
	if err != nil {
		panic(err)
	}

	return vc.MarshalJSON()
}

func getJSONLDDocumentLoader() *lddocloader.DocumentLoader {
	loader, err := ldtestutil.DocumentLoader()
	if err != nil {
		panic(err)
	}

	return loader
}

type bbsSigner struct {
	privKeyBytes []byte
}

func newBBSSigner(privKey *bbs12381g2pub.PrivateKey) (*bbsSigner, error) {
	privKeyBytes, err := privKey.Marshal()
	if err != nil {
		return nil, err
	}

	return &bbsSigner{privKeyBytes: privKeyBytes}, nil
}

func (s *bbsSigner) Sign(data []byte) ([]byte, error) {
	msgs := s.textToLines(string(data))

	return bbs12381g2pub.New().Sign(msgs, s.privKeyBytes)
}

// Alg return alg.
func (s *bbsSigner) Alg() string {
	return ""
}

func (s *bbsSigner) textToLines(txt string) [][]byte {
	lines := strings.Split(txt, "\n")
	linesBytes := make([][]byte, 0, len(lines))

	for i := range lines {
		if strings.TrimSpace(lines[i]) != "" {
			linesBytes = append(linesBytes, []byte(lines[i]))
		}
	}

	return linesBytes
}

func loadBBSKeyPair(pubKeyB64, privKeyB64 string) (*bbs12381g2pub.PublicKey, *bbs12381g2pub.PrivateKey, error) {
	pubKeyBytes, err := base64.RawStdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		return nil, nil, err
	}

	pubKey, err := bbs12381g2pub.UnmarshalPublicKey(pubKeyBytes)
	if err != nil {
		return nil, nil, err
	}

	privKeyBytes, err := base64.RawStdEncoding.DecodeString(privKeyB64)
	if err != nil {
		return nil, nil, err
	}

	privKey, err := bbs12381g2pub.UnmarshalPrivateKey(privKeyBytes)
	if err != nil {
		return nil, nil, err
	}

	return pubKey, privKey, nil
}
