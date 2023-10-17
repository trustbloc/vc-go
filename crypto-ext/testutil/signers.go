/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package testutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"strings"

	"github.com/trustbloc/bbs-signature-go/bbs12381g2pub"
	"github.com/trustbloc/kms-go/doc/jose"
)

// Ed25519Signer is a Jose compliant signer.
type Ed25519Signer struct {
	privKey []byte
}

// Sign data.
func (s Ed25519Signer) Sign(data []byte) ([]byte, error) {
	return ed25519.Sign(s.privKey, data), nil
}

// Headers defined to be compatible with jose signer. TODO: remove after jose refactoring.
func (s Ed25519Signer) Headers() jose.Headers {
	return jose.Headers{
		jose.HeaderAlgorithm: "EdDSA",
	}
}

// NewEd25519Signer creates Ed25519Signer.
func NewEd25519Signer(ed25519PK []byte) *Ed25519Signer {
	return &Ed25519Signer{privKey: ed25519PK}
}

// RS256Signer is a Jose complient signer.
type RS256Signer struct {
	privKey *rsa.PrivateKey
}

// Sign data.
func (s RS256Signer) Sign(data []byte) ([]byte, error) {
	hash := crypto.SHA256.New()

	_, err := hash.Write(data)
	if err != nil {
		return nil, err
	}

	hashed := hash.Sum(nil)

	return rsa.SignPKCS1v15(rand.Reader, s.privKey, crypto.SHA256, hashed)
}

// Headers defined to be compatible with jose signer. TODO: remove after jose refactoring.
func (s RS256Signer) Headers() jose.Headers {
	return jose.Headers{
		jose.HeaderAlgorithm: "RS256",
	}
}

// NewRS256Signer creates RS256Signer.
func NewRS256Signer(privKey *rsa.PrivateKey) *RS256Signer {
	return &RS256Signer{
		privKey: privKey,
	}
}

// PS256Signer is a Jose complient signer.
type PS256Signer struct {
	privKey *rsa.PrivateKey
}

// Sign data.
func (s PS256Signer) Sign(data []byte) ([]byte, error) {
	hash := crypto.SHA256.New()

	_, err := hash.Write(data)
	if err != nil {
		return nil, err
	}

	hashed := hash.Sum(nil)

	return rsa.SignPSS(rand.Reader, s.privKey, crypto.SHA256, hashed, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	})
}

// Headers defined to be compatible with jose signer. TODO: remove after jose refactoring.
func (s PS256Signer) Headers() jose.Headers {
	return jose.Headers{
		jose.HeaderAlgorithm: "PS256",
	}
}

// NewPS256Signer creates PS256Signer.
func NewPS256Signer(privKey *rsa.PrivateKey) *PS256Signer {
	return &PS256Signer{
		privKey: privKey,
	}
}

// ECDSASigner makes ECDSA based signatures.
type ECDSASigner struct {
	privateKey *ecdsa.PrivateKey
	hash       crypto.Hash
}

func newECDSASigner(
	privKey *ecdsa.PrivateKey,
	hash crypto.Hash,
) *ECDSASigner {
	return &ECDSASigner{
		privateKey: privKey,
		hash:       hash,
	}
}

// Sign signs a message.
func (es *ECDSASigner) Sign(msg []byte) ([]byte, error) {
	return signEcdsa(msg, es.privateKey, es.hash)
}

//nolint:gomnd
func signEcdsa(msg []byte, privateKey *ecdsa.PrivateKey, hash crypto.Hash) ([]byte, error) {
	hasher := hash.New()
	_, _ = hasher.Write(msg)
	hashed := hasher.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashed)
	if err != nil {
		return nil, err
	}

	curveBits := privateKey.Curve.Params().BitSize

	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes++
	}

	copyPadded := func(source []byte, size int) []byte {
		dest := make([]byte, size)
		copy(dest[size-len(source):], source)

		return dest
	}

	return append(copyPadded(r.Bytes(), keyBytes), copyPadded(s.Bytes(), keyBytes)...), nil
}

// NewECDSASecp256k1Signer creates a new ECDSA Secp256k1 signer with generated key.
func NewECDSASecp256k1Signer(privateKey *ecdsa.PrivateKey) *ECDSASigner {
	return newECDSASigner(privateKey, crypto.SHA256)
}

// BBSSigner makes bbs+ signatures.
type BBSSigner struct {
	privateKey []byte
}

// NewBBSSigner creates BBSSigner.
func NewBBSSigner(key *bbs12381g2pub.PrivateKey) (*BBSSigner, error) {
	src, err := key.Marshal()
	if err != nil {
		return nil, err
	}

	return &BBSSigner{privateKey: src}, nil
}

// Sign signs a message.
func (s *BBSSigner) Sign(data []byte) ([]byte, error) {
	return bbs12381g2pub.New().Sign(s.textToLines(string(data)), s.privateKey)
}

func (s *BBSSigner) textToLines(txt string) [][]byte {
	lines := strings.Split(txt, "\n")
	linesBytes := make([][]byte, 0, len(lines))

	for i := range lines {
		if strings.TrimSpace(lines[i]) != "" {
			linesBytes = append(linesBytes, []byte(lines[i]))
		}
	}

	return linesBytes
}
