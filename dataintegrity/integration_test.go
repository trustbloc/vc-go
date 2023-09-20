/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dataintegrity

import (
	_ "embed"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/sjson"
	"github.com/trustbloc/did-go/doc/did"
	"github.com/trustbloc/did-go/doc/ld/documentloader"
	mockldstore "github.com/trustbloc/did-go/doc/ld/mock"
	"github.com/trustbloc/did-go/doc/ld/store"
	kmsapi "github.com/trustbloc/kms-go/spi/kms"

	"github.com/trustbloc/vc-go/dataintegrity/models"
	"github.com/trustbloc/vc-go/dataintegrity/suite/ecdsa2019"
	"github.com/trustbloc/vc-go/internal/testutil/kmscryptoutil"
)

var (
	//go:embed suite/ecdsa2019/testdata/valid_credential.jsonld
	validCredential []byte
)

const (
	mockDID2  = "did:test:p384"
	mockVMID2 = "#key-2"
	mockKID2  = mockDID2 + mockVMID2
)

func TestIntegration(t *testing.T) {
	docLoader, err := documentloader.NewDocumentLoader(createMockProvider())
	require.NoError(t, err)

	kmsCrypto := kmscryptoutil.LocalKMSCrypto(t)

	signerInit := ecdsa2019.NewSignerInitializer(&ecdsa2019.SignerInitializerOptions{
		LDDocumentLoader: docLoader,
		SignerGetter:     ecdsa2019.WithKMSCryptoWrapper(kmsCrypto),
	})

	verifierInit := ecdsa2019.NewVerifierInitializer(&ecdsa2019.VerifierInitializerOptions{
		LDDocumentLoader: docLoader,
	})

	p256JWK, err := kmsCrypto.Create(kmsapi.ECDSAP256IEEEP1363)
	require.NoError(t, err)

	p384JWK, err := kmsCrypto.Create(kmsapi.ECDSAP384IEEEP1363)
	require.NoError(t, err)

	p256VM, err := did.NewVerificationMethodFromJWK(mockKID, "JsonWebKey2020", mockDID, p256JWK)
	require.NoError(t, err)

	p384VM, err := did.NewVerificationMethodFromJWK(mockKID2, "JsonWebKey2020", mockDID2, p384JWK)
	require.NoError(t, err)

	resolver := resolveFunc(func(id string) (*did.DocResolution, error) {
		switch id {
		case mockDID:
			return makeMockDIDResolution(id, p256VM, did.AssertionMethod), nil
		case mockDID2:
			return makeMockDIDResolution(id, p384VM, did.AssertionMethod), nil
		}

		fmt.Printf("DID: '%s'", id)

		return nil, ErrVMResolution
	})

	signer, err := NewSigner(&Options{DIDResolver: resolver}, signerInit)
	require.NoError(t, err)

	verifier, err := NewVerifier(&Options{DIDResolver: resolver}, verifierInit)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		t.Run("P-256 key", func(t *testing.T) {
			signOpts := &models.ProofOptions{
				VerificationMethod:   p256VM,
				VerificationMethodID: p256VM.ID,
				SuiteType:            ecdsa2019.SuiteType,
				Purpose:              AssertionMethod,
				ProofType:            models.DataIntegrityProof,
				Created:              time.Now(),
				MaxAge:               100,
			}

			signedCred, err := signer.AddProof(validCredential, signOpts)
			require.NoError(t, err)

			verifyOpts := &models.ProofOptions{
				VerificationMethodID: mockKID,
				SuiteType:            ecdsa2019.SuiteType,
				Purpose:              AssertionMethod,
				ProofType:            models.DataIntegrityProof,
				Created:              time.Now(),
				MaxAge:               100,
			}

			err = verifier.VerifyProof(signedCred, verifyOpts)
			require.NoError(t, err)
		})

		t.Run("P-384 key", func(t *testing.T) {
			signOpts := &models.ProofOptions{
				VerificationMethod:   p384VM,
				VerificationMethodID: mockKID2,
				SuiteType:            ecdsa2019.SuiteType,
				Purpose:              AssertionMethod,
				ProofType:            models.DataIntegrityProof,
				Created:              time.Now(),
				MaxAge:               100,
			}

			signedCred, err := signer.AddProof(validCredential, signOpts)
			require.NoError(t, err)

			verifyOpts := &models.ProofOptions{
				VerificationMethodID: mockKID2,
				SuiteType:            ecdsa2019.SuiteType,
				Purpose:              AssertionMethod,
				ProofType:            models.DataIntegrityProof,
				Created:              time.Now(),
				MaxAge:               100,
			}

			err = verifier.VerifyProof(signedCred, verifyOpts)
			require.NoError(t, err)
		})
	})

	t.Run("failure", func(t *testing.T) {
		t.Run("wrong key", func(t *testing.T) {
			signOpts := &models.ProofOptions{
				VerificationMethod:   p256VM,
				VerificationMethodID: p256VM.ID,
				SuiteType:            ecdsa2019.SuiteType,
				Purpose:              AssertionMethod,
				ProofType:            models.DataIntegrityProof,
				Created:              time.Now(),
			}

			verifyOpts := &models.ProofOptions{
				VerificationMethod:   p384VM,
				VerificationMethodID: p384VM.ID,
				SuiteType:            ecdsa2019.SuiteType,
				Purpose:              AssertionMethod,
				ProofType:            models.DataIntegrityProof,
				MaxAge:               100,
			}

			signedCred, err := signer.AddProof(validCredential, signOpts)
			require.NoError(t, err)

			err = verifier.VerifyProof(signedCred, verifyOpts)
			require.Error(t, err)
			require.Contains(t, err.Error(), "failed to verify ecdsa-2019 DI proof")
		})
		t.Run("malformed proof created", func(t *testing.T) {
			signOpts := &models.ProofOptions{
				VerificationMethod:   p256VM,
				VerificationMethodID: p256VM.ID,
				SuiteType:            ecdsa2019.SuiteType,
				Purpose:              "assertionMethod",
				ProofType:            models.DataIntegrityProof,
				Created:              time.Now(),
			}

			verifyOpts := &models.ProofOptions{
				VerificationMethod:   p384VM,
				VerificationMethodID: p384VM.ID,
				SuiteType:            ecdsa2019.SuiteType,
				Purpose:              "assertionMethod",
				ProofType:            models.DataIntegrityProof,
				MaxAge:               100,
				Created:              time.Time{},
			}

			signedCred, err := signer.AddProof(validCredential, signOpts)
			require.NoError(t, err)

			signedCredStr, err := sjson.Set(string(signedCred), "proof.created", "malformed")
			require.NoError(t, err)

			err = verifier.VerifyProof([]byte(signedCredStr), verifyOpts)
			require.Error(t, err)
			require.Contains(t, err.Error(), "malformed data integrity proof")
		})
	})
}

type provider struct {
	ContextStore        store.ContextStore
	RemoteProviderStore store.RemoteProviderStore
}

func (p *provider) JSONLDContextStore() store.ContextStore {
	return p.ContextStore
}

func (p *provider) JSONLDRemoteProviderStore() store.RemoteProviderStore {
	return p.RemoteProviderStore
}

func createMockProvider() *provider {
	return &provider{
		ContextStore:        mockldstore.NewMockContextStore(),
		RemoteProviderStore: mockldstore.NewMockRemoteProviderStore(),
	}
}
