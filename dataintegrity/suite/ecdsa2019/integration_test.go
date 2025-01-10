/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdsa2019

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/did-go/doc/did"
	"github.com/trustbloc/did-go/doc/ld/documentloader"
	kmsapi "github.com/trustbloc/kms-go/spi/kms"

	"github.com/trustbloc/vc-go/internal/testutil/kmscryptoutil"

	"github.com/trustbloc/vc-go/dataintegrity/models"
)

func TestIntegration(t *testing.T) {
	docLoader, err := documentloader.NewDocumentLoader(createMockProvider())
	require.NoError(t, err)

	kmsCrypto := kmscryptoutil.LocalKMSCrypto(t)

	signerInit := NewSignerInitializer(&SignerInitializerOptions{
		LDDocumentLoader: docLoader,
		SignerGetter:     WithKMSCryptoWrapper(kmsCrypto),
	})

	signer, err := signerInit.Signer()
	require.NoError(t, err)

	verifierInit := NewVerifierInitializer(&VerifierInitializerOptions{
		LDDocumentLoader: docLoader,
	})

	verifier, err := verifierInit.Verifier()
	require.NoError(t, err)

	p256JWK, err := kmsCrypto.Create(kmsapi.ECDSAP256IEEEP1363)
	require.NoError(t, err)

	p384JWK, err := kmsCrypto.Create(kmsapi.ECDSAP384IEEEP1363)
	require.NoError(t, err)

	p256VM, err := did.NewVerificationMethodFromJWK("#key-1", "JsonWebKey2020", "did:foo:bar", p256JWK)
	require.NoError(t, err)

	p384VM, err := did.NewVerificationMethodFromJWK("#key-2", "JsonWebKey2020", "did:foo:bar", p384JWK)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		t.Run("P-256 key", func(t *testing.T) {
			proofOpts := &models.ProofOptions{
				VerificationMethod:   p256VM,
				VerificationMethodID: p256VM.ID,
				SuiteType:            SuiteType,
				Purpose:              "assertionMethod",
				ProofType:            models.DataIntegrityProof,
				Created:              time.Now(),
				Expires:              time.Now().Add(time.Minute),
			}

			proof, err := signer.CreateProof(validCredential, proofOpts)
			require.NoError(t, err)

			err = verifier.VerifyProof(validCredential, proof, proofOpts)
			require.NoError(t, err)
		})

		t.Run("P-256 key with new Suite", func(t *testing.T) {
			proofOpts := &models.ProofOptions{
				VerificationMethod:   p256VM,
				VerificationMethodID: p256VM.ID,
				SuiteType:            SuiteTypeNew,
				Purpose:              "assertionMethod",
				ProofType:            models.DataIntegrityProof,
				Created:              time.Now(),
				Expires:              time.Now().Add(time.Minute),
			}

			proof, err := signer.CreateProof(validCredential, proofOpts)
			require.NoError(t, err)

			err = verifier.VerifyProof(validCredential, proof, proofOpts)
			require.NoError(t, err)

			require.EqualValues(t, SuiteTypeNew, proof.CryptoSuite)
		})

		t.Run("P-384 key", func(t *testing.T) {
			proofOpts := &models.ProofOptions{
				VerificationMethod:   p384VM,
				VerificationMethodID: p384VM.ID,
				SuiteType:            SuiteType,
				Purpose:              "assertionMethod",
				ProofType:            models.DataIntegrityProof,
				Created:              time.Now(),
				Expires:              time.Now().Add(time.Minute),
			}

			proof, err := signer.CreateProof(validCredential, proofOpts)
			require.NoError(t, err)

			err = verifier.VerifyProof(validCredential, proof, proofOpts)
			require.NoError(t, err)
		})
	})

	t.Run("failure", func(t *testing.T) {
		t.Run("wrong key", func(t *testing.T) {
			signOpts := &models.ProofOptions{
				VerificationMethod:   p256VM,
				VerificationMethodID: p256VM.ID,
				SuiteType:            SuiteType,
				Purpose:              "assertionMethod",
				ProofType:            models.DataIntegrityProof,
				Created:              time.Now(),
			}

			verifyOpts := &models.ProofOptions{
				VerificationMethod:   p384VM,
				VerificationMethodID: p384VM.ID,
				SuiteType:            SuiteType,
				Purpose:              "assertionMethod",
				ProofType:            models.DataIntegrityProof,
			}

			proof, err := signer.CreateProof(validCredential, signOpts)
			require.NoError(t, err)

			err = verifier.VerifyProof(validCredential, proof, verifyOpts)
			require.Error(t, err)
			require.Contains(t, err.Error(), "failed to verify ecdsa-2019 DI proof")
		})
	})
}
