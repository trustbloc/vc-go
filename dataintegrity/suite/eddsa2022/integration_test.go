package eddsa2022

import (
	_ "embed"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/did-go/doc/did"
	"github.com/trustbloc/did-go/doc/ld/documentloader"
	mockldstore "github.com/trustbloc/did-go/doc/ld/mock"
	"github.com/trustbloc/did-go/doc/ld/store"
	kmsapi "github.com/trustbloc/kms-go/spi/kms"

	"github.com/trustbloc/vc-go/dataintegrity/models"
	"github.com/trustbloc/vc-go/internal/testutil/kmscryptoutil"
)

var (
	//go:embed testdata/valid_credential.jsonld
	validCredential []byte
	//go:embed testdata/invalid_jsonld.jsonld
	invalidJSONLD []byte
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

	ed25519JWK, err := kmsCrypto.Create(kmsapi.ED25519)
	require.NoError(t, err)

	ed25519VM, err := did.NewVerificationMethodFromJWK("#key-1", "JsonWebKey2020", "did:foo:bar", ed25519JWK)
	require.NoError(t, err)

	ed25519JWK2, err := kmsCrypto.Create(kmsapi.ED25519)
	require.NoError(t, err)

	ed25519VM2, err := did.NewVerificationMethodFromJWK("#key-1", "JsonWebKey2020", "did:foo:bar", ed25519JWK2)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		t.Run("ED25519 key", func(t *testing.T) {
			proofOpts := &models.ProofOptions{
				VerificationMethod:   ed25519VM,
				VerificationMethodID: ed25519VM.ID,
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
				VerificationMethod:   ed25519VM,
				VerificationMethodID: ed25519VM.ID,
				SuiteType:            SuiteType,
				Purpose:              "assertionMethod",
				ProofType:            models.DataIntegrityProof,
				Created:              time.Now(),
				Expires:              time.Now().Add(time.Minute),
			}

			verifyOpts := &models.ProofOptions{
				VerificationMethod:   ed25519VM2,
				VerificationMethodID: ed25519VM2.ID,
				SuiteType:            SuiteType,
				Purpose:              "assertionMethod",
				ProofType:            models.DataIntegrityProof,
			}

			proof, err := signer.CreateProof(validCredential, signOpts)
			require.NoError(t, err)

			err = verifier.VerifyProof(validCredential, proof, verifyOpts)
			require.Error(t, err)
			require.Contains(t, err.Error(), "failed to verify eddsa-2022 DI proof")
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
