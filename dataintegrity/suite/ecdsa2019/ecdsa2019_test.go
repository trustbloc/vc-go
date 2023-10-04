/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdsa2019

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	_ "embed"
	"errors"
	"testing"
	"time"

	"github.com/multiformats/go-multibase"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/did-go/doc/did"
	"github.com/trustbloc/did-go/doc/ld/documentloader"
	mockldstore "github.com/trustbloc/did-go/doc/ld/mock"
	"github.com/trustbloc/did-go/doc/ld/store"
	"github.com/trustbloc/kms-go/doc/jose/jwk"
	"github.com/trustbloc/kms-go/doc/jose/jwk/jwksupport"
	mockwrapper "github.com/trustbloc/kms-go/mock/wrapper"

	"github.com/trustbloc/vc-go/crypto-ext/pubkey"
	"github.com/trustbloc/vc-go/dataintegrity/models"
	"github.com/trustbloc/vc-go/dataintegrity/suite"
)

var (
	//go:embed testdata/valid_credential.jsonld
	validCredential []byte
	//go:embed testdata/invalid_jsonld.jsonld
	invalidJSONLD []byte
)

const (
	fooBar = "foo bar"
)

func TestNew(t *testing.T) {
	docLoader, err := documentloader.NewDocumentLoader(createMockProvider())
	require.NoError(t, err)

	kc := &mockwrapper.MockKMSCrypto{}

	signerGetter := WithKMSCryptoWrapper(kc)

	t.Run("signer success", func(t *testing.T) {
		sigInit := NewSignerInitializer(&SignerInitializerOptions{
			LDDocumentLoader: docLoader,
			SignerGetter:     signerGetter,
		})

		signer, err := sigInit.Signer()
		require.NoError(t, err)
		require.NotNil(t, signer)
		require.False(t, signer.RequiresCreated())
	})

	t.Run("verifier success", func(t *testing.T) {
		verInit := NewVerifierInitializer(&VerifierInitializerOptions{
			LDDocumentLoader: docLoader,
		})

		verifier, err := verInit.Verifier()
		require.NoError(t, err)
		require.NotNil(t, verifier)
		require.False(t, verifier.RequiresCreated())
	})
}

type testCase struct {
	signer       *mockwrapper.MockKMSCrypto
	docLoader    *documentloader.DocumentLoader
	proofOpts    *models.ProofOptions
	proof        *models.Proof
	p256Verifier Verifier
	p384Verifier Verifier
	document     []byte
	errIs        error
	errStr       string
}

func successCase(t *testing.T) *testCase {
	t.Helper()

	_, mockVM := getVMWithJWK(t)

	docLoader, err := documentloader.NewDocumentLoader(createMockProvider())
	require.NoError(t, err)

	signer := &mockwrapper.MockKMSCrypto{}

	proofCreated := time.Now()

	proofOpts := &models.ProofOptions{
		VerificationMethod:   mockVM,
		VerificationMethodID: mockVM.ID,
		SuiteType:            SuiteType,
		Purpose:              "assertionMethod",
		ProofType:            models.DataIntegrityProof,
		Created:              proofCreated,
		MaxAge:               100,
	}

	mockSig, err := multibase.Encode(multibase.Base58BTC, []byte("mock signature"))
	require.NoError(t, err)

	proof := &models.Proof{
		Type:               models.DataIntegrityProof,
		CryptoSuite:        SuiteType,
		ProofPurpose:       "assertionMethod",
		VerificationMethod: mockVM.ID,
		Created:            proofCreated.Format(models.DateTimeFormat),
		ProofValue:         mockSig,
	}

	return &testCase{
		signer:    signer,
		docLoader: docLoader,
		proofOpts: proofOpts,
		proof:     proof,
		document:  validCredential,
		errIs:     nil,
		errStr:    "",
	}
}

func testSign(t *testing.T, tc *testCase) {
	sigInit := NewSignerInitializer(&SignerInitializerOptions{
		LDDocumentLoader: tc.docLoader,
		SignerGetter:     WithKMSCryptoWrapper(tc.signer),
	})

	signer, err := sigInit.Signer()
	require.NoError(t, err)

	proof, err := signer.CreateProof(tc.document, tc.proofOpts)

	if tc.errStr == "" && tc.errIs == nil {
		require.NoError(t, err)
		require.NotNil(t, proof)
	} else {
		require.Error(t, err)
		require.Nil(t, proof)

		if tc.errStr != "" {
			require.Contains(t, err.Error(), tc.errStr)
		}

		if tc.errIs != nil {
			require.ErrorIs(t, err, tc.errIs)
		}
	}
}

type mockVerifier struct {
	err error
}

func (mv *mockVerifier) Verify(_, _ []byte, _ *pubkey.PublicKey) error {
	return mv.err
}

func testVerify(t *testing.T, tc *testCase) {
	verInit := NewVerifierInitializer(&VerifierInitializerOptions{
		LDDocumentLoader: tc.docLoader,
		P256Verifier:     tc.p256Verifier,
		P384Verifier:     tc.p384Verifier,
	})

	verifier, err := verInit.Verifier()
	require.NoError(t, err)

	err = verifier.VerifyProof(tc.document, tc.proof, tc.proofOpts)

	if tc.errStr == "" && tc.errIs == nil {
		require.NoError(t, err)
	} else {
		require.Error(t, err)

		if tc.errStr != "" {
			require.Contains(t, err.Error(), tc.errStr)
		}

		if tc.errIs != nil {
			require.ErrorIs(t, err, tc.errIs)
		}
	}
}

func TestSuite_CreateProof(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		t.Run("P-256 key", func(t *testing.T) {
			tc := successCase(t)

			testSign(t, tc)
		})

		t.Run("P-384 key", func(t *testing.T) {
			tc := successCase(t)

			tc.proofOpts.VerificationMethod = getP384VM(t)

			testSign(t, tc)
		})
	})

	t.Run("failure", func(t *testing.T) {
		t.Run("signer sign error", func(t *testing.T) {
			tc := successCase(t)

			errExpected := errors.New("expected error")

			tc.signer.SignErr = errExpected
			tc.errIs = errExpected

			testSign(t, tc)
		})
	})
}

func TestSuite_VerifyProof(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		t.Run("P-256 key", func(t *testing.T) {
			tc := successCase(t)
			tc.p256Verifier = &mockVerifier{}
			tc.p384Verifier = &mockVerifier{err: errors.New("some error")}

			testVerify(t, tc)
		})

		t.Run("P-384 key", func(t *testing.T) {
			tc := successCase(t)

			tc.p256Verifier = &mockVerifier{err: errors.New("some error")}
			tc.p384Verifier = &mockVerifier{}
			tc.proofOpts.VerificationMethod = getP384VM(t)

			testVerify(t, tc)
		})
	})

	t.Run("failure", func(t *testing.T) {
		t.Run("decode proof signature", func(t *testing.T) {
			tc := successCase(t)

			tc.proof.ProofValue = "!%^@^@#%&#%#@"
			tc.errStr = "decoding proofValue"

			testVerify(t, tc)
		})

		t.Run("crypto verify", func(t *testing.T) {
			tc := successCase(t)

			errExpected := errors.New("expected error")

			tc.p256Verifier = &mockVerifier{err: errExpected}
			tc.errIs = errExpected

			testVerify(t, tc)
		})
	})
}

func TestSharedFailures(t *testing.T) {
	t.Run("unmarshal doc", func(t *testing.T) {
		tc := successCase(t)

		tc.document = []byte("not JSON!")
		tc.errStr = "expects JSON-LD payload"

		testSign(t, tc)
	})

	t.Run("no jwk in vm", func(t *testing.T) {
		tc := successCase(t)

		tc.proofOpts.VerificationMethod = &did.VerificationMethod{
			ID:    tc.proofOpts.VerificationMethodID,
			Value: []byte(fooBar),
		}
		tc.errStr = "verification method needs JWK"

		testSign(t, tc)
	})

	t.Run("unsupported ECDSA curve", func(t *testing.T) {
		tc := successCase(t)

		badKey, vm := getVMWithJWK(t)

		badKey.Crv = fooBar

		tc.proofOpts.VerificationMethod = vm
		tc.errStr = "unsupported ECDSA curve"

		testVerify(t, tc)
	})

	t.Run("invalid proof/suite type", func(t *testing.T) {
		tc := successCase(t)

		tc.proofOpts.ProofType = fooBar
		tc.errIs = suite.ErrProofTransformation

		testSign(t, tc)

		tc.proofOpts.ProofType = models.DataIntegrityProof
		tc.proofOpts.SuiteType = fooBar

		testSign(t, tc)
	})

	t.Run("canonicalize doc", func(t *testing.T) {
		tc := successCase(t)

		tc.document = invalidJSONLD
		tc.errStr = "canonicalizing signature base data"

		testSign(t, tc)
	})
}

func getVMWithJWK(t *testing.T) (*jwk.JWK, *models.VerificationMethod) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jwkPriv, err := jwksupport.JWKFromKey(priv)
	require.NoError(t, err)

	mockVM, err := did.NewVerificationMethodFromJWK("#key-1", "JsonWebKey2020", "did:foo:bar", jwkPriv)
	require.NoError(t, err)

	return jwkPriv, mockVM
}

func getP384VM(t *testing.T) *models.VerificationMethod {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	jwkPriv, err := jwksupport.JWKFromKey(priv)
	require.NoError(t, err)

	mockVM, err := did.NewVerificationMethodFromJWK("#key-1", "JsonWebKey2020", "did:foo:bar", jwkPriv)
	require.NoError(t, err)

	return mockVM
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
