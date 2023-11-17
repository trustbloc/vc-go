/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package testsupport

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/bbs-signature-go/bbs12381g2pub"
	"github.com/trustbloc/kms-go/doc/jose/jwk"
	"github.com/trustbloc/kms-go/doc/jose/jwk/jwksupport"
	kmsapi "github.com/trustbloc/kms-go/spi/kms"
	wrapperapi "github.com/trustbloc/kms-go/wrapper/api"

	"github.com/trustbloc/vc-go/crypto-ext/testutil"
	vered25519 "github.com/trustbloc/vc-go/crypto-ext/verifiers/ed25519"
	rsaver "github.com/trustbloc/vc-go/crypto-ext/verifiers/rsa"
	"github.com/trustbloc/vc-go/internal/testutil/kmscryptoutil"
	"github.com/trustbloc/vc-go/proof/checker"
	"github.com/trustbloc/vc-go/proof/creator"
	"github.com/trustbloc/vc-go/proof/defaults"
	"github.com/trustbloc/vc-go/proof/jwtproofs/eddsa"
	"github.com/trustbloc/vc-go/proof/jwtproofs/es256"
	"github.com/trustbloc/vc-go/proof/jwtproofs/es256k"
	"github.com/trustbloc/vc-go/proof/jwtproofs/es384"
	"github.com/trustbloc/vc-go/proof/jwtproofs/es521"
	"github.com/trustbloc/vc-go/proof/jwtproofs/ps256"
	"github.com/trustbloc/vc-go/proof/jwtproofs/rs256"
	"github.com/trustbloc/vc-go/proof/ldproofs/bbsblssignature2020"
	"github.com/trustbloc/vc-go/proof/ldproofs/ecdsasecp256k1signature2019"
	"github.com/trustbloc/vc-go/proof/ldproofs/ed25519signature2018"
	"github.com/trustbloc/vc-go/proof/ldproofs/ed25519signature2020"
	"github.com/trustbloc/vc-go/proof/ldproofs/jsonwebsignature2020"
	"github.com/trustbloc/vc-go/vermethod"
)

const (
	// AnyPubKeyID indicated that proof checker should ignore pub key id when looking for verification method.
	AnyPubKeyID = "anyID"
)

// VMResolver mock verification method resolver.
type VMResolver struct {
	mockedVerificationMethods []mockedVerificationMethod
	expectedIssuer            string
}

type mockedVerificationMethod struct {
	lookupID                string
	verificationMethodValue *vermethod.VerificationMethod
}

type cryptographicSigner interface {
	// Sign will sign document and return signature.
	Sign(data []byte) ([]byte, error)
}

// NewSingleKeyResolver creates vm resolver with single key embedded.
func NewSingleKeyResolver(lookupID string, keyBytes []byte, keyType string, expectedProofIssuer string) *VMResolver {
	return &VMResolver{
		expectedIssuer: expectedProofIssuer,
		mockedVerificationMethods: []mockedVerificationMethod{{
			lookupID:                lookupID,
			verificationMethodValue: &vermethod.VerificationMethod{Type: keyType, Value: keyBytes},
		}},
	}
}

// NewSingleJWKResolver creates vm resolver with single jwk embedded.
func NewSingleJWKResolver(lookupID string, j *jwk.JWK, keyType string, expectedProofIssuer string) *VMResolver {
	return &VMResolver{
		expectedIssuer: expectedProofIssuer,
		mockedVerificationMethods: []mockedVerificationMethod{{
			lookupID:                lookupID,
			verificationMethodValue: &vermethod.VerificationMethod{Type: keyType, JWK: j},
		}},
	}
}

// ResolveVerificationMethod resolves verification method.
func (r *VMResolver) ResolveVerificationMethod(
	verificationMethod string,
	expectedKeyController string,
) (*vermethod.VerificationMethod, error) {
	if r.expectedIssuer != "" && r.expectedIssuer != expectedKeyController {
		return nil, fmt.Errorf("invalid issuer. expected %q got %q",
			r.expectedIssuer, expectedKeyController)
	}
	for _, mocked := range r.mockedVerificationMethods {
		if mocked.lookupID == AnyPubKeyID {
			return mocked.verificationMethodValue, nil
		}

		checkingIssuer := r.expectedIssuer
		if checkingIssuer == "" {
			checkingIssuer = strings.Split(mocked.lookupID, "#")[0]
		}

		if mocked.lookupID == verificationMethod && expectedKeyController == checkingIssuer {
			return mocked.verificationMethodValue, nil
		}
	}

	return nil, fmt.Errorf("%q not supports %q verification method (key id) ",
		expectedKeyController,
		verificationMethod)
}

// NewEd25519Pair returns a pair of proof creator and checker.
func NewEd25519Pair(pubKey ed25519.PublicKey, privKey ed25519.PrivateKey,
	publicKeyID string) (*creator.ProofCreator, *checker.ProofChecker) {
	proofCreator :=
		creator.New(
			creator.WithLDProofType(jsonwebsignature2020.New(), testutil.NewEd25519Signer(privKey)),
			creator.WithLDProofType(ed25519signature2018.New(), testutil.NewEd25519Signer(privKey)),
			creator.WithLDProofType(ed25519signature2020.New(), testutil.NewEd25519Signer(privKey)),
			creator.WithJWTAlg(eddsa.New(), testutil.NewEd25519Signer(privKey)))

	resolver := &VMResolver{
		mockedVerificationMethods: []mockedVerificationMethod{{
			lookupID: publicKeyID,
			verificationMethodValue: &vermethod.VerificationMethod{
				Type:  "Ed25519VerificationKey2018",
				Value: pubKey,
			}}, {
			lookupID: publicKeyID,
			verificationMethodValue: &vermethod.VerificationMethod{
				Type:  "Ed25519VerificationKey2020",
				Value: pubKey,
			}},
		},
	}

	return proofCreator, defaults.NewDefaultProofChecker(resolver)
}

// Ed25519SignKey describe ed25519 sig verify key.
type Ed25519SignKey struct {
	PubKey      ed25519.PublicKey
	PrivKey     ed25519.PrivateKey
	PublicKeyID string
}

// NewEd25519Pairs returns a pair of proof creator and checker.
func NewEd25519Pairs(sigKeys []Ed25519SignKey) (
	[]*creator.ProofCreator, *checker.ProofChecker) {
	var (
		creators                  []*creator.ProofCreator
		mockedVerificationMethods []mockedVerificationMethod
	)

	for _, sigKey := range sigKeys {
		proofCreator :=
			creator.New(
				creator.WithLDProofType(jsonwebsignature2020.New(), testutil.NewEd25519Signer(sigKey.PrivKey)),
				creator.WithLDProofType(ed25519signature2020.New(), testutil.NewEd25519Signer(sigKey.PrivKey)),
				creator.WithLDProofType(ed25519signature2018.New(), testutil.NewEd25519Signer(sigKey.PrivKey)),
				creator.WithJWTAlg(eddsa.New(), testutil.NewEd25519Signer(sigKey.PrivKey)))
		creators = append(creators, proofCreator)

		vms := []mockedVerificationMethod{
			{
				lookupID: sigKey.PublicKeyID,
				verificationMethodValue: &vermethod.VerificationMethod{
					Type:  "Ed25519VerificationKey2018",
					Value: sigKey.PubKey,
				},
			},
			{
				lookupID: sigKey.PublicKeyID,
				verificationMethodValue: &vermethod.VerificationMethod{
					Type:  "Ed25519VerificationKey2020",
					Value: sigKey.PubKey,
				},
			},
		}

		mockedVerificationMethods = append(mockedVerificationMethods, vms...)
	}

	return creators, defaults.NewDefaultProofChecker(
		&VMResolver{mockedVerificationMethods: mockedVerificationMethods})
}

// NewEd25519Verifier returns ed25519 verifier.
func NewEd25519Verifier(pubKey ed25519.PublicKey) *checker.EmbeddedVMProofChecker {
	return checker.NewEmbeddedVMProofChecker(
		&vermethod.VerificationMethod{Type: "Ed25519VerificationKey2018", Value: pubKey},
		checker.WithSignatureVerifiers(vered25519.New()),
		checker.WithLDProofTypes(
			ed25519signature2018.New(),
			ed25519signature2020.New(),
			jsonwebsignature2020.New(),
		),
		checker.WithJWTAlg(eddsa.New()),
	)
}

// NewRSA256Pair returns a pair of proof creator and checker.
func NewRSA256Pair(privKey *rsa.PrivateKey, publicKeyID string) (*creator.ProofCreator, *checker.ProofChecker) {
	pubKey := &privKey.PublicKey

	proofCreator :=
		creator.New(
			creator.WithJWTAlg(rs256.New(), testutil.NewRS256Signer(privKey)))

	resolver := &VMResolver{
		mockedVerificationMethods: []mockedVerificationMethod{{
			lookupID: publicKeyID,
			verificationMethodValue: &vermethod.VerificationMethod{
				Type:  "RsaVerificationKey2018",
				Value: x509.MarshalPKCS1PublicKey(pubKey),
			}},
		},
	}

	return proofCreator, defaults.NewDefaultProofChecker(resolver)
}

// NewRS256Verifier returns rsa rs verifier.
func NewRS256Verifier(pubKey *rsa.PublicKey) *checker.EmbeddedVMProofChecker {
	return checker.NewEmbeddedVMProofChecker(
		&vermethod.VerificationMethod{Type: "RsaVerificationKey2018", Value: x509.MarshalPKCS1PublicKey(pubKey)},
		checker.WithSignatureVerifiers(rsaver.NewRS256()),
		checker.WithLDProofTypes(
			jsonwebsignature2020.New(),
		),
		checker.WithJWTAlg(rs256.New()),
	)
}

// NewKMSSigVerPair returns a pair of proof creator and checker.
func NewKMSSigVerPair(t *testing.T, keyType kmsapi.KeyType, verificationKeyID string) (
	*creator.ProofCreator, *checker.ProofChecker) {
	t.Helper()

	proofCreators, proofChecker := NewKMSSignersAndVerifier(t, []SigningKey{{
		Type:        keyType,
		PublicKeyID: verificationKeyID,
	}})

	return proofCreators[0], proofChecker
}

// SigningKey server key for creating proof creator and proof checker.
type SigningKey struct {
	Type        kmsapi.KeyType
	PublicKeyID string
	VMType      string
}

// NewKMSSignersAndVerifier returns a pair of proof creator and checker.
func NewKMSSignersAndVerifier(t *testing.T, signingKeys []SigningKey) (
	[]*creator.ProofCreator, *checker.ProofChecker) {
	t.Helper()

	creators, checkers, err := NewKMSSignersAndVerifierErr(signingKeys)
	require.NoError(t, err)

	return creators, checkers
}

// NewKMSSignersAndVerifierErr returns a pair of proof creator and checker.
//
//nolint:gocyclo
func NewKMSSignersAndVerifierErr(signingKeys []SigningKey) (
	[]*creator.ProofCreator, *checker.ProofChecker, error) {
	kmsCrypto, err := kmscryptoutil.LocalKMSCryptoErr()
	if err != nil {
		return nil, nil, err
	}

	var (
		creators                  []*creator.ProofCreator
		mockedVerificationMethods []mockedVerificationMethod
	)

	for _, sigKey := range signingKeys {
		var (
			proofCreator *creator.ProofCreator
			mocked       mockedVerificationMethod
		)

		switch sigKey.Type {
		case kmsapi.RSARS256:
			proofCreator, mocked, err = rsa256PairDesc(sigKey.PublicKeyID)
			if err != nil {
				return nil, nil, err
			}

		case kmsapi.ECDSASecp256k1TypeIEEEP1363:
			proofCreator, mocked, err = ecdsaSecp256k1PairDesc(sigKey.PublicKeyID,
				sigKey.VMType == "" || sigKey.VMType == "JsonWebKey2020")
			if err != nil {
				return nil, nil, err
			}

		case kmsapi.BLS12381G2Type:
			proofCreator, mocked, err = bbsPairDesc(sigKey.PublicKeyID)
			if err != nil {
				return nil, nil, err
			}

		default:
			proofCreator, mocked, err = kmsPairDesc(kmsCrypto, sigKey)
			if err != nil {
				return nil, nil, err
			}
		}

		creators = append(creators, proofCreator)
		mockedVerificationMethods = append(mockedVerificationMethods, mocked)
	}

	return creators, defaults.NewDefaultProofChecker(
		&VMResolver{mockedVerificationMethods: mockedVerificationMethods}), nil
}

func rsa256PairDesc(publicKeyID string) (*creator.ProofCreator, mockedVerificationMethod, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, mockedVerificationMethod{}, err
	}

	pubKey := &privKey.PublicKey

	proofCreator :=
		creator.New(
			creator.WithJWTAlg(rs256.New(), testutil.NewRS256Signer(privKey)))

	vm := mockedVerificationMethod{
		lookupID: publicKeyID,
		verificationMethodValue: &vermethod.VerificationMethod{
			Type:  "RsaVerificationKey2018",
			Value: x509.MarshalPKCS1PublicKey(pubKey),
		},
	}

	return proofCreator, vm, nil
}

func bbsPairDesc(publicKeyID string) (*creator.ProofCreator, mockedVerificationMethod, error) {
	publicKey, privateKey, err := bbs12381g2pub.GenerateKeyPair(sha256.New, nil)
	if err != nil {
		return nil, mockedVerificationMethod{}, err
	}

	srcPublicKey, err := publicKey.Marshal()
	if err != nil {
		return nil, mockedVerificationMethod{}, err
	}

	signer, err := testutil.NewBBSSigner(privateKey)
	if err != nil {
		return nil, mockedVerificationMethod{}, err
	}

	proofCreator :=
		creator.New(
			creator.WithLDProofType(bbsblssignature2020.New(), signer))

	vm := mockedVerificationMethod{
		lookupID: publicKeyID,
		verificationMethodValue: &vermethod.VerificationMethod{
			Type:  "Bls12381G2Key2020",
			Value: srcPublicKey,
		},
	}

	return proofCreator, vm, nil
}

func ecdsaSecp256k1PairDesc(publicKeyID string, jwkVM bool) (*creator.ProofCreator, mockedVerificationMethod, error) {
	privKey, err := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
	if err != nil {
		return nil, mockedVerificationMethod{}, err
	}

	pubKey := &privKey.PublicKey

	proofCreator :=
		creator.New(
			creator.WithLDProofType(jsonwebsignature2020.New(), testutil.NewECDSASecp256k1Signer(privKey)),
			creator.WithLDProofType(ecdsasecp256k1signature2019.New(), testutil.NewECDSASecp256k1Signer(privKey)),
			creator.WithJWTAlg(es256k.New(), testutil.NewECDSASecp256k1Signer(privKey)))

	vm := mockedVerificationMethod{
		lookupID: publicKeyID,
		verificationMethodValue: &vermethod.VerificationMethod{
			Type:  "EcdsaSecp256k1VerificationKey2019",
			Value: elliptic.Marshal(pubKey.Curve, pubKey.X, pubKey.Y),
		},
	}

	if jwkVM {
		pubJWK, err := jwksupport.JWKFromKey(pubKey)
		if err != nil {
			return nil, mockedVerificationMethod{}, err
		}

		vm.verificationMethodValue = &vermethod.VerificationMethod{
			Type: "JsonWebKey2020",
			JWK:  pubJWK,
		}
	}

	return proofCreator, vm, nil
}

func kmsPairDesc(kmsCrypto wrapperapi.KMSCrypto,
	sigKey SigningKey) (*creator.ProofCreator, mockedVerificationMethod, error) {
	pubJWK, err := kmsCrypto.Create(sigKey.Type)
	if err != nil {
		return nil, mockedVerificationMethod{}, err
	}

	signer, err := kmsCrypto.FixedKeyCrypto(pubJWK)
	if err != nil {
		return nil, mockedVerificationMethod{}, err
	}

	proofCreator :=
		creator.New(
			creator.WithLDProofType(bbsblssignature2020.New(), signer),
			creator.WithLDProofType(ecdsasecp256k1signature2019.New(), signer),
			creator.WithLDProofType(ed25519signature2018.New(), signer),
			creator.WithLDProofType(ed25519signature2020.New(), signer),
			creator.WithLDProofType(jsonwebsignature2020.New(), signer),
			creator.WithJWTAlg(eddsa.New(), signer),
			creator.WithJWTAlg(es256.New(), signer),
			creator.WithJWTAlg(es256k.New(), signer),
			creator.WithJWTAlg(es384.New(), signer),
			creator.WithJWTAlg(es521.New(), signer),
			creator.WithJWTAlg(rs256.New(), signer),
			creator.WithJWTAlg(ps256.New(), signer))

	vm := &vermethod.VerificationMethod{
		Type: "JsonWebKey2020",
		JWK:  pubJWK,
	}

	if sigKey.VMType != "" && sigKey.VMType != "JsonWebKey2020" {
		pubKeyBytes, err := pubJWK.PublicKeyBytes()
		vm = &vermethod.VerificationMethod{
			Type:  sigKey.VMType,
			Value: pubKeyBytes,
		}

		if err != nil {
			return nil, mockedVerificationMethod{}, err
		}
	}

	mocked := mockedVerificationMethod{
		lookupID:                sigKey.PublicKeyID,
		verificationMethodValue: vm,
	}

	return proofCreator, mocked, nil
}

// NewProofCreator creates new proof creator with all supported proof types.
func NewProofCreator(signer cryptographicSigner) *creator.ProofCreator {
	return creator.New(
		creator.WithLDProofType(bbsblssignature2020.New(), signer),
		creator.WithLDProofType(ecdsasecp256k1signature2019.New(), signer),
		creator.WithLDProofType(ed25519signature2018.New(), signer),
		creator.WithLDProofType(ed25519signature2020.New(), signer),
		creator.WithLDProofType(jsonwebsignature2020.New(), signer),
		creator.WithJWTAlg(eddsa.New(), signer),
		creator.WithJWTAlg(es256.New(), signer),
		creator.WithJWTAlg(es256k.New(), signer),
		creator.WithJWTAlg(es384.New(), signer),
		creator.WithJWTAlg(es521.New(), signer),
		creator.WithJWTAlg(rs256.New(), signer),
		creator.WithJWTAlg(ps256.New(), signer))
}
