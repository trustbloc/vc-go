package testsupport

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/kms-go/doc/jose/jwk"
	"github.com/trustbloc/kms-go/doc/jose/jwk/jwksupport"
	kmsapi "github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/kms-go/wrapper"

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
	AnyPubKeyID = "anyID"
)

type VMResolver struct {
	mockedVerificationMethods []mockedVerificationMethod
}

type mockedVerificationMethod struct {
	lookupID                string
	verificationMethodValue *vermethod.VerificationMethod
}

func NewSingleKeyResolver(lookupID string, keyBytes []byte, keyType string) *VMResolver {
	return &VMResolver{
		mockedVerificationMethods: []mockedVerificationMethod{{
			lookupID:                lookupID,
			verificationMethodValue: &vermethod.VerificationMethod{Type: keyType, Value: keyBytes},
		}},
	}
}

func NewSingleJWKResolver(lookupID string, j *jwk.JWK, keyType string) *VMResolver {
	return &VMResolver{
		mockedVerificationMethods: []mockedVerificationMethod{{
			lookupID:                lookupID,
			verificationMethodValue: &vermethod.VerificationMethod{Type: keyType, JWK: j},
		}},
	}
}

func (r *VMResolver) ResolveVerificationMethod(verificationMethod string) (*vermethod.VerificationMethod, error) {
	for _, mocked := range r.mockedVerificationMethods {
		if mocked.lookupID == AnyPubKeyID || mocked.lookupID == verificationMethod {
			return mocked.verificationMethodValue, nil
		}
	}

	return nil, fmt.Errorf("invalid verification method (key id) %s", verificationMethod)

}

func NewEd25519Pair(pubKey ed25519.PublicKey, privKey ed25519.PrivateKey, publicKeyID string) (*creator.ProofCreator, *checker.ProofChecker) {
	proofCreator :=
		creator.New(
			creator.WithProofType(jsonwebsignature2020.New(), WrapLegacySigner(NewEd25519Signer(privKey))),
			creator.WithProofType(ed25519signature2018.New(), WrapLegacySigner(NewEd25519Signer(privKey))),
			creator.WithProofType(ed25519signature2020.New(), WrapLegacySigner(NewEd25519Signer(privKey))),
			creator.WithJWTAlg(eddsa.New(), WrapLegacySigner(NewEd25519Signer(privKey))))

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

type Ed25519SignKey struct {
	PubKey      ed25519.PublicKey
	PrivKey     ed25519.PrivateKey
	PublicKeyID string
}

func NewEd25519Pairs(sigKeys []Ed25519SignKey) (
	[]*creator.ProofCreator, *checker.ProofChecker) {

	var creators []*creator.ProofCreator
	var mockedVerificationMethods []mockedVerificationMethod

	for _, sigKey := range sigKeys {
		proofCreator :=
			creator.New(
				creator.WithProofType(jsonwebsignature2020.New(), WrapLegacySigner(NewEd25519Signer(sigKey.PrivKey))),
				creator.WithProofType(ed25519signature2020.New(), WrapLegacySigner(NewEd25519Signer(sigKey.PrivKey))),
				creator.WithProofType(ed25519signature2018.New(), WrapLegacySigner(NewEd25519Signer(sigKey.PrivKey))),
				creator.WithJWTAlg(eddsa.New(), WrapLegacySigner(NewEd25519Signer(sigKey.PrivKey))))
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

func NewEd25519Verifier(pubKey ed25519.PublicKey) *checker.EmbeddedVMProofChecker {
	return checker.NewEmbeddedVMProofChecker(
		&vermethod.VerificationMethod{Type: "Ed25519VerificationKey2018", Value: pubKey},
		checker.WithSignatreVerifiers(vered25519.New()),
		checker.WithLDProofTypes(
			ed25519signature2018.New(),
			ed25519signature2020.New(),
			jsonwebsignature2020.New(),
		),
		checker.WithJWTAlg(eddsa.New()),
	)
}

func NewRSA256Pair(privKey *rsa.PrivateKey, publicKeyID string) (*creator.ProofCreator, *checker.ProofChecker) {
	pubKey := &privKey.PublicKey

	proofCreator :=
		creator.New(
			creator.WithJWTAlg(rs256.New(), WrapLegacySigner(NewRS256Signer(privKey))))

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

func NewRS256Verifier(pubKey *rsa.PublicKey) *checker.EmbeddedVMProofChecker {
	return checker.NewEmbeddedVMProofChecker(
		&vermethod.VerificationMethod{Type: "RsaVerificationKey2018", Value: x509.MarshalPKCS1PublicKey(pubKey)},
		checker.WithSignatreVerifiers(rsaver.NewRS256()),
		checker.WithLDProofTypes(
			jsonwebsignature2020.New(),
		),
		checker.WithJWTAlg(rs256.New()),
	)
}

func NewKMSSigVerPair(t *testing.T, keyType kmsapi.KeyType, verificationKeyID string) (
	*creator.ProofCreator, *checker.ProofChecker) {
	t.Helper()

	proofCreators, proofChecker := NewKMSSignersAndVerifier(t, []SigningKey{{
		Type:        keyType,
		PublicKeyID: verificationKeyID,
	}})

	return proofCreators[0], proofChecker
}

type SigningKey struct {
	Type        kmsapi.KeyType
	PublicKeyID string
	VMType      string
}

func NewKMSSignersAndVerifier(t *testing.T, signingKeys []SigningKey) (
	[]*creator.ProofCreator, *checker.ProofChecker) {
	t.Helper()

	creators, checkers, err := NewKMSSignersAndVerifierErr(signingKeys)

	require.NoError(t, err)
	return creators, checkers
}

func NewKMSSignersAndVerifierErr(signingKeys []SigningKey) (
	[]*creator.ProofCreator, *checker.ProofChecker, error) {
	kmsCrypto, err := kmscryptoutil.LocalKMSCryptoErr()
	if err != nil {
		return nil, nil, err
	}

	var creators []*creator.ProofCreator
	var mockedVerificationMethods []mockedVerificationMethod
	for _, sigKey := range signingKeys {
		var proofCreator *creator.ProofCreator
		var mocked mockedVerificationMethod

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
			creator.WithJWTAlg(rs256.New(), WrapLegacySigner(NewRS256Signer(privKey))))

	vm := mockedVerificationMethod{
		lookupID: publicKeyID,
		verificationMethodValue: &vermethod.VerificationMethod{
			Type:  "RsaVerificationKey2018",
			Value: x509.MarshalPKCS1PublicKey(pubKey),
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
			creator.WithProofType(jsonwebsignature2020.New(), NewECDSASecp256k1Signer(privKey)),
			creator.WithProofType(ecdsasecp256k1signature2019.New(), NewECDSASecp256k1Signer(privKey)),
			creator.WithJWTAlg(es256k.New(), NewECDSASecp256k1Signer(privKey)))

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

func kmsPairDesc(kmsCrypto wrapper.KMSCrypto, sigKey SigningKey) (*creator.ProofCreator, mockedVerificationMethod, error) {
	pubJWK, err := kmsCrypto.Create(sigKey.Type)
	if err != nil {
		return nil, mockedVerificationMethod{}, err
	}

	fkc, err := kmsCrypto.FixedKeyCrypto(pubJWK)
	if err != nil {
		return nil, mockedVerificationMethod{}, err
	}

	signer := WrapLegacySigner(fkc)

	proofCreator :=
		creator.New(
			creator.WithProofType(bbsblssignature2020.New(), signer),
			creator.WithProofType(ecdsasecp256k1signature2019.New(), signer),
			creator.WithProofType(ed25519signature2018.New(), signer),
			creator.WithProofType(ed25519signature2020.New(), signer),
			creator.WithProofType(jsonwebsignature2020.New(), signer),
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

type legacySigner interface {
	// Sign will sign document and return signature
	Sign(data []byte) ([]byte, error)
}

type LegacySigWrapper struct {
	legacySigner legacySigner
}

func (w *LegacySigWrapper) Sign(data []byte, _ kmsapi.KeyType) ([]byte, error) {
	return w.legacySigner.Sign(data)
}

func WrapLegacySigner(legacySigner legacySigner) *LegacySigWrapper {
	return &LegacySigWrapper{legacySigner}
}
