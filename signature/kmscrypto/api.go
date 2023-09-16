package kmscrypto

import (
	"github.com/trustbloc/kms-go/doc/jose/jwk"
	kmsapi "github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/vc-go/signature/api"
)

type signer interface {
	Sign(msg []byte, kh interface{}) ([]byte, error)
}

type verifier interface {
	Verify(signature []byte, msg []byte, kh interface{}) error
}

type signerVerifier interface {
	signer
	verifier
}

type keyGetter interface {
	Get(keyID string) (interface{}, error)
}

type keyHandleFetcher interface {
	PubKeyBytesToHandle(pubKeyBytes []byte, keyType kmsapi.KeyType, opts ...kmsapi.KeyOpts) (interface{}, error)
	ExportPubKeyBytes(keyID string) ([]byte, kmsapi.KeyType, error)
	keyGetter
}

type keyCreator interface {
	CreateAndExportPubKeyBytes(kt kmsapi.KeyType, opts ...kmsapi.KeyOpts) (string, []byte, error)
}

type keyManager interface {
	keyCreator
	keyHandleFetcher
}

// PublicKeyVerifier implements the verifier.Verifier interface.
type PublicKeyVerifier interface {
	// Verify will verify signature against public key
	Verify(pubKey *api.PublicKey, doc []byte, signature []byte) error
}

// NewPublicKeyVerifier provides a PublicKeyVerifier using the given KMSCryptoVerifier.
func NewPublicKeyVerifier(cryptoVerifier KMSCryptoVerifier) PublicKeyVerifier {
	return &pkvImpl{kcv: cryptoVerifier}
}

type pkvImpl struct {
	kcv KMSCryptoVerifier
}

func (p *pkvImpl) Verify(pubKey *api.PublicKey, doc []byte, signature []byte) error {
	return p.kcv.Verify(signature, doc, pubKey.JWK)
}

// KMSCryptoVerifier provides a signature verification interface.
type KMSCryptoVerifier interface { // nolint: golint
	Verify(sig, msg []byte, pub *jwk.JWK) error
}

// KMSCrypto provides wrapped kms and crypto operations.
type KMSCrypto interface {
	Create(keyType kmsapi.KeyType) (*jwk.JWK, error)
	Sign(msg []byte, pub *jwk.JWK) ([]byte, error)

	KMSCryptoVerifier

	FixedKeyCrypto(pub *jwk.JWK) (FixedKeyCrypto, error)
	FixedKeySigner(pub *jwk.JWK) (FixedKeySigner, error)
}

// FixedKeyCrypto provides crypto operations using a fixed key.
type FixedKeyCrypto interface {
	Sign(msg []byte) ([]byte, error)
	Verify(sig, msg []byte) error
}

// NewKMSCrypto creates a KMSCrypto instance.
func NewKMSCrypto(kms keyManager, crypto signerVerifier) KMSCrypto {
	return &kmsCryptoImpl{
		kms: kms,
		cr:  crypto,
	}
}

// KMSCryptoSigner provides signing operations.
type KMSCryptoSigner interface { // nolint: golint
	Sign(msg []byte, pub *jwk.JWK) ([]byte, error)
	FixedKeySigner(pub *jwk.JWK) (FixedKeySigner, error)
}

// FixedKeySigner provides the common signer interface, using a fixed key for each signer instance.
type FixedKeySigner interface {
	Sign(msg []byte) ([]byte, error)
}

// NewKMSCryptoSigner creates a KMSCryptoSigner using the given kms and crypto implementations.
func NewKMSCryptoSigner(kms keyGetter, crypto signer) KMSCryptoSigner {
	return &kmsCryptoSignerImpl{
		kms:    kms,
		crypto: crypto,
	}
}
