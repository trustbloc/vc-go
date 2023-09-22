// Package kmscryptoutil contains test utilities for tests using the kmscrypto wrappers.
package kmscryptoutil

import (
	"crypto"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/kms-go/crypto/tinkcrypto"
	"github.com/trustbloc/kms-go/doc/jose/jwk"
	"github.com/trustbloc/kms-go/doc/jose/jwk/jwksupport"
	"github.com/trustbloc/kms-go/kms/localkms"
	mockkms "github.com/trustbloc/kms-go/mock/kms"
	"github.com/trustbloc/kms-go/secretlock/noop"
	"github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/kms-go/wrapper"
	mockstorage "github.com/trustbloc/vc-go/legacy/mock/storage"
)

// LocalKMSCrypto creates a kmscrypto.KMSCrypto instance that uses localkms and tinkcrypto.
func LocalKMSCrypto(t *testing.T) wrapper.KMSCrypto {
	kc, err := LocalKMSCryptoErr()
	require.NoError(t, err)

	return kc
}

// LocalKMSCryptoErr creates a kmscrypto.KMSCrypto instance that uses localkms and tinkcrypto.
// This API returns error instead of expecting a test manager.
func LocalKMSCryptoErr() (wrapper.KMSCrypto, error) {
	storeProv := mockstorage.NewMockStoreProvider()

	kmsProv, err := mockkms.NewProviderForKMS(storeProv, &noop.NoLock{})
	if err != nil {
		return nil, err
	}

	kms, err := localkms.New("local-lock://custom/master/key/", kmsProv)
	if err != nil {
		return nil, err
	}

	cr, err := tinkcrypto.New()
	if err != nil {
		return nil, err
	}

	return wrapper.NewKMSCrypto(kms, cr), nil
}

// PubKeyBytesToJWK converts the given public key to a JWK.
func PubKeyBytesToJWK(t *testing.T, pubKeyBytes []byte, keyType kms.KeyType) *jwk.JWK {
	pubJWK, err := jwksupport.PubKeyBytesToJWK(pubKeyBytes, keyType)
	require.NoError(t, err)

	tp, err := pubJWK.Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	pubJWK.KeyID = base64.RawURLEncoding.EncodeToString(tp)

	return pubJWK
}
