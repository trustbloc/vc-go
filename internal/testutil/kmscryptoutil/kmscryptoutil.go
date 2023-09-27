// Package kmscryptoutil contains test utilities for tests using the kmscrypto wrappers.
package kmscryptoutil

import (
	"crypto"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/kms-go/doc/jose/jwk"
	"github.com/trustbloc/kms-go/doc/jose/jwk/jwksupport"
	"github.com/trustbloc/kms-go/kms"
	"github.com/trustbloc/kms-go/secretlock/noop"
	kmsapi "github.com/trustbloc/kms-go/spi/kms"
	wrapperapi "github.com/trustbloc/kms-go/wrapper/api"
	"github.com/trustbloc/kms-go/wrapper/localsuite"
	"github.com/trustbloc/vc-go/legacy/mock/storage"
)

// LocalKMSCrypto creates a kmscrypto.KMSCrypto instance that uses localkms and tinkcrypto.
func LocalKMSCrypto(t *testing.T) wrapperapi.KMSCrypto {
	kc, err := LocalKMSCryptoErr()
	require.NoError(t, err)

	return kc
}

// LocalKMSCryptoErr creates a kmscrypto.KMSCrypto instance that uses localkms and tinkcrypto.
//
// This API returns an error instead of needing a testing parameter.
func LocalKMSCryptoErr() (wrapperapi.KMSCrypto, error) {
	suite, err := LocalKMSCryptoSuite()
	if err != nil {
		return nil, err
	}

	return suite.KMSCrypto()
}

// LocalKMSCryptoSuite creates a kms+crypto wrapper suite that uses localkms and tinkcrypto.
func LocalKMSCryptoSuite() (wrapperapi.Suite, error) {
	p, err := kms.NewAriesProviderWrapper(storage.NewMockStoreProvider())
	if err != nil {
		return nil, err
	}

	return localsuite.NewLocalCryptoSuite("local-lock://custom/master/key/", p, &noop.NoLock{})
}

// PubKeyBytesToJWK converts the given public key to a JWK.
func PubKeyBytesToJWK(t *testing.T, pubKeyBytes []byte, keyType kmsapi.KeyType) *jwk.JWK {
	pubJWK, err := jwksupport.PubKeyBytesToJWK(pubKeyBytes, keyType)
	require.NoError(t, err)

	tp, err := pubJWK.Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	pubJWK.KeyID = base64.RawURLEncoding.EncodeToString(tp)

	return pubJWK
}
