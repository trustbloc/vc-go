package kmscrypto

import (
	"github.com/trustbloc/kms-go/doc/jose/jwk"
	"github.com/trustbloc/kms-go/doc/jose/jwk/jwksupport"
	"github.com/trustbloc/kms-go/spi/kms"
)

type kmsCryptoImpl struct {
	kms keyManager
	cr  signerVerifier
}

func (k *kmsCryptoImpl) Create(keyType kms.KeyType) (*jwk.JWK, error) {
	kid, pkBytes, err := k.kms.CreateAndExportPubKeyBytes(keyType)
	if err != nil {
		return nil, err
	}

	pk, err := jwksupport.PubKeyBytesToJWK(pkBytes, keyType)
	if err != nil {
		return nil, err
	}

	pk.KeyID = kid

	return pk, nil
}

func (k *kmsCryptoImpl) Sign(msg []byte, pub *jwk.JWK) ([]byte, error) {
	kh, err := k.kms.Get(pub.KeyID)
	if err != nil {
		return nil, err
	}

	return k.cr.Sign(msg, kh)
}

func getKeyHandle(pub *jwk.JWK, keyManager keyHandleFetcher) (interface{}, error) {
	var (
		pkb []byte
		kt  kms.KeyType
		err error
	)

	pkb, kt, err = keyManager.ExportPubKeyBytes(pub.KeyID)
	if err != nil {
		pkb, err = pub.PublicKeyBytes()
		if err != nil {
			return nil, err
		}

		kt, err = pub.KeyType()
		if err != nil {
			return nil, err
		}
	}

	kh, err := keyManager.PubKeyBytesToHandle(pkb, kt)
	if err != nil {
		return nil, err
	}

	return kh, nil
}

func (k *kmsCryptoImpl) Verify(sig, msg []byte, pub *jwk.JWK) error {
	kh, err := getKeyHandle(pub, k.kms)
	if err != nil {
		return err
	}

	return k.cr.Verify(sig, msg, kh)
}

func (k *kmsCryptoImpl) FixedKeyCrypto(pub *jwk.JWK) (FixedKeyCrypto, error) {
	sigKH, err := k.kms.Get(pub.KeyID)
	if err != nil {
		return nil, err
	}

	verKH, err := getKeyHandle(pub, k.kms)
	if err != nil {
		return nil, err
	}

	return &fixedKeyImpl{
		cr:    k.cr,
		sigKH: sigKH,
		verKH: verKH,
	}, nil
}

func (k *kmsCryptoImpl) FixedKeySigner(pub *jwk.JWK) (FixedKeySigner, error) {
	kh, err := k.kms.Get(pub.KeyID)
	if err != nil {
		return nil, err
	}

	return &fixedKeySignerImpl{
		cr: k.cr,
		kh: kh,
	}, nil
}

type fixedKeyImpl struct {
	cr    signerVerifier
	sigKH interface{}
	verKH interface{}
}

func (f *fixedKeyImpl) Sign(msg []byte) ([]byte, error) {
	return f.cr.Sign(msg, f.sigKH)
}

func (f *fixedKeyImpl) Verify(sig, msg []byte) error {
	return f.cr.Verify(sig, msg, f.verKH)
}
