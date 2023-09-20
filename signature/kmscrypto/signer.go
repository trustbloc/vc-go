package kmscrypto

import (
	"github.com/trustbloc/kms-go/doc/jose/jwk"
)

type kmsCryptoSignerImpl struct {
	kms    keyGetter
	crypto signer
}

func (k *kmsCryptoSignerImpl) Sign(msg []byte, pub *jwk.JWK) ([]byte, error) {
	kh, err := k.kms.Get(pub.KeyID)
	if err != nil {
		return nil, err
	}

	return k.crypto.Sign(msg, kh)
}

func (k *kmsCryptoSignerImpl) FixedKeySigner(pub *jwk.JWK) (FixedKeySigner, error) {
	kh, err := k.kms.Get(pub.KeyID)
	if err != nil {
		return nil, err
	}

	return &fixedKeySignerImpl{
		cr: k.crypto,
		kh: kh,
	}, nil
}

type fixedKeySignerImpl struct {
	cr signer
	kh interface{}
}

func (f *fixedKeySignerImpl) Sign(msg []byte) ([]byte, error) {
	return f.cr.Sign(msg, f.kh)
}
