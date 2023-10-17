/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs

import (
	"encoding/base64"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	gojose "github.com/go-jose/go-jose/v3"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/did-go/doc/ld/proof"
	"github.com/trustbloc/kms-go/doc/jose/jwk"
	"github.com/trustbloc/kms-go/doc/jose/jwk/jwksupport"
	"github.com/trustbloc/kms-go/spi/kms"

	"github.com/trustbloc/vc-go/crypto-ext/pubkey"
)

func TestTransformFromBlankNodes(t *testing.T) {
	const (
		a  = "<urn:bnid:_:c14n0>"
		ae = "_:c14n0"
		b  = "<urn:bnid:_:c14n0> "
		be = "_:c14n0 "
		c  = "abcd <urn:bnid:_:c14n0> "
		ce = "abcd _:c14n0 "
		d  = "abcd <urn:bnid:_:c14n0> efgh"
		de = "abcd _:c14n0 efgh"
		e  = "abcd <urn:bnid:_:c14n23> efgh"
		ee = "abcd _:c14n23 efgh"
		f  = "abcd <urn:bnid:_:c14n> efgh"
		fe = "abcd _:c14n efgh"
		g  = ""
		ge = ""
	)

	at := transformFromBlankNode(a)
	require.Equal(t, ae, at)

	bt := transformFromBlankNode(b)
	require.Equal(t, be, bt)

	ct := transformFromBlankNode(c)
	require.Equal(t, ce, ct)

	dt := transformFromBlankNode(d)
	require.Equal(t, de, dt)

	et := transformFromBlankNode(e)
	require.Equal(t, ee, et)

	ft := transformFromBlankNode(f)
	require.Equal(t, fe, ft)

	gt := transformFromBlankNode(g)
	require.Equal(t, ge, gt)
}

//nolint:lll,goconst
func TestNewBBSG2SignatureVerifier(t *testing.T) {
	// pkBase58 from did:key:zUC724vuGvHpnCGFG1qqpXb81SiBLu3KLSqVzenwEZNPoY35i2Bscb8DLaVwHvRFs6F2NkNNXRcPWvqnPDUd9ukdjLkjZd3u9zzL4wDZDUpkPAatLDGLEYVo8kkAzuAKJQMr7N2
	pubKeyBase58 := "nEP2DEdbRaQ2r5Azeatui9MG6cj7JUHa8GD7khub4egHJREEuvj4Y8YG8w51LnhPEXxVV1ka93HpSLkVzeQuuPE1mH9oCMrqoHXAKGBsuDT1yJvj9cKgxxLCXiRRirCycki"
	pubKeyBytes := base58.Decode(pubKeyBase58)

	sigBase64 := `qPrB+1BLsVSeOo1ci8dMF+iR6aa5Q6iwV/VzXo2dw94ctgnQGxaUgwb8Hd68IiYTVabQXR+ZPuwJA//GOv1OwXRHkHqXg9xPsl8HcaXaoWERanxYClgHCfy4j76Vudr14U5AhT3v8k8f0oZD+zBIUQ==`
	sigBytes, err := base64.StdEncoding.DecodeString(sigBase64)
	require.NoError(t, err)

	// Case 16 (https://github.com/w3c-ccg/vc-http-api/pull/128)
	msg := `
_:c14n0 <http://purl.org/dc/terms/created> "2021-02-23T19:31:12Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#BbsBlsSignature2020> .
_:c14n0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:c14n0 <https://w3id.org/security#verificationMethod> <did:key:zUC724vuGvHpnCGFG1qqpXb81SiBLu3KLSqVzenwEZNPoY35i2Bscb8DLaVwHvRFs6F2NkNNXRcPWvqnPDUd9ukdjLkjZd3u9zzL4wDZDUpkPAatLDGLEYVo8kkAzuAKJQMr7N2#zUC724vuGvHpnCGFG1qqpXb81SiBLu3KLSqVzenwEZNPoY35i2Bscb8DLaVwHvRFs6F2NkNNXRcPWvqnPDUd9ukdjLkjZd3u9zzL4wDZDUpkPAatLDGLEYVo8kkAzuAKJQMr7N2> .
<did:example:b34ca6cd37bbf23> <http://schema.org/birthDate> "1958-07-17"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<did:example:b34ca6cd37bbf23> <http://schema.org/familyName> "SMITH" .
<did:example:b34ca6cd37bbf23> <http://schema.org/gender> "Male" .
<did:example:b34ca6cd37bbf23> <http://schema.org/givenName> "JOHN" .
<did:example:b34ca6cd37bbf23> <http://schema.org/image> <data:image/png;base64,iVBORw0KGgo...kJggg==> .
<did:example:b34ca6cd37bbf23> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .
<did:example:b34ca6cd37bbf23> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#PermanentResident> .
<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#birthCountry> "Bahamas" .
<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#commuterClassification> "C1" .
<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#lprCategory> "C09" .
<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#lprNumber> "999-999-999" .
<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#residentSince> "2015-01-01"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<https://issuer.oidp.uscis.gov/credentials/83627465> <http://schema.org/description> "Government of Example Permanent Resident Card." .
<https://issuer.oidp.uscis.gov/credentials/83627465> <http://schema.org/name> "Permanent Resident Card" .
<https://issuer.oidp.uscis.gov/credentials/83627465> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#PermanentResidentCard> .
<https://issuer.oidp.uscis.gov/credentials/83627465> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:b34ca6cd37bbf23> .
<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#expirationDate> "2029-12-03T12:19:52Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#issuanceDate> "2019-12-03T12:19:52Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#issuer> <did:key:zUC724vuGvHpnCGFG1qqpXb81SiBLu3KLSqVzenwEZNPoY35i2Bscb8DLaVwHvRFs6F2NkNNXRcPWvqnPDUd9ukdjLkjZd3u9zzL4wDZDUpkPAatLDGLEYVo8kkAzuAKJQMr7N2> .
`

	verifier := NewBBSG2SignatureVerifier()
	err = verifier.Verify(sigBytes, []byte(msg), &pubkey.PublicKey{
		Type:     kms.BLS12381G2Type,
		BytesKey: &pubkey.BytesKey{Bytes: pubKeyBytes},
	})

	require.NoError(t, err)

	t.Run("Success with jwk", func(t *testing.T) {
		pubJWK, jwkErr := jwksupport.PubKeyBytesToJWK(pubKeyBytes, kms.BLS12381G2Type)
		require.NoError(t, jwkErr)

		jwkErr = verifier.Verify(sigBytes, []byte(msg), &pubkey.PublicKey{
			Type: kms.BLS12381G2Type,
			JWK:  pubJWK,
		})
		require.NoError(t, jwkErr)
	})

	t.Run("invalid public key type", func(t *testing.T) {
		err = verifier.Verify(sigBytes, []byte(msg), &pubkey.PublicKey{
			Type:     kms.AES256GCM,
			BytesKey: &pubkey.BytesKey{Bytes: []byte("invalid-key")},
		})

		require.Error(t, err)
		require.ErrorContains(t, err, "unsupported key type AES256GCM")
	})

	t.Run("invalid public key bytes", func(t *testing.T) {
		err = verifier.Verify(sigBytes, []byte(msg), &pubkey.PublicKey{
			Type:     kms.BLS12381G2Type,
			BytesKey: &pubkey.BytesKey{Bytes: []byte("invalid-key")},
		})

		require.Error(t, err)
		require.ErrorContains(t, err, "invalid size of public key")
	})

	t.Run("invalid public key bytes", func(t *testing.T) {
		err = verifier.Verify(sigBytes, []byte(msg), &pubkey.PublicKey{
			Type: kms.BLS12381G2Type,
		})

		require.Error(t, err)
		require.ErrorContains(t, err, "incorrect pub key, should contain key bytes or jwk")
	})

	t.Run("invalid public key type", func(t *testing.T) {
		err = verifier.Verify(sigBytes, []byte(msg), &pubkey.PublicKey{
			Type: kms.BLS12381G2Type,
			JWK: &jwk.JWK{
				JSONWebKey: gojose.JSONWebKey{
					Key: "foo",
				},
				Kty: "EC",
				Crv: "BLS12381_G2",
			},
		})
		require.Error(t, err)
		require.ErrorContains(t, err, "invalid jwk")
	})
}

//nolint:lll
func TestNewBBSG2SignatureProofVerifier(t *testing.T) {
	// pkBase58 from did:key:zUC724vuGvHpnCGFG1qqpXb81SiBLu3KLSqVzenwEZNPoY35i2Bscb8DLaVwHvRFs6F2NkNNXRcPWvqnPDUd9ukdjLkjZd3u9zzL4wDZDUpkPAatLDGLEYVo8kkAzuAKJQMr7N2
	pubKeyBase58 := "nEP2DEdbRaQ2r5Azeatui9MG6cj7JUHa8GD7khub4egHJREEuvj4Y8YG8w51LnhPEXxVV1ka93HpSLkVzeQuuPE1mH9oCMrqoHXAKGBsuDT1yJvj9cKgxxLCXiRRirCycki"
	pubKeyBytes := base58.Decode(pubKeyBase58)

	sigBase64 := "ABgA/wYfjSxZz8DBQHTIuX+F0MmeskKbywg6NSMGHOqJ9LvYrfaakmMaPh+UsJxIK1z5v3NuiRP4OGhIbYgjo0KovKMZzluSzCGwzAyXui2hnFlrySj3RP+WNmWd+6QZQ6bEm+pyhNC6VrEMVDxJ2TH7DShbx6GFQ6RLvuS0Xf38GuOhX26+5RJ9RBs5Qaj4/UKsTfc9AAAAdKGdxxloz3ZJ2QnoFlqicO6MviT8yzeyf5gILHg8YUjNIAVJJNsh26kBqIdQkaROpQAAAAIVX5Y1Jy9hgEQgqUld/aGN2uxOLZAJsri9BRRHoFNWkkcF73EV4BE9+Hs+8fuvX0SNDAmomTVz6vSrq58bjHZ+tmJ5JddwT1tCunHV330hqleI47eAqwGuY9hdeSixzfL0/CGnZ2XoV2YAybVTcupSAAAACw03E8CoLBvqXeMV7EtRTwMpKQmEUyAM5iwC2ZaAkDLnFOt2iHR4P8VExFmOZCl94gt6bqWuODhJ5mNCJXjEO9wmx3RNM5prB7Au5g59mdcuuY/GCKmKNt087BoHYG//dEFi4Q+bRpVE5MKaGv/JZd/LmPAfKfuj5Tr37m0m3hx6HROmIv0yHcakQlNQqM6QuRQLMr2U+nj4U4OFQZfMg3A+f6fVS6T18WLq4xbHc/2L1bYhIw+SjXwkj20cGhEBsmFOqj4oY5AzjN1t4gfzb5itxQNkZFVE2IdBP9v/Ck8rMQLmxs68PDPcp6CAb9dvMS0fX5CTTbJHqG4XEjYRaBVG0Ji5g3vTpGVAA4jqOzpTbxKQawA4SvddV8NUUm4N/zCeWMermi3yRhZRl1AXa8BqGO+mXNI7yAPjn1YDoGliQkoQc5B4CYY/5ldP19XS2hV5Ak16AJtD4tdeqbaX0bo="
	sigBytes, err := base64.StdEncoding.DecodeString(sigBase64)
	require.NoError(t, err)

	// Case 17 (https://github.com/w3c-ccg/vc-http-api/pull/128)
	msg := `
_:c14n0 <http://purl.org/dc/terms/created> "2021-02-23T19:31:12Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#BbsBlsSignature2020> .
_:c14n0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:c14n0 <https://w3id.org/security#verificationMethod> <did:key:zUC724vuGvHpnCGFG1qqpXb81SiBLu3KLSqVzenwEZNPoY35i2Bscb8DLaVwHvRFs6F2NkNNXRcPWvqnPDUd9ukdjLkjZd3u9zzL4wDZDUpkPAatLDGLEYVo8kkAzuAKJQMr7N2#zUC724vuGvHpnCGFG1qqpXb81SiBLu3KLSqVzenwEZNPoY35i2Bscb8DLaVwHvRFs6F2NkNNXRcPWvqnPDUd9ukdjLkjZd3u9zzL4wDZDUpkPAatLDGLEYVo8kkAzuAKJQMr7N2> .
<did:example:b34ca6cd37bbf23> <http://schema.org/birthDate> "1958-07-17"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<did:example:b34ca6cd37bbf23> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .
<did:example:b34ca6cd37bbf23> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#PermanentResident> .
<https://issuer.oidp.uscis.gov/credentials/83627465> <http://schema.org/description> "Government of Example Permanent Resident Card." .
<https://issuer.oidp.uscis.gov/credentials/83627465> <http://schema.org/name> "Permanent Resident Card" .
<https://issuer.oidp.uscis.gov/credentials/83627465> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#PermanentResidentCard> .
<https://issuer.oidp.uscis.gov/credentials/83627465> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:b34ca6cd37bbf23> .
<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#expirationDate> "2029-12-03T12:19:52Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#issuanceDate> "2019-12-03T12:19:52Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#issuer> <did:key:zUC724vuGvHpnCGFG1qqpXb81SiBLu3KLSqVzenwEZNPoY35i2Bscb8DLaVwHvRFs6F2NkNNXRcPWvqnPDUd9ukdjLkjZd3u9zzL4wDZDUpkPAatLDGLEYVo8kkAzuAKJQMr7N2> .
`

	nonceBytes, err := base64.StdEncoding.DecodeString("G/hn9Ca9bIWZpJGlhnr/41r8RB0OO0TLChZASr3QJVztdri/JzS8Zf/xWJT5jW78zlM=")
	require.NoError(t, err)

	verifier := NewBBSG2SignatureProofVerifier()
	err = verifier.Verify(sigBytes, []byte(msg), &pubkey.PublicKey{
		Type:     kms.BLS12381G2Type,
		BytesKey: &pubkey.BytesKey{Bytes: pubKeyBytes},
	}, &proof.Proof{Nonce: nonceBytes})

	require.NoError(t, err)
}

//nolint:lll
func TestNewBBSG2SignatureProofVerifierCase19(t *testing.T) {
	// pkBase58 from did:key:zUC724vuGvHpnCGFG1qqpXb81SiBLu3KLSqVzenwEZNPoY35i2Bscb8DLaVwHvRFs6F2NkNNXRcPWvqnPDUd9ukdjLkjZd3u9zzL4wDZDUpkPAatLDGLEYVo8kkAzuAKJQMr7N2
	pubKeyBase58 := "nEP2DEdbRaQ2r5Azeatui9MG6cj7JUHa8GD7khub4egHJREEuvj4Y8YG8w51LnhPEXxVV1ka93HpSLkVzeQuuPE1mH9oCMrqoHXAKGBsuDT1yJvj9cKgxxLCXiRRirCycki"
	pubKeyBytes := base58.Decode(pubKeyBase58)

	sigBase64 := "AAwP/4nFun/RtaXtUVTppUimMRTcEROs3gbjh9iqjGQAsvD+ne2uzME26gY4zNBcMKpvyLD4I6UGm8ATKLQI4OUiBXHNCQZI4YEM5hWI7AzhFXLEEVDFL0Gzr4S04PvcJsmV74BqST8iI1HUO2TCjdT1LkhgPabP/Zy8IpnbWUtLZO1t76NFwCV8+R1YpOozTNKRQQAAAHSpyGry6Rx3PRuOZUeqk4iGFq67iHSiBybjo6muud7aUyCxd9AW3onTlV2Nxz8AJD0AAAACB3FmuAUcklAj5cdSdw7VY57y7p4VmfPCKaEp1SSJTJRZXiE2xUqDntend+tkq+jjHhLCk56zk5GoZzr280IeuLne4WgpB2kNN7n5dqRpy4+UkS5+kiorLtKiJuWhk+OFTiB8jFlTbm0dH3O3tm5CzQAAAAIhY6I8vQ96tdSoyGy09wEMCdWzB06GElVHeQhWVw8fukq1dUAwWRXmZKT8kxDNAlp2NS7fXpEGXZ9fF7+c1IJp"
	sigBytes, err := base64.StdEncoding.DecodeString(sigBase64)
	require.NoError(t, err)

	// Case 19 (https://github.com/w3c-ccg/vc-http-api/pull/128)
	msg := `
_:c14n0 <http://purl.org/dc/terms/created> "2021-02-23T19:37:24Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#BbsBlsSignature2020> .
_:c14n0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:c14n0 <https://w3id.org/security#verificationMethod> <did:key:zUC724vuGvHpnCGFG1qqpXb81SiBLu3KLSqVzenwEZNPoY35i2Bscb8DLaVwHvRFs6F2NkNNXRcPWvqnPDUd9ukdjLkjZd3u9zzL4wDZDUpkPAatLDGLEYVo8kkAzuAKJQMr7N2#zUC724vuGvHpnCGFG1qqpXb81SiBLu3KLSqVzenwEZNPoY35i2Bscb8DLaVwHvRFs6F2NkNNXRcPWvqnPDUd9ukdjLkjZd3u9zzL4wDZDUpkPAatLDGLEYVo8kkAzuAKJQMr7N2> .
<did:key:z5TcESXuYUE9aZWYwSdrUEGK1HNQFHyTt4aVpaCTVZcDXQmUheFwfNZmRksaAbBneNm5KyE52SdJeRCN1g6PJmF31GsHWwFiqUDujvasK3wTiDr3vvkYwEJHt7H5RGEKYEp1ErtQtcEBgsgY2DA9JZkHj1J9HZ8MRDTguAhoFtR4aTBQhgnkP4SwVbxDYMEZoF2TMYn3s#zUC7LTa4hWtaE9YKyDsMVGiRNqPMN3s4rjBdB3MFi6PcVWReNfR72y3oGW2NhNcaKNVhMobh7aHp8oZB3qdJCs7RebM2xsodrSm8MmePbN25NTGcpjkJMwKbcWfYDX7eHCJjPGM> <https://example.org/examples#degree> <urn:bnid:_:c14n0> .
<http://example.gov/credentials/3732> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://example.org/examples#UniversityDegreeCredential> .
<http://example.gov/credentials/3732> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<http://example.gov/credentials/3732> <https://www.w3.org/2018/credentials#credentialSubject> <did:key:z5TcESXuYUE9aZWYwSdrUEGK1HNQFHyTt4aVpaCTVZcDXQmUheFwfNZmRksaAbBneNm5KyE52SdJeRCN1g6PJmF31GsHWwFiqUDujvasK3wTiDr3vvkYwEJHt7H5RGEKYEp1ErtQtcEBgsgY2DA9JZkHj1J9HZ8MRDTguAhoFtR4aTBQhgnkP4SwVbxDYMEZoF2TMYn3s#zUC7LTa4hWtaE9YKyDsMVGiRNqPMN3s4rjBdB3MFi6PcVWReNfR72y3oGW2NhNcaKNVhMobh7aHp8oZB3qdJCs7RebM2xsodrSm8MmePbN25NTGcpjkJMwKbcWfYDX7eHCJjPGM> .
<http://example.gov/credentials/3732> <https://www.w3.org/2018/credentials#issuanceDate> "2020-03-10T04:24:12.164Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<http://example.gov/credentials/3732> <https://www.w3.org/2018/credentials#issuer> <did:key:zUC724vuGvHpnCGFG1qqpXb81SiBLu3KLSqVzenwEZNPoY35i2Bscb8DLaVwHvRFs6F2NkNNXRcPWvqnPDUd9ukdjLkjZd3u9zzL4wDZDUpkPAatLDGLEYVo8kkAzuAKJQMr7N2> .
<urn:bnid:_:c14n0> <http://schema.org/name> "Bachelor of Science and Arts"^^<http://www.w3.org/1999/02/22-rdf-syntax-ns#HTML> .
<urn:bnid:_:c14n0> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://example.org/examples#BachelorDegree> .
`

	nonceBytes, err := base64.StdEncoding.DecodeString("lEixQKDQvRecCifKl789TQj+Ii6YWDLSwn3AxR0VpPJ1QV5htod/0VCchVf1zVM0y2E=")
	require.NoError(t, err)

	verifier := NewBBSG2SignatureProofVerifier()
	err = verifier.Verify(sigBytes, []byte(msg), &pubkey.PublicKey{
		Type:     kms.BLS12381G2Type,
		BytesKey: &pubkey.BytesKey{Bytes: pubKeyBytes},
	}, &proof.Proof{Nonce: nonceBytes})

	require.NoError(t, err)

	t.Run("Success with jwk", func(t *testing.T) {
		pubJWK, jwkErr := jwksupport.PubKeyBytesToJWK(pubKeyBytes, kms.BLS12381G2Type)
		require.NoError(t, jwkErr)

		jwkErr = verifier.Verify(sigBytes, []byte(msg), &pubkey.PublicKey{
			Type: kms.BLS12381G2Type,
			JWK:  pubJWK,
		}, &proof.Proof{Nonce: nonceBytes})
		require.NoError(t, jwkErr)
	})

	t.Run("invalid public key bytes", func(t *testing.T) {
		err = verifier.Verify(sigBytes, []byte(msg), &pubkey.PublicKey{
			Type:     kms.BLS12381G2Type,
			BytesKey: &pubkey.BytesKey{Bytes: []byte("invalid-key")},
		}, &proof.Proof{Nonce: nonceBytes})

		require.Error(t, err)
		require.ErrorContains(t, err, "invalid size of public key")
	})

	t.Run("invalid public key bytes", func(t *testing.T) {
		err = verifier.Verify(sigBytes, []byte(msg), &pubkey.PublicKey{
			Type: kms.BLS12381G2Type,
		}, &proof.Proof{Nonce: nonceBytes})

		require.Error(t, err)
		require.ErrorContains(t, err, "incorrect pub key, should contain key bytes or jwk")
	})

	t.Run("invalid public key type", func(t *testing.T) {
		err = verifier.Verify(sigBytes, []byte(msg), &pubkey.PublicKey{
			Type: kms.BLS12381G2Type,
			JWK: &jwk.JWK{
				JSONWebKey: gojose.JSONWebKey{
					Key: "foo",
				},
				Kty: "EC",
				Crv: "BLS12381_G2",
			},
		}, &proof.Proof{Nonce: nonceBytes})
		require.Error(t, err)
		require.ErrorContains(t, err, "invalid jwk")
	})
}
