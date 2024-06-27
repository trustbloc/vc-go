/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"fmt"

	josejwt "github.com/go-jose/go-jose/v3/jwt"
	"github.com/veraison/go-cose"

	"github.com/trustbloc/vc-go/cwt"
	jsonutil "github.com/trustbloc/vc-go/util/json"
)

// CWTClaims converts Verifiable Credential into CWT Credential claims, which can be than serialized
// e.g. into JWS.
func (vc *Credential) CWTClaims() (*CWTCredClaims, error) {
	return newCWTCredClaims(vc)
}

// newJWTCredClaims creates JWT Claims of VC with an option to minimize certain fields of VC
// which is put into "vc" claim.
func newCWTCredClaims(vc *Credential) (*CWTCredClaims, error) {
	vcc := &vc.credentialContents

	subjectID, err := SubjectID(vcc.Subject)
	if err != nil {
		return nil, fmt.Errorf("get VC subject id: %w", err)
	}

	// currently jwt encoding supports only single subject (by the spec)
	claims := &CWTClaims{
		Issuer:    vcc.Issuer.ID,                           // iss
		NotBefore: josejwt.NewNumericDate(vcc.Issued.Time), // nbf
		ID:        vcc.ID,                                  // jti
		Subject:   subjectID,                               // sub
	}

	if vcc.Expired != nil {
		claims.Expiry = josejwt.NewNumericDate(vcc.Expired.Time) // exp
	}

	if vcc.Issued != nil {
		claims.IssuedAt = josejwt.NewNumericDate(vcc.Issued.Time)
	}

	credentialJSONCopy := jsonutil.ShallowCopyObj(vc.credentialJSON)

	credClaims := &CWTCredClaims{
		CWTClaims: claims,
		VC:        credentialJSONCopy,
	}

	return credClaims, nil
}

// MarshaCOSE serializes into signed form (COSE).
func (jcc *CWTCredClaims) MarshaCOSE(
	signatureAlg cose.Algorithm,
	signer cwt.ProofCreator,
	keyID string,
) ([]byte, error) {
	return marshalCOSE(jcc, signatureAlg, signer, keyID)
}
