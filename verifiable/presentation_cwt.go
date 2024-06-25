/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"github.com/veraison/go-cose"

	"github.com/trustbloc/vc-go/cwt"
	"github.com/trustbloc/vc-go/jwt"
)

func newCWTPresClaims(vp *Presentation, audience []string, minimizeVP bool) (*CWTPresClaims, error) {
	jwtClaims, err := newJWTPresClaims(vp, audience, minimizeVP)
	if err != nil {
		return nil, err
	}

	return &CWTPresClaims{
		Claims:       jwtClaims.Claims,
		Presentation: jwtClaims.Presentation,
	}, nil
}

type CWTPresClaims struct {
	*jwt.Claims
	Presentation rawPresentation `json:"vp,omitempty"`
}

func (c *CWTPresClaims) MarshalCWT(
	signatureAlg cose.Algorithm,
	signer cwt.ProofCreator,
	keyID string,
) ([]byte, error) {
	return marshalCOSE(c, signatureAlg, signer, keyID)
}
