/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
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
) ([]byte, *cose.Sign1Message, error) {
	return marshalCOSE(c, signatureAlg, signer, keyID)
}

// CreateCWTVP creates a CWT presentation from the given presentation.
func (vp *Presentation) CreateCWTVP(
	aud []string,
	signatureAlg cose.Algorithm,
	signer cwt.ProofCreator,
	keyID string,
	minimizeVP bool,
) (*Presentation, error) {
	cwtClaims, err := vp.CWTClaims(aud, minimizeVP)
	if err != nil {
		return nil, fmt.Errorf("failed to create CWT claims: %w", err)
	}

	cwtBytes, msg, err := cwtClaims.MarshalCWT(signatureAlg, signer, keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CWT: %w", err)
	}

	var vpMap map[interface{}]interface{}

	err = cbor.Unmarshal(msg.Payload, &vpMap)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal VP map: %w", err)
	}

	vp2 := vp.Clone()

	vp2.CWT = &VpCWT{
		Raw:     cwtBytes,
		Message: msg,
		VPMap:   convertToStringMap(vpMap),
	}

	vp2.JWT = ""

	return vp2, nil
}

// IsCWT returns true is the presentation is CWT.
func (vp *Presentation) IsCWT() bool {
	return vp.CWT != nil && len(vp.CWT.Raw) > 0
}
