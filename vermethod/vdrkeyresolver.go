/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vermethod

import (
	"fmt"

	"github.com/trustbloc/did-go/doc/did"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
)

type didResolver interface {
	Resolve(did string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error)
}

// VDRResolver resolves DID in order to find public keys for VC verification using vdr.Registry.
// A source of DID could be issuer of VC or holder of VP. It can be also obtained from
// JWS "issuer" claim or "verificationMethod" of Linked Data Proof.
type VDRResolver struct {
	vdr didResolver
}

// NewVDRResolver creates VDRResolver.
func NewVDRResolver(vdr didResolver) *VDRResolver {
	return &VDRResolver{vdr: vdr}
}

// ResolveVerificationMethod resolves verification method by key id.
func (r *VDRResolver) ResolveVerificationMethod(
	verificationMethod string,
	expectedKeyController string,
) (*VerificationMethod, error) {
	docResolution, err := r.vdr.Resolve(expectedKeyController)
	if err != nil {
		return nil, fmt.Errorf("resolve DID %s: %w", expectedKeyController, err)
	}

	for _, verifications := range docResolution.DIDDocument.VerificationMethods() {
		for _, verification := range verifications {
			if verification.VerificationMethod.ID == verificationMethod &&
				verification.Relationship != did.KeyAgreement {
				return &VerificationMethod{
					Type:  verification.VerificationMethod.Type,
					Value: verification.VerificationMethod.Value,
					JWK:   verification.VerificationMethod.JSONWebKey(),
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("public key with KID %s is not found for DID %s", verificationMethod, expectedKeyController)
}
