/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vermethod

import (
	"fmt"
	"strings"

	"github.com/trustbloc/did-go/doc/did"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
)

const (
	resolveDIDParts = 2
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
func (r *VDRResolver) ResolveVerificationMethod(verificationMethod string) (*VerificationMethod, error) {
	idSplit := strings.Split(verificationMethod, "#")
	if len(idSplit) != resolveDIDParts {
		return nil, fmt.Errorf("wrong id %s to resolve", idSplit)
	}

	methodDID, keyID := idSplit[0], fmt.Sprintf("#%s", idSplit[1])

	docResolution, err := r.vdr.Resolve(methodDID)
	if err != nil {
		return nil, fmt.Errorf("resolve DID %s: %w", methodDID, err)
	}

	for _, verifications := range docResolution.DIDDocument.VerificationMethods() {
		for _, verification := range verifications {
			if strings.Contains(verification.VerificationMethod.ID, keyID) &&
				verification.Relationship != did.KeyAgreement {
				return &VerificationMethod{
					Type:  verification.VerificationMethod.Type,
					Value: verification.VerificationMethod.Value,
					JWK:   verification.VerificationMethod.JSONWebKey(),
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("public key with KID %s is not found for DID %s", keyID, methodDID)
}
