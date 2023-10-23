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
func (r *VDRResolver) ResolveVerificationMethod(
	verificationMethod string,
	issuer string,
) (*VerificationMethod, error) {
	compare := func(input string, input2 string) bool {
		return input == input2
	}

	if !strings.HasPrefix(issuer, "did:") { // if issuer is not a DID fetch by key
		idSplit := strings.Split(verificationMethod, "#")
		if len(idSplit) != resolveDIDParts {
			return nil, fmt.Errorf("wrong id %s to resolve", idSplit)
		}

		issuer, verificationMethod = idSplit[0], fmt.Sprintf("#%s", idSplit[1])
		compare = func(input string, input2 string) bool {
			return strings.Contains(input, input2)
		}
	}

	docResolution, err := r.vdr.Resolve(issuer)
	if err != nil {
		return nil, fmt.Errorf("resolve DID %s: %w", issuer, err)
	}

	for _, verifications := range docResolution.DIDDocument.VerificationMethods() {
		for _, verification := range verifications {
			if compare(verification.VerificationMethod.ID, verificationMethod) &&
				verification.Relationship != did.KeyAgreement {
				return &VerificationMethod{
					Type:  verification.VerificationMethod.Type,
					Value: verification.VerificationMethod.Value,
					JWK:   verification.VerificationMethod.JSONWebKey(),
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("public key with KID %s is not found for DID %s", verificationMethod, issuer)
}
