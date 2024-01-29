/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package defaults

import (
	"github.com/trustbloc/vc-go/crypto-ext/verifiers/bbs"
	"github.com/trustbloc/vc-go/crypto-ext/verifiers/ecdsa"
	"github.com/trustbloc/vc-go/crypto-ext/verifiers/ed25519"
	"github.com/trustbloc/vc-go/crypto-ext/verifiers/rsa"
	proofdesc "github.com/trustbloc/vc-go/proof"
	"github.com/trustbloc/vc-go/proof/checker"
	"github.com/trustbloc/vc-go/proof/jwtproofs/eddsa"
	"github.com/trustbloc/vc-go/proof/jwtproofs/es256"
	"github.com/trustbloc/vc-go/proof/jwtproofs/es256k"
	"github.com/trustbloc/vc-go/proof/jwtproofs/es384"
	"github.com/trustbloc/vc-go/proof/jwtproofs/es521"
	"github.com/trustbloc/vc-go/proof/jwtproofs/ps256"
	"github.com/trustbloc/vc-go/proof/jwtproofs/rs256"
	"github.com/trustbloc/vc-go/proof/ldproofs/bbsblssignature2020"
	"github.com/trustbloc/vc-go/proof/ldproofs/bbsblssignatureproof2020"
	"github.com/trustbloc/vc-go/proof/ldproofs/ecdsasecp256k1signature2019"
	"github.com/trustbloc/vc-go/proof/ldproofs/ed25519signature2018"
	"github.com/trustbloc/vc-go/proof/ldproofs/ed25519signature2020"
	"github.com/trustbloc/vc-go/proof/ldproofs/jsonwebsignature2020"
	"github.com/trustbloc/vc-go/vermethod"
)

type verificationMethodResolver interface {
	ResolveVerificationMethod(verificationMethod string, expectedProofIssuer string) (*vermethod.VerificationMethod, error)
}

// NewDefaultProofChecker creates proof checker with all available validation algorithms.
func NewDefaultProofChecker(verificationMethodResolver verificationMethodResolver) *checker.ProofChecker {
	jwtCheckers := []proofdesc.JWTProofDescriptor{
		eddsa.New(), es256.New(), es256k.New(), es384.New(), es521.New(), rs256.New(), ps256.New(),
	}
	return checker.New(verificationMethodResolver,
		checker.WithSignatureVerifiers(ed25519.New(), bbs.NewBBSG2SignatureVerifier(),
			rsa.NewPS256(), rsa.NewRS256(),
			ecdsa.NewSecp256k1(), ecdsa.NewES256(), ecdsa.NewES384(), ecdsa.NewES521()),
		checker.WithLDProofTypes(
			bbsblssignature2020.New(),
			ecdsasecp256k1signature2019.New(),
			ed25519signature2018.New(),
			ed25519signature2020.New(),
			jsonwebsignature2020.New(),
		),
		checker.WithLDProofTypeEx(bbsblssignatureproof2020.New(), bbs.NewBBSG2SignatureProofVerifier()),
		checker.WithJWTAlg(jwtCheckers...),
		checker.WithCWTAlg(jwtCheckers...),
	)
}
