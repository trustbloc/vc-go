package checker

import "github.com/veraison/go-cose"

type CheckCWTProofRequest struct {
	KeyID string
	Algo  cose.Algorithm
}
