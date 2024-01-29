package cwt_test

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/veraison/go-cose"

	"github.com/trustbloc/vc-go/cwt"
	"github.com/trustbloc/vc-go/proof/checker"
)

func TestWrapper(t *testing.T) {
	t.Run("extract issuer", func(t *testing.T) {
		mockVerifier := NewMockProofChecker(gomock.NewController(t))
		verifier := cwt.Verifier{
			ProofChecker: mockVerifier,
		}

		mockVerifier.EXPECT().CheckCWTProof(gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(
				request checker.CheckCWTProofRequest,
				message *cose.Sign1Message,
				expectedProofIssuer string,
			) error {
				assert.Equal(t, "coap://as.example.com", expectedProofIssuer)

				return nil
			})

		assert.NoError(t, verifier.Verify(&cose.Sign1Message{},
			"coap://as.example.com#AsymmetricECDSA256#321232131", 0))
	})
}
