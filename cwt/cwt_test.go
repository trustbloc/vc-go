package cwt_test

import (
	"encoding/hex"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/veraison/go-cose"

	"github.com/trustbloc/vc-go/cwt"
	"github.com/trustbloc/vc-go/proof/checker"
)

func TestParse(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		input, decodeErr := hex.DecodeString("d28443a10126a104524173796d6d657472696345434453413235365850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b7158405427c1ff28d23fbad1f29c4c7c6a555e601d6fa29f9179bc3d7438bacaca5acd08c8d4d4f96131680c429a01f85951ecee743a52b9b63632c57209120e1c9e30")
		assert.NoError(t, decodeErr)

		proofChecker := NewMockProofChecker(gomock.NewController(t))
		proofChecker.EXPECT().CheckCWTProof(gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(request checker.CheckCWTProofRequest, message *cose.Sign1Message, expectedIssuer string) error {
				assert.Equal(t, "AsymmetricECDSA256", request.KeyID)
				assert.Equal(t, cose.AlgorithmES256, request.Algo)
				assert.NotNil(t, message)
				assert.Equal(t, "coap://as.example.com", expectedIssuer)
				return nil
			})

		resp, _, err := cwt.ParseAndCheckProof(input, proofChecker, true)
		assert.NoError(t, err)
		assert.NotNil(t, resp)
	})
}
