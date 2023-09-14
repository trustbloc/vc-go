/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	jsonutil "github.com/trustbloc/vc-go/util/json"
)

func TestJwtAlgorithm_Name(t *testing.T) {
	alg, err := RS256.Name()
	require.NoError(t, err)
	require.Equal(t, "RS256", alg)

	alg, err = EdDSA.Name()
	require.NoError(t, err)
	require.Equal(t, "EdDSA", alg)

	// not supported alg
	sa, err := JWSAlgorithm(-1).Name()
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported algorithm")
	require.Empty(t, sa)
}

func TestStringSlice(t *testing.T) {
	strings, err := stringSlice([]interface{}{"str1", "str2"})
	require.NoError(t, err)
	require.Equal(t, []string{"str1", "str2"}, strings)

	strings, err = stringSlice([]interface{}{"str1", 15})
	require.Error(t, err)
	require.Nil(t, strings)
}

func TestTypedID_MarshalJSON(t *testing.T) {
	t.Run("Successful marshalling", func(t *testing.T) {
		tid := TypedID{
			ID:   "http://example.com/policies/credential/4",
			Type: "IssuerPolicy",
			CustomFields: map[string]interface{}{
				"profile": "http://example.com/profiles/credential",
			},
		}

		data, err := json.Marshal(&tid)
		require.NoError(t, err)

		var tidRecovered TypedID
		err = json.Unmarshal(data, &tidRecovered)
		require.NoError(t, err)

		require.Equal(t, tid, tidRecovered)
	})
}

func TestTypedID_UnmarshalJSON(t *testing.T) {
	t.Run("Successful unmarshalling", func(t *testing.T) {
		tidJSONBytes := `{
  "type": "IssuerPolicy",
  "id": "http://example.com/policies/credential/4",
  "profile": "http://example.com/profiles/credential",
  "prohibition": [{
    "assigner": "https://example.edu/issuers/14",
    "assignee": "AllVerifiers",
    "target": "http://example.edu/credentials/3732"
  }]
}`

		var tidJSON JSONObject
		err := json.Unmarshal([]byte(tidJSONBytes), &tidJSON)
		require.NoError(t, err)

		tid, err := parseTypedIDObj(tidJSON)
		require.NoError(t, err)

		require.Equal(t, "http://example.com/policies/credential/4", tid.ID)
		require.Equal(t, "IssuerPolicy", tid.Type)
		require.Equal(t, CustomFields{
			"profile": "http://example.com/profiles/credential",
			"prohibition": []interface{}{
				map[string]interface{}{
					"assigner": "https://example.edu/issuers/14",
					"assignee": "AllVerifiers",
					"target":   "http://example.edu/credentials/3732",
				},
			},
		}, tid.CustomFields)
	})

	t.Run("Invalid unmarshalling", func(t *testing.T) {
		tidJSONWithInvalidType := `{
  "type": 77
}`

		var tidJSON JSONObject
		err := json.Unmarshal([]byte(tidJSONWithInvalidType), &tidJSON)
		require.NoError(t, err)

		_, err = parseTypedIDObj(tidJSON)
		require.Error(t, err)
		require.Contains(t, err.Error(), "parse TypedID")
	})
}

func TestDecodeType(t *testing.T) {
	t.Run("Decode single type", func(t *testing.T) {
		types, err := decodeType("VerifiableCredential")
		require.NoError(t, err)
		require.Equal(t, []string{"VerifiableCredential"}, types)
	})

	t.Run("Decode several types", func(t *testing.T) {
		types, err := decodeType([]interface{}{"VerifiableCredential", "UniversityDegreeCredential"})
		require.NoError(t, err)
		require.Equal(t, []string{"VerifiableCredential", "UniversityDegreeCredential"}, types)
	})

	t.Run("Error on decoding of invalid Verifiable Credential type", func(t *testing.T) {
		types, err := decodeType(77)
		require.Error(t, err)
		require.Contains(t, err.Error(), "credential type of unknown structure")
		require.Nil(t, types)
	})

	t.Run("Error on decoding of invalid Verifiable Credential types", func(t *testing.T) {
		types, err := decodeType([]interface{}{"VerifiableCredential", 777})
		require.Error(t, err)
		require.Contains(t, err.Error(), "vc types: array element is not a string")
		require.Nil(t, types)
	})
}

func TestDecodeContext(t *testing.T) {
	t.Run("Decode single context", func(t *testing.T) {
		contexts, extraContexts, err := decodeContext("https://www.w3.org/2018/credentials/v1")
		require.NoError(t, err)
		require.Equal(t, []string{"https://www.w3.org/2018/credentials/v1"}, contexts)
		require.Empty(t, extraContexts)
	})

	t.Run("Decode several contexts", func(t *testing.T) {
		contexts, extraContexts, err := decodeContext([]interface{}{
			"https://www.w3.org/2018/credentials/v1",
			"https://www.w3.org/2018/credentials/examples/v1",
		})
		require.NoError(t, err)
		require.Equal(t,
			[]string{"https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"},
			contexts)
		require.Empty(t, extraContexts)
	})

	t.Run("Decode several contexts with custom objects", func(t *testing.T) {
		customContext := map[string]interface{}{
			"image": map[string]interface{}{"@id": "schema:image", "@type": "@id"},
		}
		contexts, extraContexts, err := decodeContext([]interface{}{
			"https://www.w3.org/2018/credentials/v1",
			"https://www.w3.org/2018/credentials/examples/v1",
			customContext,
		})
		require.NoError(t, err)
		require.Equal(t,
			[]string{"https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"},
			contexts)
		require.Equal(t, []interface{}{customContext}, extraContexts)
	})

	t.Run("Decode context of invalid type", func(t *testing.T) {
		contexts, extraContexts, err := decodeContext(55)
		require.Error(t, err)
		require.Nil(t, contexts)
		require.Nil(t, extraContexts)
	})
}

func Test_safeStringValue(t *testing.T) {
	var i interface{} = "str"

	require.Equal(t, "str", safeStringValue(i))

	i = nil
	require.Equal(t, "", safeStringValue(i))
}

func Test_proofsToRaw(t *testing.T) {
	singleProof := []Proof{{
		"proofValue": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..67TTULBvibJaJ2oZf3tGYhxZqxYS89qGQykL5hfCoh-MF0vrwQqzciZhjNrAGTAgHtDZsnSQVwJ8bO_7Sc0ECw", //nolint:lll
	}}

	singleProofRaw := proofsToRaw(singleProof)

	expectedProof, err := jsonutil.ToMap(singleProof[0])
	require.NoError(t, err)

	require.Equal(t, expectedProof, singleProofRaw)

	severalProofs := []Proof{
		singleProof[0],
		{"proofValue": "if8ooA+32YZc4SQBvIDDY9tgTatPoq4IZ8Kr+We1t38LR2RuURmaVu9D4shbi4VvND87PUqq5/0vsNFEGIIEDA=="},
	}
	expectedSeveralProofs, err := toArray(severalProofs)
	require.NoError(t, err)

	severalProofsRaw := proofsToRaw(severalProofs)

	require.Equal(t, expectedSeveralProofs, severalProofsRaw)
}

func Test_parseLDProof(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		singleProof := []interface{}{map[string]interface{}{
			"proofValue": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..67TTULBvibJaJ2oZf3tGYhxZqxYS89qGQykL5hfCoh-MF0vrwQqzciZhjNrAGTAgHtDZsnSQVwJ8bO_7Sc0ECw", //nolint:lll
		}}

		proofs, err := parseLDProof(singleProof)
		require.NoError(t, err)
		require.Len(t, proofs, 1)
	})

	t.Run("unsupported proof value", func(t *testing.T) {
		singleProof := []interface{}{
			"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19", //nolint:lll
		}

		_, err := parseLDProof(singleProof)
		require.Error(t, err)
	})
}

// toArray convert array to array of json objects.
func toArray[T any](v []T) ([]interface{}, error) {
	maps := make([]interface{}, len(v))

	for i := range v {
		m, err := jsonutil.ToMap(v[i])
		if err != nil {
			return nil, err
		}

		maps[i] = m
	}

	return maps, nil
}
