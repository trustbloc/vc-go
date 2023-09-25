/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package json

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

type testJSON struct {
	S []string `json:"stringSlice"`
	I int      `json:"intValue"`
}

type testJSONInvalid struct {
	I []string `json:"intValue"`
	S int      `json:"stringSlice"`
}

func Test_marshalJSON(t *testing.T) {
	t.Run("Successful JSON marshaling", func(t *testing.T) {
		v := testJSON{
			S: []string{"a", "b", "c"},
			I: 7,
		}

		cf := map[string]interface{}{
			"boolValue": false,
			"intValue":  8,
		}
		actual, err := MarshalWithCustomFields(&v, cf)
		require.NoError(t, err)

		expectedMap := map[string]interface{}{
			"stringSlice": []string{"a", "b", "c"},
			"intValue":    7,
			"boolValue":   false,
		}
		expected, err := json.Marshal(expectedMap)
		require.NoError(t, err)

		require.Equal(t, expected, actual)
	})

	t.Run("Failed JSON marshall", func(t *testing.T) {
		// artificial example - pass smth which cannot be marshalled
		jsonBytes, err := MarshalWithCustomFields(make(chan int), map[string]interface{}{})
		require.Error(t, err)
		require.Nil(t, jsonBytes)
	})
}

func Test_unmarshalJSON(t *testing.T) {
	originalMap := map[string]interface{}{
		"stringSlice": []string{"a", "b", "c"},
		"intValue":    7,
		"boolValue":   false,
	}

	data, err := json.Marshal(originalMap)
	require.NoError(t, err)

	t.Run("Successful JSON unmarshalling", func(t *testing.T) {
		v := new(testJSON)
		cf := make(map[string]interface{})
		err := UnmarshalWithCustomFields(data, v, cf)
		require.NoError(t, err)

		expectedV := testJSON{
			S: []string{"a", "b", "c"},
			I: 7,
		}
		expectedEf := map[string]interface{}{
			"boolValue": false,
		}
		require.Equal(t, expectedV, *v)
		require.Equal(t, expectedEf, cf)
	})

	t.Run("Failed JSON unmarshalling", func(t *testing.T) {
		cf := make(map[string]interface{})

		// invalid JSON
		err := UnmarshalWithCustomFields([]byte("not JSON"), "", cf)
		require.Error(t, err)

		// unmarshallable value
		err = UnmarshalWithCustomFields(data, make(chan int), cf)
		require.Error(t, err)

		// incompatible structure of value
		err = UnmarshalWithCustomFields(data, new(testJSONInvalid), cf)
		require.Error(t, err)
	})
}

func TestAddCustomFields(t *testing.T) {
	orign := map[string]interface{}{
		"fld1": "v1",
		"fld2": "v2",
		"fld3": "v3",
	}

	cf := map[string]interface{}{
		"fld3": "cv3",
		"fld4": "cv4",
		"fld5": "cv5",
	}

	expected := map[string]interface{}{
		"fld1": "v1",
		"fld2": "v2",
		"fld3": "v3",
		"fld4": "cv4",
		"fld5": "cv5",
	}

	AddCustomFields(orign, cf)

	require.Equal(t, expected, orign)
}

func TestSplitJSONObj(t *testing.T) {
	orign := map[string]interface{}{
		"fld1": "v1",
		"fld2": "v2",
		"fld3": "v3",
		"fld4": "cv4",
		"fld5": "cv5",
	}

	obj, cf := SplitJSONObj(orign, "fld1", "fld2", "fld3")

	require.Equal(t, map[string]interface{}{
		"fld1": "v1",
		"fld2": "v2",
		"fld3": "v3",
	}, obj)

	require.Equal(t, map[string]interface{}{
		"fld4": "cv4",
		"fld5": "cv5",
	}, cf)
}

func TestShallowCopyObj(t *testing.T) {
	orign := map[string]interface{}{
		"fld1": "v1",
		"fld2": "v2",
		"fld3": "v3",
	}

	copyObj := ShallowCopyObj(orign)

	require.Equal(t, orign, copyObj)

	copyObj["fld1"] = "new"

	require.NotEqual(t, orign, copyObj)
}

func TestCopyExcept(t *testing.T) {
	orign := map[string]interface{}{
		"fld1": "v1",
		"fld2": "v2",
		"fld3": "v3",
		"fld4": "cv4",
		"fld5": "cv5",
	}

	expected := map[string]interface{}{
		"fld1": "v1",
		"fld2": "v2",
		"fld3": "v3",
	}

	copyObj := CopyExcept(orign, "fld4", "fld5")
	require.Equal(t, expected, copyObj)
}

func TestSelect(t *testing.T) {
	orign := map[string]interface{}{
		"fld1": "v1",
		"fld2": "v2",
		"fld3": "v3",
		"fld4": "cv4",
		"fld5": "cv5",
	}

	expected := map[string]interface{}{
		"fld4": "cv4",
		"fld5": "cv5",
	}

	copyObj := Select(orign, "fld4", "fld5")
	require.Equal(t, expected, copyObj)
}
