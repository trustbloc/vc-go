/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package json

import (
	"encoding/json"

	"golang.org/x/exp/slices"
)

// MarshalWithCustomFields marshals value merged with custom fields defined in the map into JSON bytes.
func MarshalWithCustomFields(v interface{}, cf map[string]interface{}) ([]byte, error) {
	// Merge value and custom fields into the joint map.
	vm, err := MergeCustomFields(v, cf)
	if err != nil {
		return nil, err
	}

	// Marshal the joint map.
	return json.Marshal(vm)
}

// UnmarshalWithCustomFields unmarshals JSON into value v and puts all JSON fields which do not belong to value
// into custom fields map cf.
func UnmarshalWithCustomFields(data []byte, v interface{}, cf map[string]interface{}) error {
	err := json.Unmarshal(data, v)
	if err != nil {
		return err
	}

	// Collect value fields map.
	vData, err := json.Marshal(v)
	if err != nil {
		return err
	}

	var vf map[string]interface{}

	err = json.Unmarshal(vData, &vf)
	if err != nil {
		return err
	}

	// Collect all fields map.
	var af map[string]interface{}

	err = json.Unmarshal(data, &af)
	if err != nil {
		return err
	}

	// Copy only those entries which do not belong to the value (i.e. custom fields).
	for k, v := range af {
		if _, ok := vf[k]; !ok {
			cf[k] = v
		}
	}

	return nil
}

// MergeCustomFields converts value to the JSON-like map and merges it with custom fields map cf.
func MergeCustomFields(v interface{}, cf map[string]interface{}) (map[string]interface{}, error) {
	kf, err := ToMap(v)
	if err != nil {
		return nil, err
	}

	// Supplement value map with custom fields.
	for k, v := range cf {
		if _, exists := kf[k]; !exists {
			kf[k] = v
		}
	}

	return kf, nil
}

// AddCustomFields add custom filed to json object.
func AddCustomFields(obj map[string]interface{}, cf map[string]interface{}) {
	// Supplement value map with custom fields.
	for k, v := range cf {
		if _, exists := obj[k]; !exists {
			obj[k] = v
		}
	}
}

// SplitJSONObj splits provides fields into separate object.
func SplitJSONObj(json map[string]interface{}, flds ...string) (map[string]interface{}, map[string]interface{}) {
	fldsMap := make(map[string]interface{})
	rest := make(map[string]interface{})

	for k, v := range json {
		if slices.Contains(flds, k) {
			fldsMap[k] = v
		} else {
			rest[k] = v
		}
	}

	return fldsMap, rest
}

// ShallowCopyObj creates new json object with copied fields form provided object.
func ShallowCopyObj(json map[string]interface{}) map[string]interface{} {
	flds := make(map[string]interface{})

	for k, v := range json {
		flds[k] = v
	}

	return flds
}

// CopyExcept copies all fields except fields with given names.
func CopyExcept(json map[string]interface{}, flds ...string) map[string]interface{} {
	newJSON := ShallowCopyObj(json)

	for _, fld := range flds {
		delete(newJSON, fld)
	}

	return newJSON
}

// Select copies only fields with given names.
func Select(json map[string]interface{}, flds ...string) map[string]interface{} {
	newJSON := map[string]interface{}{}

	for _, fld := range flds {
		newJSON[fld] = json[fld]
	}

	return newJSON
}

// ToMap convert object, string or bytes to json object represented by map.
func ToMap(v interface{}) (map[string]interface{}, error) {
	var (
		b   []byte
		err error
	)

	switch cv := v.(type) {
	case []byte:
		b = cv
	case string:
		b = []byte(cv)
	default:
		b, err = json.Marshal(v)
		if err != nil {
			return nil, err
		}
	}

	var m map[string]interface{}

	err = json.Unmarshal(b, &m)
	if err != nil {
		return nil, err
	}

	return m, nil
}
