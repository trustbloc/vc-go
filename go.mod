// Copyright Gen Digital Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/vc-go

go 1.23.0

toolchain go1.23.6

require (
	github.com/PaesslerAG/gval v1.2.2
	github.com/PaesslerAG/jsonpath v0.1.2-0.20240726212847-3a740cf7976f
	github.com/VictoriaMetrics/fastcache v1.5.7
	github.com/btcsuite/btcd/btcec/v2 v2.3.4
	github.com/btcsuite/btcutil v1.0.3-0.20201208143702-a53e38424cce
	github.com/fxamacker/cbor/v2 v2.5.0
	github.com/go-jose/go-jose/v3 v3.0.4
	github.com/golang/mock v1.6.0
	github.com/google/uuid v1.6.0
	github.com/hashicorp/golang-lru/v2 v2.0.7
	github.com/kawamuray/jsonpath v0.0.0-20201211160320-7483bafabd7e
	github.com/mitchellh/mapstructure v1.5.0
	github.com/multiformats/go-multibase v0.2.0
	github.com/piprate/json-gold v0.5.1-0.20230111113000-6ddbe6e6f19f
	github.com/samber/lo v1.47.0
	github.com/stretchr/testify v1.10.0
	github.com/theory/jsonpath v0.3.0
	github.com/tidwall/gjson v1.14.3
	github.com/tidwall/sjson v1.1.4
	github.com/trustbloc/bbs-signature-go v1.0.2
	github.com/trustbloc/did-go v1.3.4
	github.com/trustbloc/kms-go v1.2.2
	github.com/veraison/go-cose v1.1.1-0.20240126165338-2300d5c96dbd
	github.com/xeipuuv/gojsonschema v1.2.0
	golang.org/x/exp v0.0.0-20230817173708-d852ddb80c63
)

require (
	github.com/IBM/mathlib v0.0.3-0.20231011094432-44ee0eb539da // indirect
	github.com/bits-and-blooms/bitset v1.17.0 // indirect
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/consensys/bavard v0.1.22 // indirect
	github.com/consensys/gnark-crypto v0.14.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.3.0 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/tink/go v1.7.0 // indirect
	github.com/hyperledger/fabric-amcl v0.0.0-20230602173724-9e02669dceb2 // indirect
	github.com/kilic/bls12-381 v0.1.1-0.20210503002446-7b7597926c69 // indirect
	github.com/mmcloughlin/addchain v0.4.0 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/multiformats/go-base32 v0.1.0 // indirect
	github.com/multiformats/go-base36 v0.2.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/pquerna/cachecontrol v0.2.0 // indirect
	github.com/shopspring/decimal v1.3.1 // indirect
	github.com/teserakt-io/golang-ed25519 v0.0.0-20210104091850-3888c087a4c8 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	golang.org/x/crypto v0.37.0 // indirect
	golang.org/x/sys v0.32.0 // indirect
	golang.org/x/text v0.24.0 // indirect
	google.golang.org/protobuf v1.35.2 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	rsc.io/tmplfunc v0.0.3 // indirect
)

replace github.com/piprate/json-gold v0.5.1-0.20230111113000-6ddbe6e6f19f => github.com/trustbloc/json-gold v0.5.2-0.20241206130328-d2135d9f36a8
