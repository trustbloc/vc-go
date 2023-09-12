[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://raw.githubusercontent.com/trustbloc/vc-go/main/LICENSE)
[![Release](https://img.shields.io/github/release/trustbloc/vc-go.svg?style=flat-square)](https://github.com/trustbloc/vc-go/releases/latest)
[![Godocs](https://img.shields.io/badge/godoc-reference-blue.svg)](https://godoc.org/github.com/trustbloc/vc-go)

[![Build Status](https://github.com/trustbloc/vc-go/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/trustbloc/vc-go/actions/workflows/build.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/trustbloc/vc-go)](https://goreportcard.com/report/github.com/trustbloc/vc-go)


# TrustBloc Verifiable Credential (VC) Go Library

The TrustBloc VC Go repo contains [W3C Verifiable Credential(VC)](https://www.w3.org/TR/did-core/) related shared code.

The library has the following implementations.
- [W3C Verifiable Credential(VC)](https://www.w3.org/TR/vc-data-model/) Data model
  - JSON-LD Signature Suites
    - BbsBlsSignature2020
    - EcdsaSecp256k1Signature2019
    - Ed25519Signature2018
    - Ed25519Signature2020
    - JsonWebSignature2020
    - [Data Integrity](https://www.w3.org/TR/vc-data-integrity/)
  - JWT Signature Suites
    - JWT
    - SD-JWT
- [DIF Presentation Exchange](https://identity.foundation/presentation-exchange/)
- Verifiable Credential(VC) Status
  - [StatusList2021Entry](https://www.w3.org/TR/vc-status-list/)
- [DIF Well Known DID Configuration](https://identity.foundation/.well-known/resources/did-configuration/) 


## License
Apache License, Version 2.0 (Apache-2.0). See the [LICENSE](LICENSE) file.
