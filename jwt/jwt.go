/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwt

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/go-jose/go-jose/v3/json"
	"github.com/go-jose/go-jose/v3/jwt"

	"github.com/trustbloc/kms-go/doc/jose"
)

const (
	// TypeJWT defines JWT type.
	TypeJWT = "JWT"
	// TypeSDJWT defines SD-JWT type v5+.
	TypeSDJWT = "SD-JWT"

	// AlgorithmNone used to indicate unsecured JWT.
	AlgorithmNone = "none"
)

// Claims defines JSON Web Token Claims (https://tools.ietf.org/html/rfc7519#section-4)
type Claims jwt.Claims

// jwtParseOpts holds options for the JWT parsing.
type parseOpts struct {
	detachedPayload         []byte
	proofChecker            ProofChecker
	ignoreClaimsMapDecoding bool
}

// ParseOpt is the JWT Parser option.
type ParseOpt func(opts *parseOpts)

// WithJWTDetachedPayload option is for definition of JWT detached payload.
func WithJWTDetachedPayload(payload []byte) ParseOpt {
	return func(opts *parseOpts) {
		opts.detachedPayload = payload
	}
}

// WithIgnoreClaimsMapDecoding option is for ignore decoding claims into .Payload map[string]interface.
// Decoding to map[string]interface is pretty expensive, so this option can be used for performance critical operations.
func WithIgnoreClaimsMapDecoding(ignoreClaimsMapDecoding bool) ParseOpt {
	return func(opts *parseOpts) {
		opts.ignoreClaimsMapDecoding = ignoreClaimsMapDecoding
	}
}

// WithProofChecker option is for definition of JWT detached payload.
func WithProofChecker(proofChecker ProofChecker) ParseOpt {
	return func(opts *parseOpts) {
		opts.proofChecker = proofChecker
	}
}

type unsecuredJWTVerifier struct {
}

func (*unsecuredJWTVerifier) CheckJWTProof(joseHeaders jose.Headers, _, _, signature []byte) error {
	alg, ok := joseHeaders.Algorithm()
	if !ok {
		return errors.New("alg is not defined")
	}

	if alg != AlgorithmNone {
		return errors.New("alg value is not 'none'")
	}

	if len(signature) > 0 {
		return errors.New("not empty signature")
	}

	return nil
}

// UnsecuredJWTVerifier provides verifier for unsecured JWT.
func UnsecuredJWTVerifier() ProofChecker {
	return &unsecuredJWTVerifier{}
}

type unsecuredJWTSigner struct{}

func (s unsecuredJWTSigner) Sign(_ []byte) ([]byte, error) {
	return []byte(""), nil
}

func (s unsecuredJWTSigner) Headers() jose.Headers {
	return map[string]interface{}{
		jose.HeaderAlgorithm: AlgorithmNone,
	}
}

// JSONWebToken defines JSON Web Token (https://tools.ietf.org/html/rfc7519)
type JSONWebToken struct {
	Headers jose.Headers

	Payload map[string]interface{}

	jws *jose.JSONWebSignature
}

// Parse parses input JWT in serialized form into JSON Web Token.
// Currently JWS and unsecured JWT is supported.
func Parse(jwtSerialized string, opts ...ParseOpt) (*JSONWebToken, []byte, error) {
	if !jose.IsCompactJWS(jwtSerialized) {
		return nil, nil, errors.New("JWT of compacted JWS form is supported only")
	}

	pOpts := &parseOpts{}

	for _, opt := range opts {
		opt(pOpts)
	}

	return parseJWS(jwtSerialized, pOpts)
}

// DecodeClaims fills input c with claims of a token.
func (j *JSONWebToken) DecodeClaims(c interface{}) error {
	pBytes, err := json.Marshal(j.Payload)
	if err != nil {
		return err
	}

	return json.Unmarshal(pBytes, c)
}

// LookupStringHeader makes look up of particular header with string value.
func (j *JSONWebToken) LookupStringHeader(name string) string {
	if headerValue, ok := j.Headers[name]; ok {
		if headerStrValue, ok := headerValue.(string); ok {
			return headerStrValue
		}
	}

	return ""
}

// Serialize makes (compact) serialization of token.
func (j *JSONWebToken) Serialize(detached bool) (string, error) {
	if j.jws == nil {
		return "", errors.New("JWS serialization is supported only")
	}

	return j.jws.SerializeCompact(detached)
}

func parseJWS(jwtSerialized string, opts *parseOpts) (*JSONWebToken, []byte, error) {
	jwsOpts := make([]jose.JWSParseOpt, 0)

	if opts.detachedPayload != nil {
		jwsOpts = append(jwsOpts, jose.WithJWSDetachedPayload(opts.detachedPayload))
	}

	jws, err := jose.ParseJWS(jwtSerialized, &joseVerifier{proofChecker: opts.proofChecker}, jwsOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("parse JWT from compact JWS: %w", err)
	}

	return mapJWSToJWT(jws, opts)
}

func mapJWSToJWT(jws *jose.JSONWebSignature, opts *parseOpts) (*JSONWebToken, []byte, error) {
	headers := jws.ProtectedHeaders

	err := CheckHeaders(headers)
	if err != nil {
		return nil, nil, fmt.Errorf("check JWT headers: %w", err)
	}

	token := &JSONWebToken{
		Headers: headers,
		jws:     jws,
	}

	if !opts.ignoreClaimsMapDecoding {
		claims, err := PayloadToMap(jws.Payload)
		if err != nil {
			return nil, nil, fmt.Errorf("read JWT claims from JWS payload: %w", err)
		}

		token.Payload = claims
	}

	return token, jws.Payload, nil
}

// NewSigned creates new signed JSON Web Token based on input claims.
func NewSigned(claims interface{}, signParams SignParameters, signer ProofCreator) (*JSONWebToken, error) {
	joseSignr, err := NewJOSESigner(signParams, signer)
	if err != nil {
		return nil, err
	}

	return NewJoseSigned(claims, signParams.AdditionalHeaders, joseSignr)
}

// NewUnsecured creates new unsecured JSON Web Token based on input claims.
func NewUnsecured(claims interface{}) (*JSONWebToken, error) {
	return NewJoseSigned(claims, nil, &unsecuredJWTSigner{})
}

// NewJoseSigned creates new signed JSON Web Token based on input claims.
func NewJoseSigned(claims interface{}, headers jose.Headers, signer jose.Signer) (*JSONWebToken, error) {
	payloadMap, err := PayloadToMap(claims)
	if err != nil {
		return nil, fmt.Errorf("unmarshallable claims: %w", err)
	}

	payloadBytes, err := json.Marshal(payloadMap)
	if err != nil {
		return nil, fmt.Errorf("marshal JWT claims: %w", err)
	}

	// JWS compact serialization uses only protected headers (https://tools.ietf.org/html/rfc7515#section-3.1).
	jws, err := jose.NewJWS(headers, nil, payloadBytes, signer)
	if err != nil {
		return nil, fmt.Errorf("create JWS: %w", err)
	}

	return &JSONWebToken{
		Headers: jws.ProtectedHeaders,
		Payload: payloadMap,
		jws:     jws,
	}, nil
}

// IsJWS checks if JWT is a JWS of valid structure.
func IsJWS(s string) bool {
	parts := strings.Split(s, ".")

	return len(parts) == 3 &&
		isValidJSON(parts[0]) &&
		isValidJSON(parts[1]) &&
		parts[2] != ""
}

// IsJWTUnsecured checks if JWT is an unsecured JWT of valid structure.
func IsJWTUnsecured(s string) bool {
	parts := strings.Split(s, ".")

	return len(parts) == 3 &&
		isValidJSON(parts[0]) &&
		isValidJSON(parts[1]) &&
		parts[2] == ""
}

func isValidJSON(s string) bool {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return false
	}

	var j map[string]interface{}
	err = json.Unmarshal(b, &j)

	return err == nil
}

// CheckHeaders checks jwt headers.
func CheckHeaders(headers map[string]interface{}) error {
	if _, ok := headers[jose.HeaderAlgorithm]; !ok {
		return errors.New("alg header is not defined")
	}

	typ, ok := headers[jose.HeaderType]
	if ok {
		if err := checkTypHeader(typ); err != nil {
			return err
		}
	}

	cty, ok := headers[jose.HeaderContentType]
	if ok && cty == TypeJWT { // https://tools.ietf.org/html/rfc7519#section-5.2
		return errors.New("nested JWT is not supported")
	}

	return nil
}

func checkTypHeader(typ interface{}) error {
	typStr, ok := typ.(string)
	if !ok {
		return errors.New("invalid typ header format")
	}

	chunks := strings.Split(typStr, "+")
	if len(chunks) > 1 {
		ending := strings.ToUpper(chunks[1])
		// Explicit typing.
		// https://www.rfc-editor.org/rfc/rfc8725.html#name-use-explicit-typing
		if ending != TypeJWT && ending != TypeSDJWT {
			return errors.New("invalid typ header")
		}

		return nil
	}

	if typStr != TypeJWT {
		// https://www.rfc-editor.org/rfc/rfc7519#section-5.1
		return errors.New("typ is not JWT")
	}

	return nil
}

// PayloadToMap transforms interface to map.
func PayloadToMap(i interface{}) (map[string]interface{}, error) {
	if reflect.ValueOf(i).Kind() == reflect.Map {
		return i.(map[string]interface{}), nil
	}

	var (
		b   []byte
		err error
	)

	switch cv := i.(type) {
	case []byte:
		b = cv
	case string:
		b = []byte(cv)
	default:
		b, err = json.Marshal(i)
		if err != nil {
			return nil, fmt.Errorf("marshal interface[%T]: %w", i, err)
		}
	}

	var m map[string]interface{}

	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()

	if err := d.Decode(&m); err != nil {
		return nil, fmt.Errorf("convert to map: %w", err)
	}

	return m, nil
}
