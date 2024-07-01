/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	josejwt "github.com/go-jose/go-jose/v3/jwt"

	"github.com/trustbloc/kms-go/doc/jose"

	"github.com/trustbloc/vc-go/jwt"
	jsonutil "github.com/trustbloc/vc-go/util/json"
)

const (
	vcIssuanceDateField   = "issuanceDate"
	vcIDField             = "id"
	vcExpirationDateField = "expirationDate"
	vcIssuerField         = "issuer"
	vcIssuerIDField       = "id"
)

// JWTCredClaims is JWT Claims extension by Verifiable Credential (with custom "vc" claim).
type JWTCredClaims struct {
	*jwt.Claims

	VC map[string]interface{} `json:"vc,omitempty"`
}

// ToSDJWTV5CredentialPayload defines custom marshalling of JWTCredClaims.
// Key difference with default marshaller is that returned object does not contain custom "vc" root claim.
// Example:
//
//	https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#name-example-4b-w3c-verifiable-c.
func (jcc *JWTCredClaims) ToSDJWTV5CredentialPayload() ([]byte, error) {
	type Alias JWTCredClaims

	alias := Alias(*jcc)

	vcMap := alias.VC

	alias.VC = nil

	data, err := jsonutil.MarshalWithCustomFields(alias, vcMap)
	if err != nil {
		return nil, fmt.Errorf("marshal JWTW3CCredClaims: %w", err)
	}

	return data, nil
}

// UnmarshalJSON defines custom unmarshalling of JWTCredClaims from JSON.
// For SD-JWT case, it supports both v2 and v5 formats.
func (jcc *JWTCredClaims) UnmarshalJSON(data []byte) error {
	type Alias JWTCredClaims

	alias := (*Alias)(jcc)

	customFields := make(CustomFields)

	err := jsonutil.UnmarshalWithCustomFields(data, alias, customFields)
	if err != nil {
		return fmt.Errorf("unmarshal JWTCredClaims: %w", err)
	}

	if len(customFields) > 0 && len(alias.VC) == 0 {
		alias.VC = customFields
	}

	return nil
}

// newJWTCredClaims creates JWT Claims of VC with an option to minimize certain fields of VC
// which is put into "vc" claim.
func newJWTCredClaims(vc *Credential, minimizeVC bool) (*JWTCredClaims, error) {
	vcc := &vc.credentialContents

	subjectID, err := SubjectID(vcc.Subject)
	if err != nil {
		return nil, fmt.Errorf("get VC subject id: %w", err)
	}

	// currently jwt encoding supports only single subject (by the spec)
	jwtClaims := &jwt.Claims{
		Issuer:  vcc.Issuer.ID, // iss
		ID:      vcc.ID,        // jti
		Subject: subjectID,     // sub
	}

	if vcc.Expired != nil {
		jwtClaims.Expiry = josejwt.NewNumericDate(vcc.Expired.Time) // exp
	}

	if vcc.Issued != nil {
		jwtClaims.IssuedAt = josejwt.NewNumericDate(vcc.Issued.Time)
		jwtClaims.NotBefore = josejwt.NewNumericDate(vcc.Issued.Time)
	}

	credentialJSONCopy := jsonutil.ShallowCopyObj(vc.credentialJSON)

	if minimizeVC {
		delete(credentialJSONCopy, jsonFldExpired)
		delete(credentialJSONCopy, jsonFldIssued)
		delete(credentialJSONCopy, jsonFldID)

		issuer, err := parseIssuer(credentialJSONCopy[jsonFldIssuer])
		if err != nil {
			return nil, err
		}

		if issuer != nil {
			issuer.ID = ""

			credentialJSONCopy[jsonFldIssuer] = serializeIssuer(*issuer)
		}
	}

	credClaims := &JWTCredClaims{
		Claims: jwtClaims,
		VC:     credentialJSONCopy,
	}

	return credClaims, nil
}

// JWTCredClaimsUnmarshaller unmarshals verifiable credential bytes into JWT claims with extra "vc" claim.
type JWTCredClaimsUnmarshaller func(vcJWTBytes string) (jose.Headers, *JWTCredClaims, error)

// decodeCredJWT parses JWT from the specified bytes array in compact format.
// It returns jwt.JSONWebToken and decoded Verifiable Credential refined by JWT Claims in raw byte array form.
func decodeCredJWT(rawJWT string) (jose.Headers, []byte, error) {
	credClaims := &JWTCredClaims{}

	joseHeaders, err := unmarshalJWT(rawJWT, credClaims)
	if err != nil {
		return nil, nil, err
	}

	// Apply VC-related claims from JWT.
	err = credClaims.refineFromJWTClaims()
	if err != nil {
		return nil, nil, fmt.Errorf("refineFromJWTClaims claims: %w", err)
	}

	vcData, err := json.Marshal(credClaims.VC)
	if err != nil {
		return nil, nil, errors.New("failed to marshal 'vc' claim of JWT")
	}

	return joseHeaders, vcData, nil
}

func (jcc *JWTCredClaims) refineFromJWTClaims() error {
	vcMap := jcc.VC
	claims := jcc.Claims

	if iss := claims.Issuer; iss != "" {
		err := refineVCIssuerFromJWTClaims(vcMap, iss)
		if err != nil {
			return err
		}
	}

	if nbf := claims.NotBefore; nbf != nil {
		nbfTime := nbf.Time().UTC()
		vcMap[vcIssuanceDateField] = nbfTime.Format(time.RFC3339)
	}

	if jti := claims.ID; jti != "" {
		vcMap[vcIDField] = jti
	}

	if iat := claims.IssuedAt; iat != nil {
		iatTime := iat.Time().UTC()
		vcMap[vcIssuanceDateField] = iatTime.Format(time.RFC3339)
	}

	if exp := claims.Expiry; exp != nil {
		expTime := exp.Time().UTC()
		vcMap[vcExpirationDateField] = expTime.Format(time.RFC3339)
	}

	return nil
}

func refineVCIssuerFromJWTClaims(vcMap map[string]interface{}, iss string) error {
	// Issuer of Verifiable Credential could be either string (id) or struct (with "id" field).
	if _, exists := vcMap[vcIssuerField]; !exists {
		vcMap[vcIssuerField] = iss
		return nil
	}

	issuerID := ""

	switch issuerFld := vcMap[vcIssuerField].(type) {
	case string:
		issuerID = issuerFld
	case map[string]interface{}:
		id, err := parseStringFld(issuerFld, jsonFldIssuerID)
		if err != nil {
			return fmt.Errorf("get issuer id from vc: %w", err)
		}

		issuerID = id
	}

	if strings.HasPrefix(iss, "did:") && strings.HasPrefix(issuerID, "did:") && iss != issuerID {
		return fmt.Errorf(`iss(%s) claim and vc.issuer.id(%s) missmatch`, iss, issuerID)
	}

	switch issuerFld := vcMap[vcIssuerField].(type) {
	case string:
		vcMap[vcIssuerField] = iss
	case map[string]interface{}:
		issuerFld[vcIssuerIDField] = iss
	}

	return nil
}
